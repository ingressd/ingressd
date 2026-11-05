# Architecture and contracts (revision 1)

Revision 1 introduces a hosted **panel** that manages **self-hosted edge nodes**: the panel UI, onboarding, the app deployment pipeline, live preview, usage metering, and exit routing (the `smartdns` config section) with exits on user nodes. A multi-tenant PoP network and anycast are not part of this design, but nothing here should block them.

This document describes the contracts between the node (this repository) and the panel: protocol messages, API shapes and the config schema. Changes to a contract should be the smallest compatible change.

---

## 1. Repositories and components

**Two repositories, on purpose:**

| Repo | Visibility | Contains |
|---|---|---|
| **`ingressd/ingressd`** (this repo, the *node*) | Public, Apache-2.0 | Edge agent, edge proxy, connector, exit routing (`smartdns`), config schema (`pkg/config`), panel↔node protocol (`pkg/nodeproto`), CLI, installers |
| Panel | Private, proprietary | Hosted panel backend, web UI, panel API spec, panel deployment |

There is **no self-hostable panel**. A node runs in one of two modes:
- **Standalone**: the node agent + CLI + `config.yaml` (which can be exported from the panel and imported into a standalone node).
- **Managed**: the hosted panel manages the node(s).

Consequences for the node repo:
- The node's **local web admin UI and API** (`internal/api`, `internal/admin`, `internal/ui`, `web/`) were **removed** in rev1. Standalone is CLI + config only.
- Code the panel needs lives under **`pkg/`** (Go forbids importing another module's `internal/`): `pkg/config` (schema, parse, validate, edit) and `pkg/nodeproto`. Keep `pkg/` minimal and stable.

| Component | Repo / path | Role |
|---|---|---|
| **Panel** | panel (separate, private) | Hosted control plane: accounts/orgs, nodes, sites, apps, policies, exit routing objects, deployment pipeline, live-preview relay, usage + quotas, audit, export. REST API + SSE + node control channel. Postgres. Serves the web app. |
| **Web app** | panel | The panel UI. Talks only to the panel REST API. |
| **Node agent** | node repo: `cmd/ingressd` + `internal/nodeagent` | The edge. Standalone mode (CLI + config) **or managed mode**: enrolled with a panel, receives signed config snapshots over an outbound WebSocket, applies them with the existing pipeline, reports status/usage/logs/diagnostics. |
| **Edge proxy** | node repo: `edge/` module (custom Caddy) | Unchanged role. |
| **Connector** | node repo: `cmd/ingressd-connector` | Home side. Rev1 adds LAN service discovery and a one-line installer. |
| **Exit routing** (`smartdns`) | node repo: `internal/smartdns`, `internal/mesh` | Runs inside the node agent: resolver + SNI relay for the home, exits on other nodes of the same org via a node mesh. |
| **Shared protocol** | node repo: `pkg/nodeproto` | Types for panel↔node messages. Owned jointly; change carefully. |

The panel consumes `pkg/config` and `pkg/nodeproto` as an ordinary Go module dependency of this repository.

Follow [../CONTRIBUTING.md](../CONTRIBUTING.md) (extension points, one-line hooks, conventions, build/test instructions).

---

## 2. Data model (panel, Postgres)

IDs are prefixed random strings (`org_…`, `usr_…`, `nod_…`, `sit_…`, `app_…`, `pol_…`, `ext_…`, `svc_…`). Names/slugs are unique per org and become config keys on nodes.

The panel stores users and orgs, nodes (status, public addresses, version, age recipient, hashed credential, applied revision, health), enrol tokens (hashed), sites, apps, policies (same shape as config `policies.<name>`), org settings, secrets (age ciphertext encrypted **to the target node**; the panel never sees plaintext), exit routing exits and routed services, hourly usage with per-node sequence numbers (idempotent ingestion), optional per-org limits, signed config revisions (history, rollback, export), an audit log and discovered LAN services. The panel's schema is internal to the panel; the node only sees compiled `config.yaml` snapshots and `pkg/nodeproto` messages.

---

## 3. Config compiler: panel state → node `config.yaml`

The node already understands `config.yaml` (validated by `pkg/config`). The panel **compiles** each node's share of the org state into that exact schema, so the whole existing pipeline (render → apply, keys, certs, WAF, access…) is reused unchanged.

- Per node: tunnels for its `sites` (site name → tunnel key; `kind: unifi` → `site: router`, `vendor: unifi`; `kind: connector` → `site: connector`; transit allocated by the panel per node, unique on that node), apps whose site is on that node (app name → app key; `origin` + `tunnel`), referenced policies, org `access`/`email` settings, `smartdns` and `mesh` sections (§7), `edge.admin.hostname` omitted in managed mode (the local admin UI is disabled in managed mode).
- The compiler must produce YAML that passes `config.Parse` + `Validate` **in the panel before sending**; validation errors are shown to the user, not discovered on the node.
- Every compile that changes the output creates a new `revision` (monotonic per node) stored in `config_revisions`.
- Secrets referenced as `secret://name` are delivered alongside as ciphertexts encrypted to the node (§6).

---

## 4. Panel ↔ node control channel

Defined in `pkg/nodeproto`. Summary:

1. **Enrolment**: the user creates an enrol token in the UI. The install command embeds it:
   `curl -fsSL <panel>/install/node.sh | sudo sh -s -- --panel <panel-url> --token <token>`.
   The node generates its age identity (existing `secrets` package) and calls `POST /api/node/v1/enroll` with the token and its age recipient. The panel returns `node_id`, a long random **credential** (stored hashed) and the **org signing public key** (pinned by the node).
2. **Connection**: the node dials `GET /api/node/v1/connect` (WebSocket, `Authorization: Bearer <node_id>.<credential>`), sends `hello`, and keeps the connection up (reconnect with jittered backoff, 1s → 60s).
3. **Messages**: JSON envelopes `{type, id, data}`.
   - panel → node: `snapshot`, `live_subscribe`, `live_unsubscribe`, `diag_request`, `discover_request`, `ping`.
   - node → panel: `hello`, `applied`, `status` (every 15 s and on change), `usage` (every 60 s, sequence-numbered), `log` (only while a live subscription is active), `diag_result`, `discovery`, `event`, `pong`.
4. **Snapshots** are signed by the org key (ed25519 over `nodeproto.SnapshotSigningPayload`). Nodes reject snapshots with a bad signature or a revision ≤ the applied one (except an explicit `force` resync after detach/re-attach). The node writes `config.yaml`, merges secrets, runs the existing apply pipeline, and replies `applied{revision, ok, error}`.
5. **Offline behaviour**: the node keeps serving its last applied config indefinitely when the panel is unreachable.
6. **Detach**: `ingressd node detach` (or the panel's Detach button, delivered as a final message) stops managed mode; the node keeps its config and becomes Standalone.

---

## 5. App deployment pipeline

Shown live in the UI. Orchestrated by the panel; checks that need the node are sent as `diag_request`.

| Step | Key | Who checks | OK when | Typical failure + hint |
|---|---|---|---|---|
| 1 | `config` | panel | compiled config validates and the node replied `applied` ok | validation error (field path) |
| 2 | `origin` | node (`diag_request{kind:"origin"}`) | TCP + HTTP request to the origin through the tunnel succeeds | `tunnel_down` / `no_reply` (SYN unanswered: router firewall zone) / `refused` / `http_error` |
| 3 | `dns` | panel (queries 1.1.1.1, 8.8.8.8, 9.9.9.9) | every hostname resolves to the node's public IP (A) or CNAMEs to it | `missing` / `wrong_target` / `proxied` (Cloudflare anycast ranges) |
| 4 | `certificate` | node (status `certs[]`) | cert for each hostname `valid` | `issuing` (in progress) / `failed` with ACME error |
| 5 | `live` | node (`diag_request{kind:"http"}` against `https://<host>` via the node's own public IP) | 2xx/3xx/401/403 from the edge with valid TLS | timeouts, TLS errors |

Step states: `pending`, `running`, `ok`, `failed`, `skipped`. Each step has `message` (what happened) and `hint` (what to do). The pipeline re-runs automatically when inputs change (config apply, DNS change detected by periodic re-check every 30 s while not live, cert state change), and on demand (`POST /apps/{id}/redeploy`).

Diagnostic codes are defined in `pkg/nodeproto` (`DiagCode*`) so UI hints are consistent. The UniFi lessons (DNS line in imports, VPN-client firewall zone) are part of the hint text.

---

## 6. Trust model in rev1

Implemented now:
- Keys are generated on the node and never leave it (TLS keys, WireGuard keys, age identity, Origin CA).
- **Secrets entered in the UI are encrypted in the browser to the target node's age recipient** (JS `age-encryption`), sent as ciphertext; the panel stores and forwards ciphertext only.
- Nodes dial out; no inbound management port.
- Snapshots are signed with the org key; nodes pin the org public key at enrolment.
- Nodes keep running without the panel; `detach` leaves a working standalone node.

Known rev1 limitations (also documented in the panel's security page):
- The org signing private key is held by the panel (encrypted at rest with a panel master key). Passkey-held org keys come later, so in rev1 a fully compromised panel could still sign config.
- Live preview is relayed through the panel (TLS to the panel, not end-to-end encrypted to the browser). Logs are not stored by the panel; only the live stream passes through.

---

## 7. Exit routing (`smartdns`) in rev1

- **Exits are nodes.** An exit = (node, country, optional VPN WireGuard config). The exit node can also bind egress to a VPN interface (as an earlier prototype did).
- **Mesh**: the panel gives every node in an org a WireGuard mesh address (e.g. `10.255.<n>.<m>`) and peers; nodes bring up interface `ix-mesh` (config section `mesh`).
- **Flow**: home UDM forwards service domains to the resolver on its **home node's tunnel transit IP**. The resolver asks the **exit node** (over the mesh) to resolve the name *from the exit's location* and returns the home node's own transit IP. The home device connects to the home node on 443/80; the relay reads SNI/Host and forwards the stream over the mesh to the exit node's relay, which connects to the destination (optionally via the VPN interface). TLS stays end to end.
- Carried over from an earlier prototype: AAAA/HTTPS suppression, stale-while-revalidate cache (24 h stale on failure), fail closed, exit location checks (`edgecheck`, configured by `smartdns.checks`, which the panel fills in from its service catalog), recent-DNS domain discovery.
- Config sections on the node: `smartdns` (resolver listen addresses, services → exit names, edge location checks) and `mesh` (node's mesh address, peers, which peer is which exit).

### 7.1 VPN exits (a VPN provider's WireGuard config)

An exit can egress through a commercial VPN instead of the node's own IP, so traffic can leave through the provider without renting another server. The panel imports the provider's `.conf` in the browser (parsed and age-encrypted to the node; the panel stores ciphertext plus the interface public key, endpoint and provider name) and compiles `smartdns.exits.<name>: { node: self, country: GB, vpn: "secret://vpn-<name>" }`. Any node can host any number of VPN exits.

- **Parsing** (`internal/smartdns/wgconf`, mirrored by the panel's browser-side parser): `[Interface]` PrivateKey and an IPv4 Address are required, plus exactly one `[Peer]` with PublicKey and Endpoint (`host:port`, IPv6 literal `[addr]:port` allowed). PresharedKey, MTU, DNS and PersistentKeepalive are honoured. IPv6 addresses and IPv6 DNS servers are kept as information only (exits egress over IPv4; an IPv6-only config is refused with a clear message). wg-quick keys (Table, PostUp, SaveConfig…) and provider comments (Proton's NetShield, NAT-PMP, VPN Accelerator) are ignored. OpenVPN files, missing keys and bad endpoints get specific errors. Samples of Proton, Mullvad, IVPN, AirVPN and Windscribe layouts are in `wgconf/testdata` (keys redacted).
- **Isolation**: each VPN exit gets interface `ix-x-<name>` (names longer than 10 characters become `ix-x-<4 chars>-<hash>`, always ≤ 15 bytes), its own routing table (1900 + index in name order) holding `0.0.0.0/1` + `128.0.0.0/1` via the interface, and an fwmark rule selecting that table. Nothing goes into the main table, so a full-tunnel `AllowedIPs = 0.0.0.0/0, ::/0` never touches the node's default route; the peer's AllowedIPs is always `0.0.0.0/0` because only exit routing sockets ever use the interface. Those sockets set `SO_MARK` *and* `SO_BINDTODEVICE`, so with the tunnel or its routes gone they fail instead of leaking out of the main route. The WireGuard UDP packets themselves are unmarked and leave by the normal route.
- **DNS**: the file's IPv4 `DNS =` servers resolve service names inside the tunnel (the provider's resolver sees the exit's location); without a DNS line the `smartdns.upstream` resolvers are asked through the tunnel. The node's own resolver (`/etc/resolv.conf`) is never changed.
- **MTU and keepalive**: `MTU =` sets the interface MTU (default 1420). PersistentKeepalive from the file is applied, 25 s when absent: providers drop idle NAT mappings and an exit is idle most of the time.
- **Endpoint changes**: the apply step resolves the endpoint (IPv4 first, IPv6 fallback). At runtime the node re-resolves host-name endpoints every 30 s and repoints the peer when the address in use is no longer listed (providers move servers; a name that did not resolve at apply time is picked up later). Key rotation is a config replacement in the panel (`PUT /orgs/{org}/smartdns/exits/{exit}/vpn`), which re-renders the interface in place.
- **Health** (`nodeproto.ExitStatus`, reported in `nodes.health.exits`): `up` means the tunnel had a handshake within 3 minutes; `egress` and `country` come from a trace fetched *through the exit's egress* (Cloudflare's `https://1.1.1.1/cdn-cgi/trace` format, every 10 minutes, 1 minute after a failure, and right after the tunnel comes up; `INGRESSD_SMARTDNS_TRACE_URL` overrides the URL), with edge location checks taking precedence for the country. A mismatch with the expected country is reported in `message`; `endpoint` is the server address the tunnel uses now. A down tunnel fails closed: service names get SERVFAIL, nothing is relayed elsewhere.
- **Tests**: `go test ./internal/smartdns/... ./internal/render ./pkg/config`, and the netns suite `test/netns/smartdns-vpn-exits-e2e.sh` (two simulated providers as two exits on one node: per-service egress, untouched default route, keepalive/MTU/PSK, endpoint move, fail closed).

### 7.2 Exit failover

A service can list up to four exits of one country in order of preference (`smartdns.services.<name>.exits`; the single `exit` field is normalised into a one-element list). Each home node keeps a sticky active exit per service: new connections use it while it is up, move to the next healthy exit when it goes down, and move back only after the preferred exit has stayed healthy for `smartdns.failback_after` (default 5m). The relay resolves and connects through the same exit and retries the next one only before any client byte was sent; with every exit down the service still fails closed. Home nodes learn a remote exit's health by polling `GET /v1/exits` on the exit node every 5 s, and exit nodes mark a refusal caused by a down exit with `exit_down`. Nodes advertise `smartdns-failover` and report each service's active exit in `status.smartdns_services`. Design, compatibility rules and tests: [EXIT-FAILOVER.md](EXIT-FAILOVER.md); netns suite `test/netns/smartdns-exit-failover-e2e.sh`.

---

## 8. Usage metering and quotas

Rev1 **measures, records and displays** usage; per-org limits are optional (null = unlimited).

- Node: aggregates per app (requests, bytes in/out, status classes) from the access-log store (`internal/observe`), per site tunnel rx/tx (WireGuard counters), and exit routing relay bytes per service. Sends `usage` deltas every 60 s with a monotonically increasing `seq`; persists unsent deltas across restarts (so nothing is lost or double counted).
- Panel: idempotent ingestion (`usage_seq`), hourly buckets (`usage_hourly`), monthly totals per org/app/site/node, and a `quotas` row per org with nullable limits.
- UI: a Usage page (current period bars vs limits, "unlimited" when null, history chart, per-app/site breakdown) and quota badges on app/site cards. API: `GET /usage`, `GET /usage/history`, `GET/PUT /quota` (owner only).

---

## 9. Panel API

REST under `/api/v1`, JSON, cookie session (`__Host-` cookie, SameSite=Lax for SSE GETs, CSRF header on mutations). SSE endpoints for deployment events, live preview and org-wide status. The panel API is specified and versioned by the panel; nodes do not use it (they use the control channel in §4).

---

## 10. Testing

- Unit tests everywhere (`make test`).
- netns end-to-end tests in `test/netns/*-e2e.sh` (unique namespace prefixes), run as root on Linux.
- `test/fakepanel/` is a minimal panel for exercising managed mode (enrol, snapshots, status, usage, live logs) without the hosted panel.

See [../TESTING.md](../TESTING.md).
