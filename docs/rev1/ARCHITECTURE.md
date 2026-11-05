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
- **Isolation**: each VPN exit gets interface `ix-x-<name>` (names longer than 10 characters become `ix-x-<4 chars>-<hash>`, always ≤ 15 bytes), its own routing table (`smartdns.exits.<name>.table`, 1900–1999, else 1900 + index in name order; the rule priority is `10900 + (table − 1900)`) holding `0.0.0.0/1` + `128.0.0.0/1` via the interface, and an fwmark rule selecting that table. Nothing goes into the main table, so a full-tunnel `AllowedIPs = 0.0.0.0/0, ::/0` never touches the node's default route; the peer's AllowedIPs is always `0.0.0.0/0` because only exit routing sockets ever use the interface. Those sockets set `SO_MARK` *and* `SO_BINDTODEVICE`, so with the tunnel or its routes gone they fail instead of leaking out of the main route. The WireGuard UDP packets themselves are unmarked and leave by the normal route.
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

---

## 11. Realms (shared nodes)

A panel can merge several organisations onto one node by writing one ordinary `config.yaml` with `realms`. The node does not trust the merge: it re-checks every cross-realm invariant and refuses the config otherwise.

```yaml
realms:
  tq7k2m:
    access: { portal_url: https://auth.ingressd.com/a/tq7k2m, session_key: secret://tq7k2m_session, jwt_key: secret://tq7k2m_jwt }
    shape: { rate_mbit: 50 }      # bandwidth cap on this node (tc)
security: { tunnel_input: restricted }
tunnels:
  tq7k2m01: { realm: tq7k2m, table: 1201, virtual_prefix: 10.0.4.0/24, subnets: [192.168.1.0/24], … }
apps:
  tq7k2m.nas: { realm: tq7k2m, tunnel: tq7k2m01, origin: http://192.168.1.10:5000, … }
```

**Names.** Apps, pools, policies, groups and service tokens may carry one namespace label (`tq7k2m.nas`); tunnels stay plain (interface names). Names are still keys of one map, so everything named after them (cookie `__edge_<app>`, rate-limit zones `<app>_<n>`, snapshot directories, pool state) is distinct per realm; `.` is a valid cookie-name character, so cookie names need no rewriting.

**Validation** (`pkg/config/realms.go`). With `realms` present: every tunnel, app, pool, policy, group and service token names an existing realm; app → tunnel/pool/policies, pool → tunnels and policy → groups/service tokens never cross realms; realm tunnels set `virtual_prefix` and an explicit `table`; every origin goes through one of its realm's tunnels at an IP literal inside that tunnel's subnets (no hostnames, no public origins, so never metadata, the mesh or another realm's virtual addresses); an exact hostname belongs to one app, and a wildcard never covers another realm's host at any depth. Refused alongside realms: top-level `access`, `l4`, `edge.admin` (hostname, non-public exposure, allowlist) and top-level `smartdns` (it would serve every realm's tunnels; each realm has its own, see below). `security.tunnel_input` must be `restricted`: open input would let every realm's sites reach the proxy and SSH through their tunnels. A realm with protected apps must have `access` with `portal_url` and its own `session_key`/`jwt_key`; the block is validated like the top-level one and `portal_host` is refused.

**Stable tables** (`tunnels.<t>.table`, any remapped tunnel). The table doubles as fwmark; tunnels without one keep `1000 + index in sorted name order`. Explicit tables are 1000–1899 (Smart DNS VPN exits own 1900+), unique, and may not land on another tunnel's implicit number. The rule priority is `10000 + (table − 1000)`, so it is stable too and stays below the VPN exits' 10900+.

**Restricted tunnel input** (`security.tunnel_input: restricted`, needs the managed firewall). From any tunnel interface the input chain accepts only the connector control port 51819 from the site to its own edge transit address and Smart DNS (53, relay ports) on that tunnel's own transit address; everything else from a tunnel (80/443, SSH, other local addresses) is dropped before the public ports are opened. An `output` chain drops TCP from unprivileged sockets (the edge runs as user `ingressd`; the control plane, root, uses the mesh itself) to `169.254.0.0/16`, the mesh network and `fd00:ec2::254/128` (AWS metadata over IPv6), plus every network in `security.edge_output_deny` (IPv4 or IPv6 CIDRs, e.g. the provider's private network; restricted mode only), so the proxy cannot be turned into an SSRF to metadata, the mesh or the provider network. TCP only, so link-local NTP/DNS used by host daemons keeps working. The forward chain is unchanged.

**Shaping** (`realms.<r>.shape.rate_mbit`, 1–100000). Each shaped realm with at least one tunnel gets an IFB device `ifb-<realm>` (realm names longer than 11 characters become `ifb-<4 chars>-<hash>`, always ≤ 15 bytes; two realms hashing to one name are refused) with a root HTB `1:` whose default class `1:10` runs at the rate (ceil = rate, burst 10 ms of the rate and at least 32 KiB) and an `fq_codel` leaf. Every tunnel of the realm redirects its ingress (origin → edge, the data the edge will serve) to that IFB with an ingress qdisc and a `matchall` + `mirred` filter, so all of a realm's tunnels share one cap. Egress into each tunnel (edge → origin) gets its own root HTB at the same rate: a per-tunnel approximation of the realm cap, acceptable because that direction is small for typical sites. Render emits the plan as `network.shapes` (realm, IFB, rate, tunnel interfaces); the network apply step reconciles it over netlink after the interfaces: missing devices and qdiscs are created, the rate is changed in place (class change, so tunnels and transfers in flight are untouched), and unshaped `ix-*` WireGuard interfaces lose the root HTB `1:` and ingress qdisc. Only IFBs carrying the link alias `ingressd-shape` and the qdiscs of ingressd's own `ix-*` interfaces are touched. Needs the `ifb`, `sch_htb`, `sch_fq_codel`, `cls_matchall` and `act_mirred` kernel modules.

**PoP forwarding** (`edge.forward`, MANAGED.md §6.2; works with and without realms).

```yaml
edge:
  forward:
    listen_mesh: true               # serve the forward listener on mesh.address:51880
    secret: secret://forward-hop    # HMAC key, the same on every node of the mesh
    siblings:                       # local tunnel -> mesh peers holding the same site, preferred first (1-4)
      tq7k2m01: [nod_b, nod_c]
```

Validation: `mesh` is required, `secret` is a secret reference, `listen_mesh` or `siblings` is set, sibling tunnels exist and siblings are distinct `mesh.peers` ids. An app whose origins use a tunnel with siblings renders a `reverse_proxy` whose upstreams are its local origins followed by the siblings' forward listeners (`<peer mesh address>:51880`), with the `edge_forward` selection policy (edge module `edgeforward`): local upstreams are used through the app's usual policy (`edge_tiered` for pools) while their tunnel is up, otherwise the first available sibling. A tunnel is down when the control plane's health monitor finds its handshake older than 180 s or its interface missing; the monitor pushes `tunnels: {<name>: {down: true}}` into `edge_state` next to the pool state. Passive health also counts (a failed dial ejects the upstream for 30 s, `try_duration` 12 s leaves room for one sibling retry after a local dial timeout). The `edge_forward` transport is the `http` transport plus a `forward` block: requests to a local origin go out unchanged (any client-sent hop header removed), requests to a sibling go as plain HTTP over the mesh (WireGuard encrypts the hop) with `X-Ingressd-Hop: v1;<node mesh address>;<app>;<unix time>;<HMAC-SHA256>`.

The forward listener is a second Caddy server bound to the mesh address only, opened by nftables to `ix-mesh` from mesh peers (in restricted mode the output chain lets the unprivileged proxy reach the siblings' port 51880, nothing else on the mesh). Its first handler, `edge_forward_verify`, refuses (403) a missing, malformed or wrongly signed hop, one older or newer than 30 s, one signed by a node that is not a mesh peer or that is not the connection's source address, and answers 508 to a hop signed by itself. A valid hop selects the route of the app it names, which proxies to that app's local tunnel origins only: no `edge_auth`, WAF, cache or rate limits (the first node enforced them), no siblings, and the transport refuses to forward a request that came through a forward listener, so a request makes at most one hop. With realms the app key names the realm, and an app's origins are validated to be its own realm's tunnels, so the listener can only reach the same realm's tunnels. TLS terminates on the first node; the listener trusts the peers' `X-Forwarded-For` (static trusted proxies), so the origin sees the visitor first, then the forwarding node. The listener keeps no access log: a forwarded request is logged and metered once, on the first node.

**Per-realm Smart DNS** (`realms.<r>.smartdns`, MANAGED.md §10). A realm carries a block with the schema of top-level `smartdns` (services, exits, checks, failback_after, upstream, listen); top-level `smartdns` stays refused alongside realms.

```yaml
realms:
  tq7k2m:
    smartdns:
      enabled: true                 # listen defaults to the realm's tunnels' transit addresses
      exits:
        tq7k2m.gb: { node: self, country: GB, vpn: "secret://tq7k2m-vpn-gb", table: 1901 }
        tq7k2m.nl: { node: nod_nl, country: NL }
      services:
        tq7k2m.tv: { domains: [stream.example], exits: [tq7k2m.gb] }
```

- **Validation**: service and exit names carry the realm's namespace (`<realm>.<name>`, as the panel's namespacing rewrite writes them), so they are unique on the node and an exit's realm follows from its block; a service lists exits of its own block only; explicit `listen` addresses must be transit addresses of the realm's own tunnels (no LAN or other addresses); domains are unique within a block, so two realms may route the same domain to different exits. VPN exits use explicit tables: `smartdns.exits.<name>.table` (1900–1999, unique on the node, policy rule priority `10900 + (table − 1900)`) is required for a VPN exit in a realm, so tables never move as other tenants' exits come and go (outside realms it is optional; an implicit `1900 + index` may not land on an explicit table). Interface names and tables are checked across every block.
- **Resolver and relay**: one `smartdns.Manager` per node (it also runs the node's single mesh runtime) holds one scope per block, and each listener belongs to the block whose listen address it binds: the resolver and the relay pick services, upstreams and exits by the local address a query or connection arrived on, so a realm's sites only ever see their own realm's routes. A query on an address no realm listens on is refused (the node's own block, outside realms, keeps answering on any of its addresses as before). Restricted tunnel input still pins port 53 and the relay ports to each tunnel's own transit address, so a site can reach only its own realm's resolver. Failback timers, upstreams and edge checks come from the service's block; usage, status and recent lookups are keyed by the (namespaced) service names.
- **Exit API**: requests carry the realm the home node serves for that request (`realm` in `POST /v1/resolve` and the relay's connect frame, `?realm=` on `GET /v1/exits`; the realm of the exit in the home node's own config). The exit node checks it against its own config: an exit of realm `r` is resolved, relayed through and reported only for requests naming `r`, an exit outside realms only for requests naming none, and anything else is refused like an exit the node does not host. Exit nodes that predate this ignore the field: run realm exits on updated nodes only.

**What is per realm, what is refused**

| Process-global piece | With realms |
|---|---|
| Access keys (session/JWT), portal URL, revocations | Per realm: edge_auth of a realm app gets its realm's portal URL and keys; the control plane opens callback codes, applies `revoked_before`/`revoked_sessions` and mints app cookies with the app's realm's keys only |
| App cookie key | `HKDF(master_realm, "…edge_auth/realm/<realm>/cookie/<app>")`; configs without realms derive exactly as before |
| Revocation list polled by edge_auth | Per realm (`/v1/revocations?realm=`), one poller per realm |
| `/.ingressd/callback` | Per app, and so per realm; legacy stored (unsealed) codes are refused |
| Node portal, portal/play cookies, OTP, email, JWKS, identity providers | Refused: realms sign in on their external portal (`portal_url`); no portal host, no login-to-play (`l4`) |
| Email-wide remote revocation (`auth_revoke` with email+before) | Refused (it would hit every realm); use the realm's `revoked_before` |
| Admin hostname, `tunnel_only` trust of every tunnel | Refused |
| Machine host | Serves only the connector and tunnel endpoints (`/.ingressd/connector/*`, `/.ingressd/tunnel/*`) and a landing line, never a portal or admin UI. It is the enrolment endpoint (managed nodes), else the public IPv4, since realms have no admin hostname: join strings, WireGuard endpoints and the WebSocket fallback URL use it, and a bare IP gets an internal-CA certificate the join string pins. An app claiming it fails the render |

Not isolated by design: the bot-challenge clearance key is node-wide (a clearance cookie only proves work was done, and is host-scoped), the shared response cache is keyed by host, and top-level `security` rules, alerts and logging are operator settings. Usage, logs and live tail need no change: app and tunnel keys are already namespaced by the panel.

**Tests**: `go test ./pkg/config ./internal/render ./internal/auth ./pkg/access` and `edge/modules/edgeauth` (realm rules, realm keys in edge_auth, cookie and revocation scoping, two realms on `192.168.1.0/24` dialling distinct virtual prefixes and tables, restricted-input goldens), and `test/netns/realms-e2e.sh` (two connectors enrolled under the realms config with identical LANs, restricted input, and per-realm sign-in and cookies) and `test/netns/realms-shaping-e2e.sh` (a realm's downloads held within 25% of its rate, an unshaped realm not held by it, a rate change applied in place under a running transfer, devices removed with the shape). PoP forwarding: `edge/modules/edgeforward` (hop signing and expiry, verify refusals including loops, transport signing and second-hop refusal, selection by tunnel state and passive health), render goldens (`forward-caddy.json`, realm routing, nft) and `test/netns/pop-forward-e2e.sh` (one router site tunnelled to two edges; with edge A's tunnel down, requests via A reach the origin through B; unsigned and forged hops refused; no forwarding loop with both tunnels down). Per-realm Smart DNS: `go test ./pkg/config ./internal/smartdns ./internal/render` (namespaces, listen addresses and tables; two realms answering the same name from their own exits per listen address; relay by local address; exit API refusing other realms in resolve, health and relay; resolver rules pinned per realm tunnel) and `test/netns/realms-smartdns-e2e.sh` (two realms on a home node and their exits on an NL node: separate services per transit address, each site blocked from the other realm's resolver, relays egressing at each realm's exit, cross-realm resolve refused by the exit node).
