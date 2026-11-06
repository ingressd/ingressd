# Smart DNS on the connector

Status: node and connector implemented (2026-11-05); panel in progress; exit attachments (§5.3) not built yet; the netns suite (§7) is written but has not run on a Linux host yet. Replaces the edge-side Smart DNS of [ARCHITECTURE.md §7](ARCHITECTURE.md#7-exit-routing-smartdns-in-rev1) and §11 (per-realm Smart DNS), and moves the home side of [EXIT-FAILOVER.md](EXIT-FAILOVER.md) into the connector. The product has not launched, so the edge-side home resolver and relay are removed rather than kept for compatibility.

---

## 1. Why

Today the resolver and SNI relay run on the edge node, on each tunnel's transit address, and exits live on edge nodes reached over the mesh. A relayed stream goes

```
TV → router → WG tunnel → home edge (userspace relay) → mesh → exit edge (userspace relay) → VPN → CDN
```

That path has problems the product cannot fix by tuning:

- **Quality**: two userspace relays on servers that also serve other traffic, plus a mesh hop, sit in the path of every location-checked video segment.
- **Failover**: the home side lives and dies with an edge. Service answers point at the edge's transit IP with a 300 s TTL, routers fail over between DNS servers badly, and a site that falls back to the managed network loses Smart DNS entirely (managed nodes cannot reach exits on the customer's nodes).
- **Reachability**: connector sites cannot use it at all. The connector carries edge → LAN traffic only; nothing brings LAN traffic to the edge's resolver.
- **Operator risk**: hosting exits on shared nodes means carrying customers' video and, with operator IPs, selling geo-unblocking. Decided 2026-11-05: the operator hosts no exits.

The connector already runs on an always-on box in the home. Running the resolver and relay there, with exits on the connector itself or on the customer's own nodes, gives

```
TV → connector box → VPN → CDN                                  (connector exit)
TV → connector box → WG tunnel → own node's public IP → CDN    (node exit)
```

and the edge is no longer in the path of a connector exit at all.

## 2. Decisions

| Decision | Value |
|---|---|
| Home side (resolver + relay) | Connector only. Removed from edge nodes |
| Sites | Connector sites only. WireGuard-router sites get no Smart DNS (they can add a connector) |
| Exit locations | `connector`: the site's own connector, through a VPN config. `node`: one of the org's **self-hosted** nodes, egressing from **that node's own public IP** (route a domain out through your Amsterdam VPS without paying for a VPN). Managed nodes never host exits |
| VPNs | Terminate **only on the connector**. Nodes run no VPN interfaces, hold no VPN configs and have no exit routing tables; that node code is removed |
| Exit location kind `operator` | Reserved in the schema, refused by validation. Not offered |
| Plans | Free in every plan: Smart DNS uses no operator infrastructure, so there is no add-on |
| Failover | Kept: ordered exits (1–4, one country), sticky, `failback_after`, fail closed (EXIT-FAILOVER.md semantics), now evaluated by the connector |
| Hosting modes | Independent of Smart DNS. A self, hybrid or managed origin keeps Smart DNS when its edges change; connector exits are unaffected by any edge failure |
| Config trust | Smart DNS config is signed by the org key and VPN configs are encrypted to the connector; edges (self-hosted or managed) only pass it through and can neither read nor change it |

## 3. Architecture

### 3.1 Connector: home side

A new connector component (`internal/connector/client/smartdns`, built on the shared engine in §6) runs when the site's config carries a `smartdns` block:

- **Listen address**: one LAN IPv4 address of the connector host (`smartdns.listen`, chosen in the panel from the addresses the connector reports, default: the address of the interface holding the default route). It binds UDP+TCP 53, TCP 80 and TCP 443 on that address only.
- **Resolver**: a service name is answered with the listen address (TTL 300 s: the address never changes when exits or edges fail over, so a long TTL is safe). AAAA and HTTPS records for service names are suppressed as today. Every other name is forwarded to `upstream` (default 1.1.1.1, 9.9.9.9), so the connector can be a home's only DNS server.
- **Relay**: reads SNI (443) or Host (80), matches the service and connects through the service's active exit. Flows stick to the exit they started on; a connection is retried on the next exit only before any client byte was sent (as today). Only private sources are served (`allowedClient`).
- **Exits**: a connector exit is a wireguard-go device on a gVisor netstack, separate from the edge link, one per VPN config. No root, no interface, no routing table on the host, so it works the same on Linux, Windows, macOS and Docker, and can never capture host traffic. DNS for service names is resolved inside the VPN (the file's `DNS =` servers, else `upstream` through the tunnel), dials go through the netstack. Endpoint re-resolution every 30 s, keepalive 25 s and MTU follow §7.1 of ARCHITECTURE.md.
- **Health**: a connector exit is up when its handshake is fresher than 3 minutes **and** an active probe (TCP connect through the tunnel to the trace host, every 20 s; 3 failures = down) succeeds, so a silently dead provider is seen within a minute instead of three. Country comes from the trace fetched through the exit every 10 minutes and from edge location checks, as today.
- **Edge location checks** (`checks` from the catalog) run on the connector through its VPN exits, and on the node for its node exit (the panel puts them in both configs).

### 3.2 Edge node: exit only

A self-hosted node keeps only one role: letting its own connector sites leave from its public IP for chosen services. The node is the customer's server and its IP the customer's choice; nothing on the node changes the host's routing.

- `smartdns.exit` on the node: `{ country: NL, sites: [<tunnel>, …], upstream?, checks? }` (present = enabled). One exit per node (it has one egress: its default route). `sites` lists the connector tunnels allowed to use it; the panel fills it with the org's connector sites attached to that node. `country` is what the user expects; the node checks it (below).
- **Egress**: ordinary sockets of the node's default route, as the unprivileged `ingressd` user, connecting only to public unicast addresses (`checkConnect` / `publicUnicast` as today: never the LAN, the mesh, metadata or other tunnels). Names are resolved by the node's `upstream` resolvers (default 1.1.1.1, 9.9.9.9) from the node's location.
- **Tunnel exit API** on the tunnel's edge transit address, replacing the mesh exit API:
  - `POST :51901/v1/resolve {name}` → answers resolved at the node's location, `exit_up`.
  - `GET :51901/v1/exit` → the node exit's health (up, egress, country, message).
  - `:51902` relay: the existing framed `ConnectRequest`/`ConnectResponse` (with `exit_down`), then a byte pipe.
  - A request is served only from a connector tunnel's site address to that tunnel's own edge address, and only for tunnels listed in `sites`. Restricted tunnel input admits 51901/51902 the same way it admits 51819 today (`iifname`, source and destination pinned); 53/80/443 are no longer opened on tunnel addresses.
- **Health**: the node exit is up while the node's trace succeeds (every 10 minutes, 1 minute after a failure); `egress` and `country` from the trace (edge location checks, run by the connector through the exit, take precedence) are reported in `nodes.health.exits`. A country that differs from `country` marks the exit down (fail closed) and is shown in the panel; the user fixes it by changing the expectation.
- The connector also treats the exit as down while its tunnel to the node is down, so a node loss fails over within the 5 s health poll.
- Removed from the node: VPN interfaces (`ix-x-*`), exit tables and rules (1900–1999 and priorities 10900+), fwmark + `SO_BINDTODEVICE` egress, VPN endpoint refresh and `vpn` secrets. The mesh is no longer used by Smart DNS (it stays for PoP forwarding).

A connector reaches a node exit only over its own tunnel to that node, so the node must be one of the site's attachments. An origin in `managed` hosting mode has no own-node attachments; it can keep **exit attachments** (§5.3) to own nodes that host its exits.

### 3.3 Paths and failure behaviour

| Failure | Connector exit | Node exit |
|---|---|---|
| Any edge down, drained, rotated, origin falling back to managed | unaffected | unaffected unless it is the exit's node |
| Exit's node down | — | node exit down → next exit within 5 s |
| VPN provider down | probe fails → next exit within ~1 min | — (no VPN) |
| Node's IP no longer in the expected country (provider moved it, new VPS) | — | trace or edge check mismatch → exit down, next exit |
| Connector box down | Smart DNS down (fail closed for service domains only, §4), as are the site's apps | same |
| Every exit down | SERVFAIL, nothing relayed elsewhere | same |

A typical failover pair is one VPN exit on the connector and the user's own VPS in the same country, in either order. The panel warns when every exit of a service sits on own nodes ("no exit survives your node failing"), when two exits share a VPN endpoint (existing warning), and, on a node exit, that large streaming services often block hosting-provider IPs, so a node exit suits regional broadcasters and sports sites better than the biggest platforms.

## 4. Home setup

- **Recommended**: conditional forwarding on the router for the service domains only (UniFi, OpenWrt/dnsmasq, Pi-hole, AdGuard Home): `server=/bbc.co.uk/192.168.1.5`. A dead connector box then breaks only the routed services, not the household's DNS. The panel shows the exact lines for common routers, generated from the site's services.
- **Without conditional forwarding**: point clients or the router's DHCP DNS at the connector; names no service routes go to the upstream resolvers. The connector then carries all DNS, so a dead connector box takes the household's DNS with it.
- **Port conflicts**: the listen address must have 53, 80 and 443 free. Hosts that already serve on 80/443 (a NAS UI, a reverse proxy) need a second address for the connector: a secondary IP on Linux, a macvlan network for Docker (documented `docker run` / compose example). The connector reports bind failures per port in its health and the panel shows them with the fix.
- Clients must not use their own DNS (Chrome secure DNS, Android Private DNS, hard-coded 8.8.8.8 on some TVs); the setup page says so. Not fixable by the product.

## 5. Protocol and config

### 5.1 Config delivery

The site's Smart DNS config travels with the connector's tunnel config but is opaque to the edge:

- `TunnelConfig.SmartDNS` (raw `nodeproto.SignedSmartDNS`) (additive, covered by `Revision`). The blob is the JSON config below, signed by the org key (`nodeproto.SignSmartDNS`) and bound to the connector's WireGuard public key (`connector`), which is the same on every edge whatever each node names the tunnel (managed nodes rename tunnels into the tenant's realm). The node gets it in its snapshot (`tunnels.<t>.smartdns`; managed nodes get it in the PoP bundle) and hands it out unchanged.
- The connector stores the last accepted config in its state file and runs it at start, so Smart DNS never depends on an edge being up or on what an edge carries. An edge dropping the config stops nothing: only a signed config without exits turns Smart DNS off.
- The connector pins the org public key at enrolment (join strings gain `o`). A connector enrolled without one pins the key of the first valid config (trust on first use, logged as a warning).
- VPN configs are encrypted in the browser to the **connector's** age recipient. The connector generates an age identity at enrolment (stored with its state, never sent) and reports the recipient in its health reports (`smartdns.age_recipient`); it is generated on first start, so connectors enrolled earlier get one too. Edges never hold a key that opens it.

```json
{
  "listen": "192.168.1.5",
  "upstream": ["1.1.1.1", "9.9.9.9"],
  "failback_after": "5m",
  "services": { "npo": { "domains": ["npo.nl", "npostart.nl"], "exits": ["nl-vps", "nl-vpn"] } },
  "exits": {
    "nl-vps": { "at": "node", "node": "nod_7k2", "country": "NL" },
    "nl-vpn": { "at": "connector", "country": "NL", "vpn": "age1…ciphertext" }
  },
  "checks": [ … ]
}
```

Here the user's own Amsterdam node is preferred and a VPN on the connector takes over when the node is down. `at: node` names one of the site's attachments (it never carries `vpn`); the connector talks to that edge's exit API over its tunnel. `at: operator` is reserved and refused.

### 5.2 Reporting

Additive fields in `Health` (sent to every edge as today, so any node of the site reports them):

- `smartdns.listen`, per-port bind errors, `addresses` (candidate LAN addresses for the panel's picker), `age_recipient`.
- `smartdns.exits`: `ExitStatus` for connector exits (up, egress, country, endpoint, message).
- `smartdns.services`: `ServiceStatus` (active exit, failover since).
- `smartdns.usage`: `ServiceUsage` deltas (connections, bytes), taken on each report.

Each health report carries the newest 100 lookups (`smartdns.recent`); the node keeps the last report per connector and answers the panel's `smartdns_recent_request {site}` from it, and leaves them out of `status`. Usage deltas (`smartdns_usage`) are taken once per report and kept for the next one when the report fails, so each delta reaches one edge; the node adds them to `usage` with `site` set.

### 5.3 Exit attachments (panel)

An attachment gains `role`: `serve` (today) or `exit`. An `exit` attachment brings up the tunnel and the node's exit API for the site but never serves apps: no routes, no edge DNS answers, ignored by hosting moves and `pops_per_site`. The panel creates one when a service uses a node exit on a node the site is not otherwise attached to (typically a `managed` origin using the customer's own VPS as an exit), and removes it when no service uses it. Only the org's own nodes can be exit attachments.

## 6. Code changes

### 6.1 Node repo (`ingressd`, public)

Shared engine, moved out of the edge manager:

- `internal/smartdns/engine`: match, answer cache (keyed per exit), SNI/Host peek, frame protocol, failover state (`activeExit`, failback), edge checks, recent ring, usage counters. Used by the connector and by node exits.
- `internal/smartdns/wgconf`: unchanged, now used by the connector only (and mirrored by the panel's browser parser).
- `internal/smartdns/exit` (node): egress from the node's own IP, trace, tunnel exit API.
- VPN watch logic (endpoint re-resolution, handshake age) moves to the connector's exits.

Removed:

- Edge home side: `resolver.go` service answers and listeners, `handleRelay`, per-listen-address scopes (`scopeAt`, `byAddr`), the mesh exit client and mesh exit API (`MeshAPIPort`/`MeshRelayPort` users), `Manager` owning the mesh runtime (the mesh moves to `serve`).
- Node VPN exits: `ix-x-*` interface rendering and apply, exit tables 1900–1999 and their rules, `SmartDNSExit.VPN`/`Table`, `vpnwatch.go` on the node, the `sockopt_*` fwmark/bind code, VPN secrets in node snapshots. `VPNTableMin`/`Max` go, and the 1900–1999 range is freed.
- Config: the whole `smartdns` block as it is today (listen, services, upstream, checks, failback_after, exits with mesh `node`, `vpn`, `table`) and `realms.<r>.smartdns` with its realm/namespace checks, replaced by `smartdns.exit` of §3.2.
- Render: nft rules opening 53/80/443 on transit addresses; add 51901/51902 pinned per tunnel listed in `smartdns.exit.sites`.
- Tests: `realms-smartdns-e2e.sh`, `smartdns-vpn-exits-e2e.sh`; `smartdns-exit-failover-e2e.sh` is rewritten for the connector (§7).
- Docs: ARCHITECTURE.md §7 rewritten to point here, §11's per-realm Smart DNS removed, EXIT-FAILOVER.md marked as moved to the connector.

Connector:

- `internal/connector/client/smartdns`: listeners, connector exits (wireguard-go + netstack), tunnel exit client, health and usage reporting.
- `proto`: `TunnelConfig.SmartDNS`, `TunnelConfig.Node` (the edge's node id), `Health.SmartDNS`, `Health.SmartDNSUsage`, join `o`.
- `ingressd-connector smartdns status` (local status, like `ingressd smartdns status` today).

### 6.2 Panel (`ingressd-panel`, private)

- **Remove managed exits**: `internal/api/managed_exits.go`, `managed_vpn_tables` (migration 0020 part), `popcompile.realmSmartDNS` and the Smart DNS parts of `usage_managed`, the `smartdns_own_exits` hosting check. Managed bundles carry no Smart DNS beyond passing the signed blob to the connector.
- **Schema** (new migration): `smartdns_exits.node_id` becomes nullable and gains `site_id` (`CHECK ((node_id IS NULL) <> (site_id IS NULL))`); `node_id` must be an org-owned node, at most one exit per node. `vpn_secret` (ciphertext to the site's connector recipient) is required for connector exits and refused for node exits. `site_attachments.role` (`serve` | `exit`). `smartdns_services` gains `site_id` (a service belongs to one connector site; the same catalog entry can be added to several sites).
- **Compiler**: per connector site, the signed blob (§5.1); per own node that is some service's exit, `smartdns.exit` with `sites`. No VPN secrets in node snapshots. Nothing for router sites.
- **UI** (`smartdns.tsx`): Smart DNS lives on the connector site page. Exit editor picks "VPN on this connector" (import a config) or "Leave from my node <name>" (country prefilled from the node's last trace); VPN import encrypts to the connector's recipient; listen address picker from reported addresses; router setup snippets; per-service active exit and failover state; warnings from §3.3.

## 7. Tests

- Unit (`engine`): everything EXIT-FAILOVER §10 lists (order, stickiness, failback, flapping, all down, retry rules, cache per exit), now against connector and node exits behind one interface.
- Connector: netstack exit dialing through a fake provider (wireguard-go peer in-process), probe-based down detection, bind errors reported, signed-blob rejection (wrong org key, wrong site, tampered), VPN ciphertext for another recipient refused.
- Node: tunnel exit API refuses tunnels not in `sites` and non-site sources, never dials private or mesh addresses; country mismatch marks the exit down; no `ix-x-*` interface or 1900+ rule is ever created; nft goldens for 51901/51902.
- netns `connector-smartdns-e2e.sh`: a LAN client, a connector (TUN mode), an edge node that is the site's node exit, a simulated provider for the connector's VPN exit and a fake CDN. Checks: service names answered with the listen address, AAAA suppressed, other names answered by the upstream resolver; HTTPS and HTTP leave from the node's IP, resolved at the node; tampered, foreign-key and replayed configs refused while the config in effect keeps working; removing the node exit fails over to the VPN within the health poll; with the edge down and the connector restarted, streams keep using the VPN from the stored config; with the provider gone too, SERVFAIL and nothing relayed; only a signed config without exits turns Smart DNS off.
- Throughput: `test/perf` relay benchmark (iperf through LAN → connector → netstack VPN) on a Raspberry Pi 4–class box; target several 4K streams (≥ 100 Mbit/s) before launch.

## 8. Open questions

1. Use kernel WireGuard for connector exits in TUN mode on Linux (faster) or keep one netstack path everywhere (simpler)? Decide after the benchmark.
2. Is one listen address per site enough, or do some homes need one per VLAN?
