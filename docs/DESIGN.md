# ingressd — Self-Hosted Edge for the Home Lab

> Design reference for ingressd: a self-hosted alternative to Cloudflare Tunnel / Access / WAF / Spectrum / Load Balancing / Always Online, running on a single public cloud VM and tunnelling back to home (UDM Pro or anything else) over WireGuard.
>
> Section numbers are stable: code and other documents cite them (for example `DESIGN.md §6.4`).
>
> **This is the original single-VM design, not a description of the current code.** The data plane (edge, tunnels, Access, WAF, pools, L4, Always Online) follows it closely. The admin parts do not: the local web UI, admin users, RBAC and the REST API (§3 layout, §8, §14, parts of §16 and §18) were replaced in rev1 by the separately hosted panel. Today a node is managed either with `config.yaml` and the CLI, or by the panel; see [rev1/ARCHITECTURE.md](rev1/ARCHITECTURE.md). Where this document and the code disagree, the code is authoritative.

---

## 1. Goals & non-goals

### Goals
1. Point any domain at the edge VM's public IP and serve it with automatic Let's Encrypt certificates.
2. Connect any number of **sites** (home UDM Pro, cloud VPS, friend's house) over WireGuard; site always initiates.
3. Publish **HTTP applications** (`server.example.com → 192.168.0.17:8080`) through tunnels with a reverse proxy.
4. Load balance an application across **origin pools** spanning multiple tunnels (even split, weighted, active/backup).
5. Protect applications with **access policies** (email OTP, email/domain allowlists, groups, IP, country, service tokens).
6. Optional **origin TLS**: private Origin CA, strict verification, authenticated origin pulls (mTLS).
7. **WAF** (OWASP CRS), rate limiting, geo rules, JS proof-of-work **bot challenge**, CrowdSec reputation.
8. **Always Online**: serve stale cache / crawled snapshot when all origins are down.
9. **TCP/UDP forwarding** for game servers (FiveM, Minecraft) with "Login to play" allowlisting.
10. A clean **control panel** with multi-admin RBAC, plus a CLI and API; the full configuration is a readable, versioned YAML file.

### Non-goals (v1)
- Running as a DNS provider or managing DNS records.
- Multi-edge / anycast / geo steering (data model leaves room; see §16).
- End-user OIDC / passkeys for Access (admins get passkeys in v1; end-user OIDC is v1.x).
- Absorbing volumetric DDoS — that is the VM provider's job (choose accordingly).
- Kubernetes deployment.

---

## 2. Architecture

### 2.1 Component overview

```
                         Internet
                            │   A/AAAA *.example.com → edge public IP  (DNS-only)
                            ▼
┌──────────────────────────────── Edge VM ───────────────────────────────────────┐
│ nftables  (base firewall · L4 DNAT · login-to-play sets · netmap · rate meters)│
│      │ 80/443 tcp, 443 udp                    │ game ports (tcp/udp)           │
│      ▼                                        ▼                                │
│ ┌──────────────── ingressd-edge (Caddy) ───────┐   kernel DNAT ──────┐         │
│ │ TLS/ACME → geo/IP → ratelimit → WAF →        │                     │         │
│ │ challenge → edge_auth → cache →              │                     │         │
│ │ reverse_proxy(edge_tiered LB) → fallback     │                     │         │
│ │ caddy-l4 (SNI / PROXY-protocol TCP)          │                     │         │
│ └──────┬────────────────────────▲──────────────┘                     │         │
│        │ admin API (unix sock)  │ state push / code exchange         │         │
│ ┌──────▼────────────────────────┴──────────────────────────────┐     │         │
│ │ ingressd (control plane)                                      │     │         │
│ │  API + UI · config/git · secrets · apply engine · renderers   │     │         │
│ │  auth portal · OTP/SES · RBAC · PKI/Origin CA · health checks │     │         │
│ │  tunnel mgr (wgctrl) · L4 mgr · crawler · logs/metrics/alerts │     │         │
│ │  SQLite (ephemeral)                                           │     │         │
│ └───────────────────────────────────────────────────────────────┘     │         │
│                                                                       │         │
│   wg-home (10.100.1.1)    wg-cloud (10.100.2.1)    [wstunnel via 443] │         │
└───────┬──────────────────────────┬────────────────────────────────────┼─────────┘
        │ WireGuard (site-initiated)│                                    │
        ▼                          ▼                                    │
  UDM Pro (native WG client)   Cloud VPS (ingressd-connector) ◀─────────┘
  192.168.0.0/24               10.0.1.0/24
```

### 2.2 Processes

Two binaries from one repo, two systemd units:

| Unit | Binary | Role | Restart impact |
|---|---|---|---|
| `ingressd-edge.service` | `ingressd-edge` (custom Caddy) | All L7 traffic, ACME, WAF, L4 TCP via caddy-l4 | Graceful config reloads never restart it; binary upgrade = seconds of restart |
| `ingressd.service` | `ingressd` | Control plane, API, UI, auth portal, health checks, renderers | Proxy **keeps serving** if the control plane restarts or crashes |

Kernel WireGuard interfaces and nftables rules persist independently of both processes.

IPC:
- Control plane → Caddy: Caddy admin API on `unix//run/ingressd/caddy-admin.sock` (config `/load`, targeted `PATCH`).
- Control plane → Caddy modules: state push (health, revocations, signing keys) on `/run/ingressd/edge-state.sock` (custom admin route registered by the `edge_state` module).
- Caddy modules → control plane: auth-code exchange and portal proxying on `/run/ingressd/control.sock`.

### 2.3 Request flows

**HTTP app (protected):**
1. TLS terminates in Caddy (cert from ACME automation policy).
2. Pre-auth filters: IP lists → geo → rate limit → WAF (request phase) → bot challenge (if enabled).
3. `edge_auth` checks the per-host session cookie (offline verification, no control-plane call) or service-token headers.
4. Missing/invalid → redirect to the auth portal (§7.2). Valid → strip spoofable identity headers, inject `X-Edge-User-Email` and signed `Edge-Jwt-Assertion`.
5. Cache layer (if enabled) → `reverse_proxy` with `edge_tiered` selection → origin over a WireGuard interface (optionally TLS / mTLS).
6. On no healthy upstream / 502-504 → stale cache → Always Online snapshot → custom error page.

**L4 game service (transparent mode):**
1. Packet hits `public_ip:30120` → nftables prerouting DNAT → `192.168.0.40:30120` (via tunnel netmap/fwmark if needed).
2. Forwarded out `wg-home`; **no SNAT**; site routes replies back through the tunnel (policy route); conntrack reverses the DNAT.
3. Optional allowlist set check (`login-to-play`) and per-source connection meters before DNAT.

---

## 3. Repository layout

```
ingressd/
├── cmd/
│   ├── ingressd/              # control plane + CLI (serve, apply, validate, diff, export, restore, ...)
│   ├── ingressd-edge/         # custom Caddy main (imports standard + plugin + our modules)
│   └── ingressd-connector/    # site connector
├── internal/
│   ├── config/                # schema types, load, validate (schema + semantic), yaml.v3 node editing (comment-preserving)
│   ├── secrets/               # age-encrypted store, secret:// resolution, rotation
│   ├── gitstore/              # commit/diff/rollback of /etc/ingressd, optimistic locking
│   ├── render/
│   │   ├── caddy/             # config → Caddy JSON (golden-file tested)
│   │   ├── nft/               # config → nftables ruleset
│   │   ├── wg/                # config → interface/peer state, site configs, QR
│   │   └── routing/           # ip rules / fwmark tables for netmap
│   ├── apply/                 # validate → render → diff → apply → verify → commit / rollback
│   ├── tunnel/                # wgctrl manager, handshake monitor, enrollment, wstunnel fallback
│   ├── health/                # active checks, tunnel-aware state, flap protection, state push
│   ├── auth/                  # portal, OTP, sessions, policy engine, service tokens, JWT/JWKS
│   ├── admin/                 # admin users, RBAC, TOTP, WebAuthn, API tokens
│   ├── pki/                   # Origin CA, leaf issuance, edge client certs, bundles
│   ├── l4/                    # L4 service model, presets, login-to-play allowlists
│   ├── crawler/               # Always Online snapshotter
│   ├── observe/               # log ingestion, aggregation, metrics, alert engine, notifiers
│   ├── mail/                  # SES v2 sender, templates, test-send
│   ├── geoip/                 # MaxMind DB management
│   ├── store/                 # SQLite (migrations, ephemeral tables)
│   └── api/                   # REST handlers, OpenAPI, middleware (authn, RBAC, CSRF, audit)
├── caddy/modules/
│   ├── edgestate/             # shared in-memory state + admin route for pushes
│   ├── edgeauth/              # http.handlers.edge_auth
│   ├── edgelb/                # http.reverse_proxy.selection_policies.edge_tiered
│   ├── edgechallenge/         # http.handlers.edge_challenge (PoW)
│   └── edgefallback/          # http.handlers.edge_fallback (Always Online / error pages)
├── connector/                 # wireguard-go + TUN / netstack modes, control channel, service install
├── web/                       # SvelteKit app (static adapter), Monaco YAML editor
├── schema/config.schema.json  # generated from Go types; used by UI editor + CLI
├── deploy/                    # install.sh, systemd units, docker-compose, sysctl, base nft
├── test/
│   ├── netns/                 # integration tests in Linux network namespaces
│   └── e2e/                   # docker compose + Playwright
└── docs/                      # site setup guides per router vendor, game presets, operations
```

Build: `make` → `xcaddy build` with pinned plugin versions for `ingressd-edge`; Go build for others; UI built first and embedded via `go:embed`. Releases: reproducible builds, SBOM, cosign-signed artifacts, `linux/amd64` + `linux/arm64` (+ connector for windows/darwin).

---

## 4. Configuration system

### 4.1 Files on the edge

```
/etc/ingressd/              (git repository, root:ingressd 0750)
├── config.yaml             # everything non-secret, human-editable
├── secrets.age             # age-encrypted key/value secrets
└── .git/
/etc/ingressd-keys/age.key  # X25519 identity (0600) — NOT in the git repo; back it up separately
/var/lib/ingressd/
├── state.db                # SQLite ephemeral state
├── caddy/                  # Caddy data dir (ACME certs/accounts)
├── snapshots/<app>/<ts>/   # Always Online snapshots
└── geoip/                  # MaxMind DBs
```

### 4.2 Full example `config.yaml`

```yaml
version: 1

edge:
  name: edge-lon1
  public_ipv4: 203.0.113.10
  public_ipv6: 2001:db8::10          # optional
  admin:
    hostname: edge.example.com
    exposure: public                  # public | tunnel_only | ip_allowlist
    ip_allowlist: []
  acme:
    email: me@example.com
    ca: letsencrypt                   # letsencrypt | letsencrypt_staging | zerossl
    dns_provider:
      type: cloudflare
      api_token: secret://cloudflare_dns_token
  geoip:
    maxmind_account_id: "123456"
    maxmind_license_key: secret://maxmind_key
  crowdsec:
    enabled: false
    lapi_url: http://127.0.0.1:8080
    api_key: secret://crowdsec_bouncer_key

email:
  provider: ses
  region: eu-west-2
  from: "ingressd <login@example.com>"
  access_key_id: secret://ses_access_key_id
  secret_access_key: secret://ses_secret_access_key

certificates:
  wildcards: ["*.example.com", "example.com"]   # issued via DNS-01, used by matching hosts
  origin_ca:
    enabled: true
    common_name: "ingressd Origin CA"

tunnels:
  home:
    type: wireguard
    site: router                      # router | connector
    vendor: unifi                     # unifi | opnsense | pfsense | mikrotik | openwrt | fritzbox | generic
    listen_port: 51820
    transit: 10.100.1.0/24            # edge .1, site .2
    subnets: [192.168.0.0/24]
    virtual_prefix: null              # e.g. 10.201.0.0/24 when subnets overlap another tunnel
    keepalive: 25
    public_key: "Xk1...="             # site's public key (private keys live in secrets / on the site)
  cloud-backup:
    type: wireguard
    site: connector
    listen_port: 51821
    transit: 10.100.2.0/24
    subnets: [10.0.1.0/24]
    fallback_ws: true                 # allow WireGuard-over-WebSocket via 443

groups:
  family:
    emails: [alice@gmail.com, bob@outlook.com]
  work:
    email_domains: [example.com]

service_tokens:
  ha-webhook:
    client_id: 3f9c2b1e.access
    client_secret: secret://svc_ha_webhook
    expires: 2027-11-01

policies:
  family-or-work:
    action: allow
    include: [{ group: family }, { group: work }]
    exclude: [{ country: [RU, CN] }]
    session: 24h
  admins-only:
    action: allow
    include: [{ email: [me@example.com] }]
    require: [{ ip: [81.2.3.0/24] }]
    session: 8h
  ha-webhook:
    action: service_auth
    include: [{ service_token: ha-webhook }]
  public:
    action: bypass
    include: [{ everyone: true }]

pools:
  server-pool:
    steering: weighted                # round_robin | weighted | least_conn | failover | random | ip_hash
    sticky: { cookie: edge_aff, ttl: 1h }
    failback: auto                    # auto | manual
    failback_hold: 2m
    health:
      type: http
      path: /healthz
      host: server.example.com
      interval: 10s
      timeout: 3s
      expect_status: [200]
      expect_body: null
      unhealthy_after: 3
      healthy_after: 3
    origins:
      - { name: home-1, tunnel: home,         address: https://192.168.0.17:8443, weight: 50, priority: 1 }
      - { name: home-2, tunnel: home,         address: https://192.168.0.18:8443, weight: 50, priority: 1 }
      - { name: cloud,  tunnel: cloud-backup, address: https://10.0.1.5:8443,     priority: 2 }
    fallback: always_online

apps:
  server:
    hosts: [server.example.com]
    pool: server-pool
    tls:
      origin: strict                  # off | full | strict
      verify_with: origin_ca          # origin_ca | public | custom:<pem secret>
      server_name: server.internal
      mtls: true                      # authenticated origin pulls
    access: [admins-only]
    paths:
      - { match: /api/webhook/*, access: [ha-webhook] }
    waf: { mode: block, paranoia: 1, exclusions: [{ rule: 942100, path: /api/search }] }
    rate_limit: [{ match: /login, requests: 10, per: 1m, key: ip }]
    headers:
      preset: strict                  # none | basic | strict (HSTS, nosniff, frame-deny, referrer)
      request: { set: { X-Forwarded-Proto: https } }
    proxy: { websockets: true, max_body: 512MB, timeout: 120s }

  portfolio:
    hosts: [example.com, www.example.com]
    origin: http://192.168.0.20:3000  # shorthand: single-origin pool
    tunnel: home
    access: [public]
    redirects: [{ from: www.example.com, to: example.com, code: 301 }]
    waf: { mode: block, paranoia: 2 }
    bot_challenge: suspicious         # off | suspicious | always | under_attack
    cache: { enabled: true, default_ttl: 10m, stale_if_error: 7d }
    always_online:
      enabled: true
      crawl: { schedule: "0 4 * * *", start: [/, /sitemap.xml], max_pages: 2000, keep: 3 }
      banner: true

l4:
  fivem:
    preset: fivem                     # fivem | minecraft_java | minecraft_bedrock | custom
    listen: [30120/tcp, 30120/udp]
    target: { tunnel: home, address: 192.168.0.40, port: 30120 }
    mode: transparent                 # proxy | transparent
    access: login_to_play             # public | allowlist | login_to_play
    login_to_play: { policy: family-or-work, ttl: 12h, portal_host: play.example.com }
    limits: { conn_per_ip: 20, new_conn_rate: 30/s }
  minecraft:
    preset: minecraft_java
    listen: [25565/tcp]
    target: { tunnel: home, address: 192.168.0.41, port: 25565 }
    mode: proxy
    proxy_protocol: v2                # Velocity/Paper can read real IPs
    access: public

admins:
  - { name: Alex, email: alex@example.com, role: owner }
  - { name: Sam, email: sam@example.com, role: operator, scope: { l4: [fivem, minecraft] } }

alerts:
  channels:
    phone: { type: ntfy, url: https://ntfy.sh/my-topic-xyz }
    discord: { type: discord, webhook: secret://discord_webhook }
  rules:
    - { on: [tunnel_down, pool_failover, pool_all_down, cert_renewal_failed], notify: [phone, discord] }
    - { on: [waf_spike, origin_down], notify: [discord] }

logging:
  retention: 7d
  access_log_sampling: 1.0
```

### 4.3 Secrets
- `secrets.age`: a flat map `name → value`, encrypted to the edge's age identity (and optionally a second **recovery recipient** — your offline key or passphrase).
- Referenced from YAML as `secret://name`. Validation fails if a reference is missing.
- UI/API treat secrets as **write-only** (set/rotate/delete; never displayed). Generated artifacts (WireGuard site configs, origin cert bundles) are produced on demand for download.
- Stored secrets include: DNS token, SES keys, MaxMind key, CrowdSec key, WireGuard edge private keys, Origin CA keys, session signing keys, JWT signing keys, service-token secrets, admin password hashes, TOTP seeds, WebAuthn credentials.

### 4.4 Apply pipeline

```
edit (UI / CLI / file)
  → parse (yaml.v3 Node — preserves comments & ordering)
  → schema validation (JSON Schema generated from Go types)
  → semantic validation
      references exist · hostnames unique · port conflicts · overlapping subnets need virtual_prefix
      cert coverage · always_online only on public apps · policy cycles · RBAC scope of the editor
  → render: Caddy JSON · nftables ruleset · WireGuard state · ip rules
  → diff (shown in UI before confirm; `ingressd diff` in CLI)
  → apply in order: wg (wgctrl) → routes/rules → nft (atomic `nft -f`) → Caddy (/load)
  → post-apply checks (Caddy config readback, interfaces up, rules loaded)
  → git commit (author = admin, message = summary)    |   on failure: re-apply last good render, no commit
```

- Optimistic concurrency: every edit carries the base commit hash; stale edits are rejected with a merge view.
- Manual file edits: `ingressd apply` (or the UI "Pending file changes detected → review & apply" banner via fs watch).
- Rollback: pick any commit → diff → apply.
- Dry-run everywhere (`--dry-run`, UI preview).

### 4.5 Export / backup / restore
- **Export** (Owner): `.tar.gz` containing `config.yaml`, `secrets.age`, git bundle (history), optional snapshots. Option to **re-encrypt secrets to a passphrase** so the archive is restorable without the edge's key file.
- **Scheduled backups**: local rotation + optional push to a private git remote and/or S3-compatible bucket (encrypted).
- **Restore**: `ingressd restore backup.tar.gz` on a fresh VM → applies config; ACME certs re-issue automatically (or restore Caddy data dir to avoid rate limits); WireGuard keys preserved so sites reconnect after the DNS/IP change (sites dial `edge.example.com`, so only DNS needs updating).
- **Config-only export** (no secrets) for sharing / review.

---

## 5. Tunnels & sites

### 5.1 Edge side
- One kernel WireGuard interface per tunnel (`wg-<name>`), each with its own UDP listen port (default 51820, 51821, ...). Firewall opens them automatically.
- Transit network per tunnel (`10.100.N.0/24`, edge `.1`, site `.2`), allocated automatically.
- Peer `AllowedIPs` on the edge = transit `/32` of the site + a `/32` for every address that apps, pool origins and L4 services publish on that tunnel (`Config.TunnelRoutes`). Like a cloudflared tunnel, you only name the apps: no LAN subnet is required, and the edge can reach exactly what is published. `subnets` is optional, for making whole networks reachable (and required for remapped tunnels).
- Routes to site subnets via the tunnel interface.
- **Overlapping subnets** (two sites with `192.168.0.0/24`): each tunnel gets a `virtual_prefix` (e.g. `10.201.0.0/24`). The edge:
  1. marks packets to the virtual prefix with a per-tunnel fwmark,
  2. prefix-DNATs (netmap) virtual → real subnet,
  3. routes by fwmark via a per-tunnel routing table.
  Origins are still written with real LAN IPs + tunnel name; the renderer maps them. Validation forces a virtual prefix when overlap is detected.
- **Tunnel health**: `wgctrl` polling every 5 s → last handshake age, RX/TX counters, endpoint. Handshake older than 180 s ⇒ tunnel down ⇒ all origins on it immediately unhealthy, alert fired.
- **WebSocket fallback**: a `wstunnel` server (embedded Go implementation) exposed by Caddy at `https://edge.example.com/.ingressd/tunnel/<tunnel-id>` → forwards to the tunnel's local UDP port. Used only by the connector when UDP is blocked.

### 5.2 Site types

| Site type | When | Setup |
|---|---|---|
| **Router (native WG)** | UDM/UniFi, OPNsense, pfSense, MikroTik, OpenWrt, Fritz!Box | Panel generates the site keypair (or accepts your pubkey), produces `.conf` + QR, and a vendor-specific step-by-step guide incl. firewall rules. |
| **Connector – TUN mode** | Any Linux box (root), Docker with `NET_ADMIN` | Full routed subnet access; supports **transparent** L4 mode via policy routing on the connector host. |
| **Connector – netstack mode** | No root, Windows/macOS, locked-down hosts | Userspace WireGuard + gVisor netstack: connector dials targets itself (like cloudflared). Proxy-mode only (origins see the connector's IP). |

### 5.3 UniFi (UDM Pro) specifics
- Use **UniFi Network → VPN → VPN Client → WireGuard → import config** (or Site-to-Site WireGuard where available). Survives firmware upgrades because it is native config.
- Site config generated by the panel:
  - `Address = 10.100.1.2/24`, `Endpoint = edge.example.com:51820`, `PersistentKeepalive = 25`
  - `AllowedIPs = 10.100.1.0/24` (proxy-mode apps only), or `0.0.0.0/0` **plus policy-based routes** for transparent-mode game hosts (only those devices' traffic uses the tunnel).
- Firewall (zone-based): allow `VPN → LAN` only to the published `host:port` pairs. The panel prints the exact rule list from config.
- The UDM spike ([spikes/02](spikes/02-udm-wireguard.md)) verifies all of this on current UniFi OS (import behaviour with `0.0.0.0/0`, policy routes per device/VLAN, zone firewall behaviour, MTU).

### 5.4 Connector (`ingressd-connector`)
- **Enrollment**: panel creates a one-time token (15 min TTL) → `ingressd-connector enroll https://edge.example.com <token>` → connector generates its keypair locally, posts its public key, receives tunnel config. Private key never leaves the site.
- **Control channel**: HTTPS long-poll to the control plane over the tunnel (`10.100.N.1`) for config updates, health reporting, and log of reachability tests. Falls back to public HTTPS if the tunnel is down.
- **Transport selection**: UDP direct → if no handshake within 15 s, WebSocket over 443 → periodic UDP retry.
- **MTU**: probe and set (1420 → 1380 → 1280 for nested/WS).
- **Install**: systemd unit, Docker image, Windows service, launchd plist. Optional self-update from signed releases.
- **Transparent mode support (TUN)**: installs policy routing so replies from configured `host:port` sources leave via the tunnel.
- **Local allowlist**: the host keeps its own list of networks the edges may reach, in `connector.allowlist.json` beside the state file (same protections). What is forwarded is the site's configured subnets and transparent sources intersected with this list, enforced in the TUN nftables rules and the netstack forwarder; a wider config is narrowed, not an error, and refused networks are logged once and shown by `status` and `allow list`. By default the list is the private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) plus what the site is configured for at enrolment or the first start after an upgrade; `enroll --allow` replaces that default. An origin on a private address added in the panel later therefore works with no step on the host. The default covers every private address, the connector host's own LAN address included; use `--allow` to narrow it to the networks the site needs. A `0.0.0.0/0` subnet is not pinned: the addresses the site publishes through it are, one by one. Loopback, the cloud metadata address and public networks are refused: **publishing an origin on a public address needs `ingressd-connector allow add <network>` on the site's host** (it needs the rights that own the state file; a running connector applies the change within seconds by restarting its link). `0.0.0.0/0` and `::/0` need `--allow-any-network`. A missing, unreadable or empty list forwards nothing to the LAN while the tunnel and control channel stay up; `allow add` repairs it, starting a new list holding only what it is given. TUN mode enforces a list with `nft`: the Linux installer tries to install it, and without it the list is not enforced, which `status` and the connector's health report show. A list that cannot be used forwards nothing even then, by a routing rule on the tunnel interface. LAN discovery scans only inside the list.

---

## 6. Applications, pools & load balancing

### 6.1 App routing features
- Multiple hosts per app; wildcard host apps (`*.lab.example.com` → one pool) allowed.
- Path routes with per-path pool / access / WAF / cache overrides.
- Redirects (host/path, 301/302/307/308), rewrites, `strip_prefix`.
- Request/response header set/add/delete; security header presets.
- WebSockets, gRPC (h2c / h2 to origin), HTTP/3 at the edge.
- Limits: max body, timeouts, buffering toggles.
- Client IP: `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`; trusted-proxy semantics so origins can rely on them.
- Maintenance mode toggle with custom page; custom error pages per status.

### 6.2 Pools
- Origin = `name, tunnel | direct, address (scheme://host:port), weight, priority, state (active|draining|disabled)`.
- Direct (non-tunnel) origins allowed; validation warns unless `tls.origin = strict` and `mtls = true`.
- Steering policies: `round_robin`, `weighted`, `least_conn`, `failover`, `random`, `ip_hash`.
- **Tiers**: origins grouped by `priority`; traffic goes to the lowest-numbered tier with ≥1 healthy origin and is split by weight/policy within it.
- **Sticky sessions**: signed affinity cookie (origin ID); if the pinned origin goes unhealthy the request is re-balanced and the cookie rewritten.
- **Draining**: no new sessions; existing sticky sessions continue until TTL.
- **Manual override**: force a tier/origin (with optional expiry) — surfaced as a banner in the UI.

### 6.3 Health checking
- Owned by the control plane (single source of truth for UI, alerts, LB):
  - Active: HTTP(S) (path, host header, method, expected status list, body regex, TLS verification matching the app's origin TLS mode), or TCP connect for L4.
  - Tunnel-aware: tunnel down ⇒ origins down instantly.
  - Flap protection: `unhealthy_after` / `healthy_after` consecutive results; `failback_hold` before returning to a higher tier; `failback: manual` requires a click.
- Caddy passive health (`fail_duration`, `max_fails`, `unhealthy_status`) for per-request reaction between active checks.
- State pushed to `edge_state` within ~100 ms of change; `edge_tiered` reads it lock-free (atomic snapshot).
- Health history stored (24 h at full resolution, 30 d aggregated) for the pool timeline.

### 6.4 `edge_tiered` selection policy (custom Caddy module)
```
input: upstreams[], per-upstream metadata {origin_id, priority, weight}, pool policy, health snapshot, override
1. if override active → candidate set = forced origin(s)
2. else candidate set = lowest priority tier with any upstream (control-plane healthy ∧ caddy Available())
3. if sticky cookie → pinned origin if in candidate set
4. select within set by policy (weighted RR via smooth weighted round robin; least_conn; ip_hash; random)
5. none → return nil → handler falls through to edge_fallback chain
```

### 6.5 Fallback chain
`primary tier → lower tiers → stale cache (stale_if_error) → Always Online snapshot → custom "origin unavailable" page`

---

## 7. Access (Zero Trust)

### 7.1 Concepts
- **Identity**: a verified email address (emailed OTP, or a provider that verified it), or a provider account without one (`steam:<SteamID64>`, `discord:<id>`, …). Sign-in methods: the emailed code and Discord, Google, Microsoft, Steam (`access.providers`, offered per app with `apps.<app>.login_methods`; see [ACCESS-PROVIDERS.md](ACCESS-PROVIDERS.md)). Facts from the provider (guilds, roles, groups, tenant, owned games) are captured at sign-in into the session and the app cookie. No user pre-registration; membership comes from policies/groups.
- **Groups**: named sets of emails / email domains (later: OIDC groups).
- **Policies**: ordered per app; **first matching policy wins**.
  - `action`: `allow` | `deny` | `bypass` (no login) | `service_auth` (service tokens only).
  - `include` (any of), `require` (all of), `exclude` (none of).
  - Selectors: `everyone`, `email`, `email_domain`, `group`, `ip`, `country`, `service_token`, `login_method`, and the identity-provider selectors `discord_user`, `discord_username`, `discord_guild`, `discord_role`, `google_hd`, `microsoft_tenant`, `microsoft_group`, `microsoft_role`, `steam_id`, `steam_group`, `steam_app` (matched against the facts captured at sign-in, so a membership change applies when the session ends; network selectors are re-checked on every request).
  - `session`: duration for cookies minted under this policy.
- **Path overrides**: per path, separate policy list (e.g. `bypass` for `/api/webhook/*`).
- **Service tokens**: `Edge-Client-Id` + `Edge-Client-Secret` headers; secrets hashed (argon2id at rest in secrets store, verified via cached HMAC in the module); expiry + rotation. **Header tokens** (`service_tokens.<name>.header`): the secret alone in a header of the user's choice, checked the same way (HMAC verifier, constant time, every request, expiry, combinable with `ip`), and removed before the request reaches the origin.

### 7.2 Login flow (works across different registrable domains)
1. `GET https://app.example.com/x` → `edge_auth`: no/invalid `__edge_<appid>` cookie.
2. Redirect → `https://auth.example.com/login?app=<appid>&rd=<url>` (`rd` must match the app's configured hosts — no open redirects).
3. Portal: a **Continue with …** button per enabled provider (same-origin POST → state + PKCE + nonce sealed in a short-lived cookie → provider → `/oauth/<provider>/callback`, fully verified; see ACCESS-PROVIDERS.md), and/or enter email → if the email could ever satisfy an app policy, send OTP via SES; **response identical either way** (no enumeration).
4. User enters the 6-digit code → portal session cookie on `auth.example.com` (so other apps can skip OTP for the portal session lifetime, per policy).
5. Portal evaluates the app's policies (IP, country, email, group) → issues a **one-time auth code** (60 s TTL, single use, bound to app + `rd`).
6. Redirect → `https://app.example.com/.ingressd/callback?code=…` → `edge_auth` exchanges the code with the control plane over the unix socket → sets host-only cookie:
   - `HttpOnly; Secure; SameSite=Lax; Path=/`
   - value = PASETO v4.local (encrypted + authenticated) containing `sid, email, app, policy_id, policy_version, iat, exp, ip_bind?`
7. Subsequent requests verified **offline** in Caddy (no control-plane round trip). Revocation: control plane pushes revoked `sid`s / bumped `policy_version`s to `edge_state`.

Identity to origins: `X-Edge-User-Email` plus `Edge-Jwt-Assertion` (ES256 JWT, `aud = app`) verifiable against `https://auth.example.com/.well-known/jwks.json`. Incoming copies of these headers are always stripped.

Logout: a same-origin POST to `/.ingressd/logout` on any app (clears app cookie) and to `/logout` on the portal (revokes `sid` globally); GET on either shows a confirmation form (logout CSRF).

### 7.3 OTP specification
| Setting | Default | Configurable |
|---|---|---|
| Length | **6** | 4–8 |
| TTL | **5 min** | 1–15 min |
| Attempts per code | 5 | ✓ |
| Resend cooldown | 60 s | ✓ |
| Rate limit per email | 5 codes / 15 min | ✓ |
| Rate limit per IP | 20 codes / 15 min | ✓ |
| Lockout | 15 min after limit | ✓ |
| Storage | argon2id hash, single-use | — |

Email template: subject `Your sign-in code for <app>`, code, app name, requester IP/location, "ignore if not you". HTML + text parts. Customisable branding (logo, colours) applied to portal and email.

### 7.4 Amazon SES integration
- SES API v2 `SendEmail` with AWS SDK for Go v2.
- Setup wizard checks: domain identity verified (Easy DKIM), custom MAIL FROM (SPF alignment), DMARC record present, account out of sandbox (warn otherwise), test-send button.
- IAM least privilege: `ses:SendEmail` restricted with `ses:FromAddress` condition.
- Optional: SNS bounce/complaint webhook → suppress addresses + show in UI.
- Failure handling: retries with backoff; alert `email_delivery_failing` after N failures.

---

## 8. Admin, RBAC & API access

### 8.1 Roles

| Permission | Owner | Admin | Operator | Viewer |
|---|:-:|:-:|:-:|:-:|
| View dashboard, apps, logs | ✓ | ✓ | ✓ | ✓ |
| Drain / disable origins, force tier, maintenance mode | ✓ | ✓ | ✓ | |
| Revoke end-user sessions, login-to-play entries | ✓ | ✓ | ✓ | |
| Edit apps, pools, policies, WAF, L4, tunnels, certs | ✓ | ✓ | | |
| Download site configs / origin certs | ✓ | ✓ | | |
| Edit/rotate secrets, SES/DNS settings | ✓ | | | |
| Manage admins & roles | ✓ | | | |
| Export / restore / rollback | ✓ | ✓ (rollback only) | | |

- **Scopes**: a role can be limited to named apps, pools, tunnels or L4 services (e.g. a friend as Operator over `l4: [fivem]`). Enforced in API middleware and in semantic validation (a scoped admin cannot commit changes outside scope).
- At least one Owner must always exist (validation).

### 8.2 Admin authentication
- Password (argon2id) **plus** mandatory second factor: TOTP or WebAuthn passkey (passkey can be sole factor).
- Admin sessions: `SameSite=Strict` cookie, 12 h idle / 7 d absolute, CSRF token on mutating requests, re-auth for sensitive actions (secrets, admins, restore).
- Admin panel exposure: `public` (default, with the above), `tunnel_only` (bound to transit IPs — reachable only over a WireGuard admin peer), or `ip_allowlist`.
- Login rate limiting + lockout; alert on admin login from a new IP/country.
- **API tokens**: per admin, scoped to a role ≤ the admin's own, expiring, shown once. Used by CLI (`ingressd login`) and automation.
- **Audit log**: every mutation (API + CLI + file apply) recorded with actor, IP, diff; also reflected in git commit author/message.
- Bootstrap: install prints a one-time setup URL to create the first Owner.

---

## 9. Certificates & PKI

### 9.1 Edge certificates (public)
- Caddy automation policies rendered from config:
  - Hosts covered by `certificates.wildcards` → wildcard cert via **Cloudflare DNS-01** (scoped token: Zone → DNS → Edit on specific zones).
  - Other hosts → individual certs via DNS-01 if the provider manages the zone, else HTTP-01/TLS-ALPN-01.
  - Optional custom uploaded certs per host.
- OCSP stapling, TLS 1.2+ (1.3 preferred), HTTP/3.
- UI: cert inventory (SANs, issuer, expiry, last renewal, errors), "renew now".
- Pre-flight check per host: resolves to the edge IP, **not** Cloudflare-proxied (warn if Cloudflare anycast IPs are returned).
- ACME staging toggle for testing.

### 9.2 Origin CA
- Two-level PKI generated on enable:
  - **Root**: ECDSA P-384, 20 y, key encrypted in `secrets.age`, used only to sign intermediates.
  - **Origin intermediate**: signs origin server certs.
  - **Edge-client intermediate**: signs the edge's mTLS client cert.
- Issue origin certs from the UI/CLI: SANs (DNS/IP), validity (default 15 y, configurable), key type (ECDSA P-256 / RSA 2048-4096) or **CSR upload** (private key never touches the edge).
- Downloads: PEM (cert + chain), key (only if generated), PKCS#12/PFX, plus config snippets for nginx, Caddy, Traefik, IIS, Apache.
- Inventory with serials, expiry, issued-by, revoke (revocation recorded; edge refuses revoked serials in `strict` mode via a pushed deny list).
  - *As built:* inventory in `pki-inventory.yaml` (git-tracked). Caddy's proxy transport cannot check individual serials, so `strict`/`origin_ca` trusts only the **current origin issuer**; `ingressd cert origin revoke <serial> --rotate` replaces that issuer, which (after apply) stops the edge trusting every certificate the old issuer signed; the CLI lists the ones to re-issue. A per-serial deny list needs a custom transport module (future).
  - The edge client cert is valid 2 y and re-issued on any apply when < 1 y remains; Caddy reads it from `<state-dir>/pki/edge-client-<serial>.{crt,key}`.

### 9.3 Origin TLS modes (per app / per origin)
| Mode | Edge → origin |
|---|---|
| `off` | Plain HTTP over WireGuard (still encrypted by WG) |
| `full` | HTTPS, no certificate verification |
| `strict` | HTTPS, verify against Origin CA, public roots, or a custom CA; optional `server_name` override |
| `+ mtls` | Edge presents its client cert (edge-client intermediate); origin is configured to require it — "authenticated origin pulls" |

---

## 10. Edge security

### 10.1 WAF
- Coraza (`coraza-caddy`) with embedded **OWASP CRS v4** (version pinned, updates via release).
- Per app/path: `mode: off | detect | block`, `paranoia: 1–4`, inbound/outbound anomaly thresholds, rule exclusions (by rule ID/tag, path, argument/header/cookie name).
- Response-body inspection off by default (performance), opt-in per app.
- WAF events → log pipeline → UI table with request detail; "**create exclusion from this event**" (proposes a scoped exclusion, previewed as a config diff).
- Regression testing with `go-ftw` CRS test suite in CI.

### 10.2 Rate limiting
- `caddy-ratelimit` zones: per app/path, key by IP, IP+path, header, or authenticated email; sliding window; `429` with `Retry-After`; optional challenge instead of block.

### 10.3 IP & geo rules
- Global and per-app allow/deny lists (CIDR); country allow/deny (MaxMind GeoLite2, auto-update with `geoipupdate` logic built in); optional ASN blocking.

### 10.4 Bot challenge (`edge_challenge`)
- JavaScript **proof-of-work** interstitial (SHA-256, adjustable difficulty), no third-party calls.
- Pass → signed clearance cookie (HMAC, bound to IP /24 + UA hash, default 24 h).
- Modes: `off`, `suspicious` (only when heuristics trigger: missing/odd headers, CrowdSec decision, high request rate without clearance, bad ASN list), `always`, `under_attack` (global toggle, higher difficulty).
- Allow-list for verified good bots (forward-confirmed reverse DNS for Googlebot/Bingbot), API paths, and service tokens.
- Accessible `<noscript>` explanation; optional Turnstile/hCaptcha provider as an alternative challenge backend.

### 10.5 CrowdSec (optional)
- Caddy bouncer module + nftables bouncer integration; the control plane can ship Caddy access logs to a local CrowdSec agent. Decisions shown in UI.

### 10.6 Security headers
- Presets: `basic` (nosniff, referrer-policy), `strict` (+ HSTS 1 y incl. subdomains opt-in, frame-deny, permissions-policy), custom CSP field.

---

## 11. TCP/UDP services (L4)

### 11.1 Engines
| Engine | Used for | Capabilities |
|---|---|---|
| **nftables DNAT** (default) | UDP and plain TCP (FiveM, Minecraft, generic) | Kernel fast path, transparent or SNAT, allowlist sets, per-IP meters |
| **caddy-l4** | TCP needing TLS-SNI routing, PROXY protocol v1/v2 injection, multiplexing many services on one port | Userspace; integrates with Caddy certs |

### 11.2 Modes
| Mode | Behaviour | Requirement |
|---|---|---|
| `proxy` | SNAT to the edge transit IP; origin sees the edge | Works everywhere; enable `proxy_protocol` where the game supports it to recover real IPs |
| `transparent` | DNAT only; **origin sees real player IPs** | Site must route replies through the tunnel: UniFi policy-based route for the game host/VLAN, or connector in TUN mode |

Validation: transparent mode requires a site that declares return-routing support; panel shows the exact UniFi steps.

### 11.3 Presets
| Preset | Ports | Default mode | Notes |
|---|---|---|---|
| `fivem` | 30120/tcp + 30120/udp | transparent | No PROXY protocol support, so transparent preferred. Panel generates the server.cfg snippet for running behind a proxy (listing host override / indirect listing settings — exact convars verified against current FiveM docs (see [spikes/04](spikes/04-fivem.md))). **txAdmin (40120) is published as an HTTP app behind Access, never a raw port.** |
| `minecraft_java` | 25565/tcp | proxy + PROXY v2 | Velocity/BungeeCord/Paper can read PROXY protocol → real IPs without transparent routing. |
| `minecraft_bedrock` | 19132/udp | transparent | UDP. |
| `custom` | any | either | Generic TCP/UDP. |

Future: hostname-based Minecraft routing (multiple servers on 25565 by handshake hostname) via an embedded Gate/mc-router-style matcher.

### 11.4 Access for L4
- `public`: open to all (with meters and CrowdSec).
- `allowlist`: static CIDRs.
- `login_to_play`: friend visits `play.example.com`, signs in via email OTP under the referenced policy → their current IP added to an nftables **set with timeout** (`ttl`, e.g. 12 h) for that service's ports. UI shows current entries; Operators can add/revoke. Optional "renew" button and email-on-expiry.
- Limits: concurrent connections per IP, new-connection rate per IP (nft meters), global PPS guard.

### 11.5 Operational notes (documented in UI)
- Latency = player→edge + edge→home: choose a VM region close to home and friends.
- Game traffic crosses the VM twice: pick a provider with generous egress.
- Game servers attract DDoS: prefer a provider with L4 DDoS filtering (e.g. OVH game range; Hetzner basic protection).

---

## 12. Caching & Always Online

### 12.1 Cache
- `cache-handler` (Souin) per app: respects origin `Cache-Control`, default TTL override, bypass for authenticated requests and `Set-Cookie` responses, purge by URL/prefix/all from the UI/API, `stale-if-error` window.
- Cache keys exclude cookies by default; vary on `Accept-Encoding`.

### 12.2 Always Online snapshots
- Allowed only for apps whose effective policy for the path is `bypass` (public). Validation error otherwise (leak prevention).
- Crawler (control plane): starts from configured URLs + `sitemap.xml`; same-host only; respects `robots.txt` opt-out; fetches **directly from the origin pool** (internal, not via public edge); captures HTML, CSS, JS, images, fonts; rewrites nothing except optional banner injection; stores with content-type metadata.
- Schedule (cron), max pages/size, keep last N snapshots, manual "snapshot now", snapshot browser + "preview offline mode".
- Serving: `edge_fallback` handler serves from the latest snapshot when the pool has no healthy origin or returns 502/503/504; response header `X-Edge-Served-From: snapshot`; optional banner ("You're viewing a cached copy; the site is temporarily offline").
- Optional mode `static_mirror`: always serve from snapshot (zero origin load) — useful for the portfolio.

---

## 13. Observability & alerting

- **Access logs**: Caddy JSON logs → net writer to the control plane → ring buffer (live tail in UI) + SQLite (7 d) + per-minute aggregates (30 d).
- **Events**: WAF matches, auth (OTP sent/verified/failed, policy denials), admin audit, health/tunnel transitions, L4 allowlist changes.
- **Dashboard**: requests/s, status codes, bandwidth, top hosts/paths/countries, WAF blocks, auth success/failure, tunnel status + latency, pool tiers, cert expiry, L4 connections.
- **Metrics**: `/metrics` (Prometheus) for control plane + Caddy metrics + WG + L4 counters (nft counters). Optional Grafana dashboard JSON in `docs/`.
- **Alert rules** (built-in, routed by config): `tunnel_down`, `origin_down`, `pool_failover`, `pool_all_down`, `cert_expiring` (<14 d) / `cert_renewal_failed`, `waf_spike`, `auth_bruteforce`, `admin_login_new_location`, `email_delivery_failing`, `disk_low`, `backup_failed`. Dedup, recovery notifications, quiet hours.
- **Channels**: ntfy, Discord, generic webhook, email (SES).

---

## 14. API, CLI & UI

### 14.1 REST API (`/api/v1`, OpenAPI 3 generated)
```
GET/PUT    /config                    (raw YAML, with base revision)
POST       /config/validate | /config/diff | /config/apply
GET        /config/history            GET /config/history/{rev}   POST /config/rollback/{rev}
POST       /config/export             POST /config/restore
CRUD       /apps  /pools  /tunnels  /l4  /policies  /groups  /service-tokens  /admins
POST       /pools/{id}/origins/{o}/drain|disable|enable     POST /pools/{id}/override
GET        /tunnels/{id}/site-config(.conf|.qr|guide)        POST /tunnels/{id}/enroll-token
GET        /certs                     POST /certs/{host}/renew
POST       /pki/origin/issue          POST /pki/origin/sign-csr   POST /pki/origin/{serial}/revoke
GET        /sessions                  DELETE /sessions/{sid}      DELETE /sessions?email=
GET/POST/DELETE /l4/{id}/allowlist
POST       /cache/{app}/purge         POST /snapshots/{app}       GET /snapshots/{app}
GET        /logs/access|waf|auth|audit (filters, cursor)          GET /logs/stream (SSE)
GET        /health/pools  /health/tunnels
PUT        /secrets/{name}            DELETE /secrets/{name}      GET /secrets (names only)
POST       /email/test
```

### 14.2 CLI (`ingressd`)
```
ingressd serve                     # control plane
ingressd login <url>               # API token auth for remote use
ingressd validate|diff|apply [-f config.yaml] [--dry-run]
ingressd history | rollback <rev>
ingressd export [--passphrase] | restore <file>
ingressd tunnel add|config|qr|enroll-token <name>
ingressd pool drain|enable|override ...
ingressd cert origin issue --san ... | sign-csr file.csr
ingressd secret set|rotate|rm <name>
ingressd admin create|reset-2fa
ingressd sessions revoke --email x
ingressd doctor                    # checks DNS, ports, ACME, SES, tunnels, kernel features
```

### 14.3 UI pages
1. **Dashboard** — traffic, security, tunnels, pools, certs, alerts at a glance.
2. **Applications** — list; detail tabs: Routing · Access · Security (WAF/rate/bot/geo) · Caching & Always Online · Origin TLS · Logs.
3. **Pools** — origins with health/latency, live traffic share, weight sliders, drain/disable/force tier, failover timeline.
4. **Sites & Tunnels** — status, handshake, throughput; **"Add site" wizard** (pick vendor → keys → download/QR → guided steps → live "waiting for handshake" check).
5. **TCP/UDP Services** — presets, mode, ports, allowlist/login-to-play entries, connection stats, generated game config snippets.
6. **Access** — policies (drag to order, test-a-user simulator: "would bob@x.com from GB be allowed on app Y?"), groups, service tokens, active sessions.
7. **Certificates** — edge cert inventory; Origin CA (issue, CSR sign, downloads, revoke).
8. **Security** — WAF event explorer with exclusion builder, IP/geo lists, bot challenge & under-attack toggle, CrowdSec decisions.
9. **Logs** — access/auth/audit search + live tail.
10. **Alerts** — channels, rules, history.
11. **Configuration** — Monaco YAML editor with schema autocomplete/validation, diff preview, history/rollback, export/restore, pending-file-change banner.
12. **Admins** — users, roles, scopes, 2FA status, API tokens.
13. **Settings** — edge, ACME/DNS, SES wizard, GeoIP, CrowdSec, branding, backups.

Every form shows the resulting YAML diff before saving.

---

## 15. Data model (SQLite — ephemeral only)

| Table | Purpose |
|---|---|
| `otp_codes` | email, app, code_hash, expires_at, attempts, ip |
| `auth_codes` | one-time callback codes (code_hash, sid, app, rd, expires_at, used) |
| `sessions` | sid, email, policy_id, policy_version, created, expires, ip, ua, revoked |
| `admin_sessions` | admin sessions + CSRF secret |
| `rate_counters` | sliding-window counters for OTP / login limits |
| `l4_allowlist` | service, ip, email, expires_at (mirrors nft set with timeout) |
| `health_events` / `health_minutely` | origin & tunnel state history |
| `access_minutely` | aggregated traffic metrics |
| `events` | WAF, auth, security events (7 d) |
| `audit` | admin actions (also in git) |
| `alert_state` | firing/resolved, dedup keys |
| `email_suppression` | SES bounces/complaints |
| `snapshots` | metadata index for Always Online snapshots |

Losing `state.db` logs everyone out and clears history — never loses configuration.

---

## 16. Security model

| Threat | Mitigation |
|---|---|
| Brute force of OTP / admin login | 6-digit default, 5 min TTL, attempt caps, per-email & per-IP limits, lockout, alerts |
| Email enumeration | Identical portal responses regardless of policy match |
| Open redirect via `rd` | `rd` must match a configured host of the target app |
| Header spoofing (`X-Edge-*`, `X-Forwarded-*`) | Always stripped/overwritten at the edge; origins verify signed JWT |
| Session theft / replay | HttpOnly+Secure cookies, PASETO encryption with per-app keys, network conditions re-checked on every request, revocation list polled by the edge |
| Compromised edge VM | Site firewall limits tunnel to published host:ports only; WG private keys of sites never on edge (connector); Origin CA root key encrypted; mTLS lets origins reject non-edge clients |
| Compromised origin | Cannot reach the node's control sockets, cannot push config |
| Compromised panel (managed nodes) | Snapshots and commands are signed with the org key the node pinned at enrolment; binaries are only installed when signed with the release key built into the node (`pkg/release/key.go`) |
| SSRF via health checks/crawler | Only configured origins; crawler same-host only |
| Secret leakage | age encryption, exports re-encrypted, config-only export option |
| Supply chain | Pinned plugin and action versions, `go mod verify`, `govulncheck` in CI, minisign-signed releases, container images signed with cosign and shipped with an SBOM and provenance (see [RELEASING.md](RELEASING.md)) |
| DDoS | Provider-level filtering (choose VM accordingly), nft meters, rate limits, PoW challenge, under-attack mode |

---

## 17. Deployment

### 17.1 Edge VM requirements
- 1–2 vCPU, 1–2 GB RAM (2 GB recommended with WAF + crawler), 20 GB disk.
- Debian 12/13 or Ubuntu 24.04 (kernel WireGuard + nftables).
- Public IPv4 (IPv6 optional). Provider with DDoS filtering and generous bandwidth if hosting game servers.

### 17.2 Install
```bash
curl -fsSL https://github.com/<you>/ingressd/releases/latest/download/install.sh | sudo bash
```
- Verifies signatures, installs binaries, creates `ingressd` user, systemd units, sysctl (`net.ipv4.ip_forward=1`, rp_filter loose on wg ifaces), base nftables (SSH, 80/443 tcp, 443 udp, WG ports), age key, git repo, prints one-time owner setup URL.
- Alternative: Docker Compose (host networking, `NET_ADMIN`, `/lib/modules` read-only) — supported but systemd is the reference deployment.

### 17.3 Ports
| Port | Proto | Purpose |
|---|---|---|
| 22 | tcp | SSH (restrict to your IPs / keys only) |
| 80 | tcp | HTTP → HTTPS redirect, ACME HTTP-01 |
| 443 | tcp/udp | HTTPS, HTTP/3, WS tunnel fallback |
| 51820+ | udp | WireGuard (one per tunnel) |
| per L4 service | tcp/udp | Game/TCP services |

### 17.4 Upgrades
- `ingressd upgrade` → download signed release → stop/start units (L7 blip of a few seconds; kernel L4 and WG unaffected) → automatic rollback if health checks fail post-upgrade.
- Config schema migrations versioned (`version:` field) with automatic, committed migrations.

---

## 18. Testing strategy

| Layer | Approach |
|---|---|
| Unit | Policy engine (table tests + fuzzing), OTP/rate logic, PKI issuance, YAML node editing (comment preservation), selection policy |
| Renderer | Golden files: `config.yaml` fixtures → expected Caddy JSON / nft ruleset / wg state |
| Caddy modules | `caddytest` harness for `edge_auth`, `edge_tiered`, `edge_challenge`, `edge_fallback` |
| Integration (Linux) | Network namespaces: edge ns + 2 site ns (one overlapping subnet) + origin ns; real WireGuard; tests for routing, netmap, failover, transparent L4, UDP echo game simulation |
| E2E | Docker Compose stack + Playwright: full login flow (SES mocked with a local fake), admin RBAC, site wizard, WAF block, snapshot fallback |
| WAF | `go-ftw` CRS regression suite |
| Load | k6 for L7 (target: 2k req/s on 2 vCPU with WAF PL1), iperf/UDP flood for L4 |
| Security | `govulncheck`, `gosec`, dependency review, periodic external scan of a staging edge |
| Manual hardware | UDM Pro checklist per release (import, routing, firewall, transparent mode) |

CI: GitHub Actions (lint, unit, renderer, caddytest, netns integration on a privileged runner, e2e, release build/sign).
