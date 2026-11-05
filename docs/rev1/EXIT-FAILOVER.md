# Exit failover for exit routing

Status: implemented (node); the panel part (§8) is not. Extends [ARCHITECTURE.md §7](ARCHITECTURE.md#7-exit-routing-smartdns-in-rev1).

> **Moving to the connector (2026-11-05).** The failover rules here (ordered exits, stickiness, `failback_after`, fail closed, retry only before the first client byte) are kept, but are evaluated by the connector, and exits are reached over the connector's tunnel instead of the mesh. §5.4 (several home nodes) and §9 (managed network) no longer apply. See [CONNECTOR-SMARTDNS.md](CONNECTOR-SMARTDNS.md).

## 1. Problem

A service routes through exactly one exit (`smartdns.services.<name>.exit` is a single name), and an exit egresses on exactly one node. When that node is unreachable over the mesh, or its VPN has had no handshake for 3 minutes, every name of the service gets SERVFAIL until someone edits the config.

The home side already survives a node loss: a connector with sibling tunnels reaches several nodes, each node answers service names with its own transit IP, and the router can forward to all of them. The exit side is the remaining single point of failure.

## 2. Goals and non-goals

Goals:

- A service lists several exits in order of preference; new connections use the first healthy one.
- Fail closed is kept: no exit is used whose country differs from the service's, and with every exit down the service still gets SERVFAIL.
- Failover is fast (seconds) and needs neither the panel nor a config change.
- A flapping preferred exit does not make the service's egress IP bounce: streaming services tie sessions to an IP.
- Older nodes keep working with a newer panel, and the other way round.

Non-goals:

- Moving open TCP streams between exits. A stream that was relayed through a failed exit breaks, and the client reconnects through the next one.
- One VPN key on several nodes at once (active/standby key moving). Providers see one peer jumping between two source IPs and the tunnel flaps. Each exit keeps its own key; the panel already refuses a second exit with the same interface public key (`smartdns_exits_vpn_public_key`).
- Load balancing across exits. The order is a preference, not a weight.

## 3. Why this fits the current design

- Clients never see an exit address. A service name always resolves to the home node's own transit IP (`resolver.go`, `answer`), and the relay picks the exit when a connection arrives (`relay.go`, `handleRelay`). Switching exits needs no DNS change on the client: the next connection simply goes elsewhere.
- The answer cache is already keyed per exit (`cacheKey{exit, name}`), so an answer resolved at one exit's location is never served for another.
- Health signals already exist: `egress.up()` for self exits (VPN handshake age), `mesh.Up(node)` (probe every 5 s), `remoteDown` (exit node said its exit is down, held 15 s) and the 10-minute trace and edge location checks.

## 4. Config contract (`pkg/config`)

```yaml
smartdns:
  services:
    bbc:
      domains: [bbc.co.uk, bbci.co.uk]
      exits: [gb-lon, gb-ams]      # new: ordered, first healthy wins
  exits:
    gb-lon: { node: node-lon-1, country: GB, vpn: secret://vpn-gb-lon }
    gb-ams: { node: node-ams-1, country: GB, vpn: secret://vpn-gb-ams }
  failback_after: 5m               # new, optional
```

- `SmartDNSService.Exits []string` is added. `Exit string` stays and means `exits: [<exit>]`. Setting both is a validation error (`smartdns.services.<name>: set exit or exits, not both`). `applySmartDNSDefaults` moves `exit` into `exits` (and clears `exit`) so the runtime only ever reads the list; `SmartDNSService.ExitList()` gives the same list for a config built in code without loading.
- Validation of `exits`: 1 to 4 entries, no duplicates, every entry a known exit, and **every exit's `country` equal** (`smartdns.services.<name>.exits[i]: country DE differs from GB of exits[0]`). The shared country is what keeps fail closed meaningful. Errors name `exits` or `exits[i]` even when the config used `exit` (`smartdns.services.<name>.exits[0]: unknown exit "de"`).
- `SmartDNS.FailbackAfter` (duration, default 5m, 0 = fail back as soon as the preferred exit is healthy, max 1h).
- Two exits on the same node are allowed (they protect against a VPN failing, not the node), and the panel warns about it (§8).

## 5. Node behaviour (`internal/smartdns`)

### 5.1 Route and active exit

`route` becomes `{Service string; Exits []string}`. Each service gets a small piece of runtime state:

```go
type activeExit struct {
	mu      sync.Mutex
	current string    // exit in use now
	since   time.Time // when current was chosen
	healthy map[string]time.Time // exit -> healthy since (zero = not healthy)
}
```

`pick(st, route) (exit string, err error)`:

1. If `current` is still up and an exit earlier in the list has been healthy for at least `failback_after`, switch to that earlier exit (failback).
2. Else if `current` is up, keep it (stickiness).
3. Else take the first exit in list order that is up and switch to it (failover), logging `service bbc: exit gb-lon down (<reason>), using gb-ams`.
4. If no exit is up, return `errExitDown` with every exit's reason joined. Fail closed as today.

"Up" is today's `exitUp` plus the refusal tracking in §5.3. The state survives reconfigures while the service's exit list is unchanged, like `probeState` does for traces.

Besides every lookup, `pick` runs for every service on the manager's 2 s status tick, so health changes are seen (and "healthy since" resets on a flap) while a service has no traffic, and the status stays current. When every exit is down the service has no active exit; the first exit to come back is then used at once (there is nothing to stick to).

### 5.2 Resolver and relay

- `lookup` takes the exit chosen by `pick` instead of `r.Exit`, and returns it, so the relay resolves and connects through **the same exit** (addresses are location specific).
- `handleRelay` retries on the next exit when connecting fails **before any client byte was sent upstream** (the peeked hello is written only after `openUpstream` succeeds, so a retry is safe): a mesh transport failure, or a refusal that says the exit is down (§5.3). A refusal for any other reason (`checkConnect`, unknown host) is not retried. At most one attempt per exit, within the existing `queryTimeout + dialTimeout*2` budget.
- The resolver path does the same for `resolveAtExit`: a transport failure or `exit_up:false` marks that exit down and moves to the next one, within `queryTimeout`.
- Stale-while-revalidate is unchanged and per exit: a stale answer is served only for the exit that is active and up.

### 5.3 Knowing a remote exit is down before a client hits it

Today a home node learns that a remote exit's VPN is down only when a resolve says `exit_up:false`. With a fresh cached answer it hands that answer out and the relay then fails. Two changes:

- **Exit health on the mesh API**: `GET /v1/exits` on exit nodes answers `{"exits":{"gb-lon":{"up":true},"gb-ams":{"up":false,"error":"no recent handshake"}}}` for the exits the node hosts. Home nodes poll it every 5 s, alongside the mesh probe, for remote exits that appear in a service's list, and feed `remoteDown` (held 15 s, so each poll renews it; the exit node's reason is kept for the status). An exit missing from the answer is treated as down (the exit node does not host it, e.g. before its config is applied). Nodes the mesh probe holds down are not polled. Polling stops for exits no service uses.
- **Typed refusal**: `ConnectResponse` gains `ExitDown bool` (JSON `exit_down`, additive). `handleExitRelay` sets it when `dialOrdered` fails with `errExitDown`, so the home node can tell "exit down, try the next" apart from "this request is not allowed". Older exit nodes leave it false, which means no retry, the same as today. On a self exit the same rule applies: a dial that fails with `errExitDown` is retried on the next exit, any other dial failure is not.

Detection time with these: a node that disappears is down after `downAfter` failed probes (5 s apart); a VPN that loses its handshake is down after the 3-minute handshake window (unchanged; making that window shorter is a separate decision, since providers can be idle for minutes) or sooner when a dial through it fails.

### 5.4 Several home nodes

Each home node runs `pick` on its own, from the same health signals, so siblings usually agree. They can briefly disagree while a failure is being detected, in which case connections arriving at different home nodes leave through different exits of the same country. That is accepted: it is bounded by the probe interval, and sharing state between siblings would add a dependency the failover is meant to avoid.

## 6. Status and usage (`pkg/nodeproto`)

- New `ServiceStatus` `{name, exits []string, active string, failover bool, since time.Time, message string}`, reported as `Status.SmartDNSServices` (JSON `smartdns_services`, additive) through a new `ServiceReporter` node agent hook, and as `services` in the node's status file (`ingressd smartdns status`). `failover` is true when `active` is not `exits[0]`; `active` is empty while every exit is down; `message` says why `exits[0]` is not in use (its down reason, or the time left before failback) or, with every exit down, every exit's reason.
- Relay usage per service is unchanged. The per-exit breakdown of the relay counters is not implemented yet: it changes the `ServiceUsage` deltas the panel ingests, so it lands together with the panel's Usage page change. The recent lookups already record which exit answered.
- New capability `CapabilitySmartDNSFailover = "smartdns-failover"` (next to `CapabilitySmartDNSChecks`).

## 7. Compatibility

| Panel | Node | Result |
|---|---|---|
| new | new (has capability) | compiles `exits`; full failover |
| new | old (no capability) | compiles `exit: <first exit>`, as `smartDNS()` already gates `checks`; no failover, same as today |
| old | new | panel sends `exit`; node normalises it to a one-element list; behaviour unchanged |

Mixed home and exit nodes: `GET /v1/exits` answers 404 on old exit nodes; the home node then falls back to today's signals for that node (mesh probe plus `exit_up` on resolve).

## 8. Panel (`ingressd-panel`)

- **Schema** (migration `0015`): `smartdns_service_exits (service_id, exit_id, position, PRIMARY KEY (service_id, exit_id))`, filled from `smartdns_services.exit_id` at position 0. `exit_id` stays for one release, kept in step with position 0, then is dropped.
- **API**: `ServiceWrite.exits: [exit id, ...]` (ordered, 1 to 4); `exit` is accepted as a deprecated alias for `exits: [exit]`. Deleting an exit that is some service's only exit stays `RESTRICT`; deleting one of several removes it from the lists.
- **Validation** in the panel, before compile: same country for every exit (hard error); exits on the same node (warning: "protects against the VPN failing, not the node"); exits that use the same VPN provider endpoint (warning: one provider outage takes both down).
- **Compiler** (`builder.smartDNS`): writes `exits` when the node has `smartdns-failover`, otherwise `exit: exits[0]`; adds every listed exit to `sd.Exits` so home nodes know where each one lives.
- **UI**: the service editor gets an ordered exit picker ("Primary", "Fallback 1", ...); the service card shows "via gb-ams (failover since 14:02)" from `ServiceStatus`; the exits page shows which services use each exit and at what position.

## 9. Managed network note

Failover is what makes VPN exits usable when nodes sit in several regions: a VPN exit needs to live on one or two nodes, not on every node, and every other node reaches it over the mesh. Placing two exits of a service on nodes in different PoPs gives node and region resilience with two provider configs (two devices on the user's VPN account), whatever the number of nodes.

Hosting tenants' VPN exits on shared nodes needs stable per-exit routing tables: realm VPN exits must set `table` (1900–1999, allocated by the panel), so tables never shift as tenants come and go (see ARCHITECTURE.md §11, per-realm Smart DNS). The exit API carries the realm (`realm` in resolve and relay requests, `?realm=` on `GET /v1/exits`) and exit nodes refuse exits of any other realm.

## 10. Tests

- Unit (`internal/smartdns`, with the existing fake `exitClient`): order and failover, stickiness, failback after `failback_after`, a flapping primary that never stays healthy long enough to fail back, all exits down gives SERVFAIL, retry on `ExitDown` but not on other refusals, no retry after bytes were sent, cache entries never crossing exits.
- Config (`pkg/config`): `exit`/`exits` exclusivity, country mismatch, duplicates, list length, normalisation.
- Panel: migration backfill, compiler output with and without the capability, validation errors and warnings.
- netns e2e: `test/netns/smartdns-exit-failover-e2e.sh` (a new suite rather than an extension of `smartdns-vpn-exits`, which tests one node): a home node and two exit nodes, each with a simulated provider. It takes down provider A (by deleting exit node A's VPN interface, which its exit health reports at once; a silently dead provider is only seen after the 3-minute handshake window) and checks that new connections leave through B within seconds and only ever through the two listed exits, that a mixed-country list is rejected, that A coming back keeps B until `failback_after` and then fails back, and that killing node B's mesh link while A is down gives SERVFAIL with nothing leaked.

## 11. Open questions

- Should the 3-minute handshake window be shorter for exits that are some service's primary? A handshake-independent check (a periodic dial through the tunnel) would detect a dead provider within seconds, at the cost of a little traffic per exit.
- Should failover be gated by plan? The plans so far limit only the management plane, so this draft assumes no.
- Is 4 exits per service the right cap?
