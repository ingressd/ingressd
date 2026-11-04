# Spike 04 — FiveM behind the edge

## Question
Which forwarding mode and server settings let friends join a FiveM server at home through the edge, show up correctly in the server list, and keep their real IPs visible to the server (bans, anti-cheat, txAdmin)?

## Background
- FiveM needs **TCP and UDP 30120** (or whatever `endpoint_add_tcp` / `endpoint_add_udp` use).
- FiveM does not speak PROXY protocol, so **proxy mode (SNAT)** makes every player appear to come from the edge.
- **Transparent mode** (DNAT only) keeps real IPs, but the game host's replies must return through the tunnel. That depends on spike 02 (UniFi policy-based routing).
- FiveM has server settings for running behind a proxy (for example, overriding the address shown in the server list and forcing indirect listing). **The exact names must be checked against the current Cfx.re documentation**; candidates to look up: `sv_listingHostOverride`, `sv_listingIpOverride`, `sv_forceIndirectListing`, `sv_proxyIPRanges`, `sv_endpoints`.

## Setup
1. Game host at home (ideally its own VM/VLAN), e.g. `192.168.0.40`.
2. Test edge VM from spike 02 with the tunnel up.
3. Proxy mode on the VM:
   ```bash
   sudo nft add table ip nat
   sudo nft add chain ip nat prerouting '{ type nat hook prerouting priority -100; }'
   sudo nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; }'
   sudo nft add rule ip nat prerouting tcp dport 30120 dnat to 192.168.0.40:30120
   sudo nft add rule ip nat prerouting udp dport 30120 dnat to 192.168.0.40:30120
   sudo nft add rule ip nat postrouting oifname "wg-home" masquerade
   ```
4. Transparent mode: same, **without** the masquerade rule, plus the UniFi policy route for `192.168.0.40` from spike 02.

## Checks

| # | Test | Proxy mode | Transparent mode |
|---|---|---|---|
| 1 | Direct connect (`connect <edge-ip>:30120` in F8 console) works | | |
| 2 | Server appears in the server list with the edge address | | |
| 3 | Player IP shown in txAdmin / `GetPlayerEndpoint` | (expect edge IP) | (expect real IP) |
| 4 | Ping added vs. playing at home directly (ms) | | |
| 5 | 30-minute session with 2+ players, no drops | | |
| 6 | Resource downloads speed acceptable (large assets go over the tunnel) | | |

## Record
- Server settings that were needed (exact names and values) → become the panel's generated snippet.
- Which mode is the default for the `fivem` preset.
- Confirm txAdmin (40120) works as an HTTP app behind Access instead of a raw port.

## Result
_Pending._
