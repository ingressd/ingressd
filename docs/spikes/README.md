# Engineering spikes

Short experiments that answer one design question each, with the method and (where measured) the result. They are engineering notes, not user documentation; the design they informed is in [../DESIGN.md](../DESIGN.md).

| # | Spike | Question | Runs where | Finding |
|---|---|---|---|---|
| 01 | [Caddy plugin build](01-caddy-plugin-build.md) | Do all required plugins compile together, at which versions? | CI / any Linux | Caddy v2.11.7 + all plugins, no conflicts, 63 MB binary |
| 02 | [UDM Pro WireGuard](02-udm-wireguard.md) | Does UniFi's native WireGuard client support the routing model, including transparent mode? | UDM Pro + a test VM | Method documented; not yet recorded |
| 03 | [Overlapping subnets (netmap)](03-netmap.md) | Can the edge route to two identical LANs via virtual prefixes? | CI (netns) / any Linux | Virtual prefix + fwmark + nft prefix-DNAT map works (nftables 1.1.6) |
| 04 | [FiveM behind the edge](04-fivem.md) | Which FiveM settings work behind proxy/transparent forwarding, and do players' real IPs survive? | Test VM + game host | Method documented; not yet recorded |
| 05 | [Coraza performance](05-coraza-perf.md) | What does CRS cost on a small VM? | Target VM | Method documented; not yet measured |
