# Spike 03 — Overlapping site subnets

## Question
Two sites both use `192.168.0.0/24`. Can the edge reach `192.168.0.17` at *each* site unambiguously?

## Approach
Each tunnel gets a virtual prefix (`home` → `10.201.0.0/24`, `office` → `10.202.0.0/24`). For traffic the edge itself generates (Caddy, health checks):

1. **Main table** has a route for each virtual prefix via its tunnel, so sockets can connect and pick the tunnel's transit address as source.
2. **nftables `route` output chain** sets a per-tunnel fwmark based on the virtual destination.
3. **nftables `nat` output chain** prefix-DNATs the virtual prefix to the real subnet, keeping the host part.
4. **`ip rule fwmark N table N`** routes the rewritten packet using a per-tunnel table that holds the real subnet → tunnel route.
5. Replies come back on the right WireGuard interface; conntrack reverses the DNAT. Reverse-path filtering must be off/loose on the edge.

The user still writes real LAN IPs in `config.yaml` (`tunnel: office, address: http://192.168.0.17`); the renderer converts them to virtual addresses.

## Run
```bash
sudo ./test/netns/netmap-spike.sh      # or: make spike-netmap
```
This builds the whole topology in network namespaces with real WireGuard, and checks that `10.201.0.17` answers "site-a", `10.202.0.17` answers "site-b", and that `192.168.0.17` itself is not routable from the edge. It also runs in CI (`netmap-spike` job).

## If `dnat ip prefix to … map` is not supported
Older nftables may reject the prefix-map syntax. The fallback is per-origin DNAT rules, which the renderer can generate anyway because it knows every origin address:
```
ip daddr 10.202.0.17 dnat to 192.168.0.17
```
Record the minimum nftables version that worked.

## Open follow-ups
- Inbound L4 forwarding to an overlapping site (prerouting instead of output chains).
- IPv6 site subnets.

## Result
✅ **Passed** on 2026-11-02, kernel 6.18.33.2-microsoft-standard-WSL2, nftables v1.1.6:
```
PASS http://10.201.0.17:8080/ -> site-a
PASS http://10.202.0.17:8080/ -> site-b
PASS 192.168.0.17 is not routable from the edge (expected)
```
- `dnat ip prefix to ip daddr map { … }` works as written, so the per-origin DNAT fallback isn't needed on nftables 1.1.x. A minimum version hasn't been established; the CI run on ubuntu-latest will add a second data point.
- The renderer needs to produce, per remapped tunnel: a main-table route for the virtual prefix, a per-tunnel routing table with the real subnet, an `ip rule fwmark`, and entries in the mark and prefix-DNAT maps.
- The edge must run with `rp_filter` 0 (or loose) on WireGuard interfaces.
