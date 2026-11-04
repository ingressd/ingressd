# Spike 02 — UDM Pro native WireGuard

## Question
Can the UDM Pro's built-in WireGuard VPN client act as an ingressd site, without custom scripts that firmware updates would wipe? Specifically:

1. Does importing a generated config work, and does the tunnel stay up?
2. Can the edge reach LAN hosts, and can the zone firewall restrict it to specific `host:port` pairs?
3. With `AllowedIPs = 0.0.0.0/0`, does UniFi route *all* traffic through the tunnel, or only what policy-based routes send there?
4. Can a policy-based route send one device's (or VLAN's) traffic through the tunnel, so transparent L4 mode works (real client IPs)?
5. What MTU works end to end?
6. Does it survive a UDM reboot and a firmware update?

## Setup

**Test edge VM** (any cheap Debian/Ubuntu VM with a public IP):
```bash
sudo apt-get install -y wireguard-tools nftables
umask 077
wg genkey | tee edge.key | wg pubkey > edge.pub
wg genkey | tee site.key | wg pubkey > site.pub
```

`/etc/wireguard/wg-home.conf` on the VM:
```ini
[Interface]
Address = 10.100.1.1/24
ListenPort = 51820
PrivateKey = <contents of edge.key>

[Peer]
PublicKey = <contents of site.pub>
AllowedIPs = 10.100.1.2/32, 192.168.0.0/24
```
```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo wg-quick up wg-home
```

**Config to import on the UDM** (`ingressd-home.conf`), first variant:
```ini
[Interface]
Address = 10.100.1.2/24
PrivateKey = <contents of site.key>
MTU = 1420

[Peer]
PublicKey = <contents of edge.pub>
Endpoint = <vm public ip>:51820
AllowedIPs = 10.100.1.0/24
PersistentKeepalive = 25
```

UniFi Network → Settings → VPN → VPN Client → Create New → WireGuard → upload the file. (Record the exact menu path for the current UniFi OS version.)

## Checks

| # | Test | Command / action | Expected | Result |
|---|---|---|---|---|
| 1 | Tunnel up | `sudo wg show` on VM | Recent handshake | |
| 2 | Edge → LAN | `curl http://192.168.0.17:<port>` on VM | Response from LAN host | |
| 3 | Firewall restrict | Add a zone rule allowing only 192.168.0.17:<port> from the VPN | Other hosts/ports time out | |
| 4 | Default route behaviour | Re-import with `AllowedIPs = 0.0.0.0/0`; from a LAN client run `curl ifconfig.me` | Note: VM IP (all traffic tunnelled) or home IP (policy routes needed) | |
| 5 | Policy route | Policy-based route: one test device → VPN client; `curl ifconfig.me` from it | VM IP for that device only | |
| 6 | Transparent DNAT | On VM: `nft add rule ip nat prerouting tcp dport 8080 dnat to 192.168.0.17:8080` (no masquerade); connect from a phone on 4G; check the server's access log | Phone's real public IP is logged | |
| 7 | MTU | From VM: `ping -M do -s 1372 192.168.0.17`, step down until it passes | Largest working size | |
| 8 | Reboot | Reboot UDM | Tunnel back within 1 min without changes | |
| 9 | Firmware | After the next UniFi update | Config intact | |

## Result
_Pending._ Record: UniFi OS and Network versions, which variant (3 or 4) is needed for transparent mode, the exact UI steps (for the site wizard guide), and any limits found.
