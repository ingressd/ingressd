#!/usr/bin/env bash
# e2e tunnel-http: a client on the "internet" reaches a LAN service
# through the edge proxy and a real WireGuard tunnel, using only the
# ingressd CLI to configure the edge and generate the site config.
set -euo pipefail
P=he-p1
source "$(dirname "$0")/lib.sh"

build_topology
lan_http 8080 "hello from lan"
start_edge_proxy

mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
tunnels:
  home:
    site: router
    vendor: unifi
    listen_port: 51820
    transit: 10.100.1.0/24
    # no subnets: the edge routes only the addresses apps point at
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    headers: { preset: strict }
  site:
    hosts: [example.test, www.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    redirects: [{ from: www.example.test, to: example.test }]
EOF

he init >/dev/null
expect "apply succeeds" "Applied." he apply --author e2e -m "First apply"
connect_site home
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true

CURL=(in_client curl -sS --max-time 3 -k --resolve web.example.test:443:198.51.100.1 --resolve www.example.test:443:198.51.100.1 --resolve web.example.test:80:198.51.100.1)
expect "HTTPS through tunnel reaches LAN service" "hello from lan" "${CURL[@]}" https://web.example.test/
expect "strict header preset applied" "strict-transport-security: max-age=31536000" "${CURL[@]}" -I https://web.example.test/
expect "Server header removed" "HTTP/2 200" "${CURL[@]}" -I https://web.example.test/
if "${CURL[@]}" -I https://web.example.test/ | grep -qi '^server:'; then fail "Server header still present"; else pass "no Server header"; fi
expect "www redirects to apex" "location: https://example.test/a?b=1" "${CURL[@]}" -I "https://www.example.test/a?b=1"
expect "HTTP redirects to HTTPS" "https://web.example.test/" "${CURL[@]}" -I http://web.example.test/

# Routes follow published apps: only 192.168.0.17 goes down the tunnel.
expect "published address routed through tunnel" "192.168.0.17 dev ix-home" in_edge ip route
if in_edge ip route | grep -q '192.168.0.0/24'; then fail "whole LAN routed without subnets"; else pass "LAN subnet not routed"; fi
reject "unpublished LAN address unreachable from edge" in_edge ping -c1 -W1 192.168.0.1
expect "peer AllowedIPs limited to published address" "allowed ips: 10.100.1.2/32, 192.168.0.17/32" in_edge wg show ix-home

# Managed firewall: a stray listener on the edge must not be reachable.
in_edge python3 -m http.server 9999 --bind 0.0.0.0 >/dev/null 2>&1 &
PIDS+=($!)
sleep 0.5
reject "firewall blocks unlisted port" in_client curl -s --max-time 2 http://198.51.100.1:9999/
expect "SSH port allowed by firewall" "tcp dport { 22, 80, 443 } accept" in_edge nft list table inet ingressd

expect "tunnel status reports up" "home    up" he tunnel status
expect "diff is empty after apply" "No changes." he diff
expect "re-apply is a no-op" "No changes to apply." he apply --author e2e

# Break the origin, then roll back via history.
GOOD=$(he history -n1 | awk '{print $1}')
sed -i 's/192.168.0.17:8080/192.168.0.17:9090/' "$TMP/conf/config.yaml"
expect "diff shows the change" '"dial": "192.168.0.17:9090"' he diff
expect "apply broken origin" "Applied." he apply --author e2e -m "Break origin"
expect "broken origin returns 502" "502" "${CURL[@]}" -o /dev/null -w '%{http_code}' https://web.example.test/
expect "history records both changes" "Break origin" he history
expect "rollback succeeds" "Applied." he rollback "$GOOD" --author e2e
expect "service restored after rollback" "hello from lan" "${CURL[@]}" https://web.example.test/

# Tunnel keepalive must survive re-applies (peer endpoint kept).
expect "peer endpoint retained" "endpoint: 172.16.1.2" in_edge wg show ix-home

# Publishing an app on a new address adds its route; the site needs no change.
ip -n "$LAN" addr add 192.168.0.18/24 dev eth0
mkdir -p "$TMP/www-18"
echo "hello from .18" >"$TMP/www-18/index.html"
in_lan python3 -m http.server 8081 --bind 192.168.0.18 --directory "$TMP/www-18" >/dev/null 2>&1 &
PIDS+=($!)
cat >>"$TMP/conf/config.yaml" <<'EOF'
  second:
    hosts: [second.example.test]
    origin: http://192.168.0.18:8081
    tunnel: home
EOF
expect "apply new app" "Applied." he apply --author e2e -m "Add second app"
expect "new address routed after apply" "192.168.0.18 dev ix-home" in_edge ip route
expect "new app reachable through tunnel" "hello from .18" in_client curl -sS --max-time 3 -k --resolve second.example.test:443:198.51.100.1 https://second.example.test/

# serve: forced apply at startup, control server behind the admin hostname,
# and re-apply when config.yaml changes.
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve force-applies at startup" "Applied." cat "$TMP/serve.log"
expect "admin hostname reaches control server" "ingressd edge node" in_client curl -sk --max-time 3 --resolve edge.example.test:443:198.51.100.1 https://edge.example.test/
sed -i 's/preset: strict/preset: basic/' "$TMP/conf/config.yaml"
expect "serve re-applies on file change" "Apply config.yaml change" he history -n1
reject "basic preset drops HSTS" bash -c "$(declare -f in_client); CLIENT=$CLIENT; in_client curl -skI --max-time 3 --resolve web.example.test:443:198.51.100.1 https://web.example.test/ | grep -qi strict-transport"

finish
