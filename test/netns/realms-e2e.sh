#!/usr/bin/env bash
# e2e realms: two tenants share one edge. Both sites are connectors with the
# same LAN (192.168.1.0/24) and an origin at the same address
# (192.168.1.10:5000) behind an app of the same name; with realms and
# restricted tunnel input each hostname reaches only its own origin, a site
# reaches nothing on the edge through its tunnel but its control port, and
# the proxy's user cannot connect to cloud metadata.
#
#   client 198.51.100.2 ─ 198.51.100.1 edge 172.16.1.1 ─ 172.16.1.2 site A ─ lan A 192.168.1.10
#                                       172.16.2.1 ─ 172.16.2.2 site B ─ lan B 192.168.1.10
set -euo pipefail
P=he-rl
source "$(dirname "$0")/lib.sh"

# wait_for <description> <want-substring> <seconds> <command...>
wait_for() {
	local desc=$1 want=$2 secs=$3 got=""
	shift 3
	for _ in $(seq $((secs * 2))); do
		got=$("$@" 2>&1 || true)
		[[ $got == *"$want"* ]] && { pass "$desc"; return; }
		sleep 0.5
	done
	fail "$desc: want '$want', got: ${got:0:600}"
}

SITEB=$P-siteb LANB=$P-lanb
ns_add "$EDGE" "$CLIENT" "$SITE" "$LAN" "$SITEB" "$LANB"
veth "$CLIENT" eth0 198.51.100.2/30 "$EDGE" pub0 198.51.100.1/30
veth "$EDGE" wana 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$EDGE" wanb 172.16.2.1/30 "$SITEB" wan0 172.16.2.2/30
veth "$SITE" lan0 192.168.1.1/24 "$LAN" eth0 192.168.1.10/24
veth "$SITEB" lan0 192.168.1.1/24 "$LANB" eth0 192.168.1.10/24
for ns in "$SITE" "$SITEB"; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1; done
ip -n "$SITE" route add default via 172.16.1.1
ip -n "$SITEB" route add default via 172.16.2.1
ip -n "$LAN" route add default via 192.168.1.1
ip -n "$LANB" route add default via 192.168.1.1

serve_lan() { # serve_lan <ns> <body>
	local dir=$TMP/www-$1
	mkdir -p "$dir"
	echo "$2" >"$dir/index.html"
	ip netns exec "$1" python3 -m http.server 5000 --bind 192.168.1.10 --directory "$dir" >/dev/null 2>&1 &
	PIDS+=($!)
}
serve_lan "$LAN" "hello from tenant A"
serve_lan "$LANB" "hello from tenant B"
start_edge_proxy

# Phase 1: the connectors enrol through the admin hostname (a single-tenant
# config); realms refuse edge.admin, so the realms config comes after.
mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
tunnels:
  tq7k2m01: { site: connector, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24, table: 1201 }
  tb4x9p01: { site: connector, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24, table: 1202 }
EOF
he init >/dev/null
expect "apply single-tenant config" "Applied." he apply --author e2e -m "Enrolment"
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve applies at startup" "Applied." cat "$TMP/serve.log"

# start_conn <ns> <tunnel> <edge address>: enrols and runs a connector.
start_conn() {
	local ns=$1 tunnel=$2 addr=$3 state=$TMP/conn-$2/connector.json token
	token=$(he tunnel enroll-token "$tunnel" 2>/dev/null)
	expect "connector of $tunnel enrols" "Enrolled tunnel \"$tunnel\"" \
		ip netns exec "$ns" "$BIN/ingressd-connector" --state "$state" enroll https://edge.example.test "$token" --edge-addr "$addr" --insecure --mode tun
	ip netns exec "$ns" "$BIN/ingressd-connector" --state "$state" run --udp-timeout 5s >"$TMP/conn-$tunnel.log" 2>&1 &
	PIDS+=($!)
	wait_for "connector of $tunnel up" "Transport: udp" 20 bash -c "ip netns exec $ns $BIN/ingressd-connector --state $state status | tr -s ' \t' ' '"
}
start_conn "$SITE" tq7k2m01 172.16.1.1
start_conn "$SITEB" tb4x9p01 172.16.2.1

# Open tunnel input (the default): the proxy answers through a tunnel.
reject "open input: proxy reachable through the tunnel" bash -c "[[ \$(ip netns exec $SITE curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://10.100.1.1/) == 000 ]]"

# Phase 2: the merged realms config, as a panel would write it.
cat >"$TMP/conf/config.yaml.new" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  acme: { ca: internal }
security: { tunnel_input: restricted }
realms:
  tq7k2m: { shape: { rate_mbit: 50 } }
  tb4x9p: {}
tunnels:
  tq7k2m01: { realm: tq7k2m, site: connector, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24, table: 1201 }
  tb4x9p01: { realm: tb4x9p, site: connector, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24, table: 1202 }
apps:
  tq7k2m.nas: { realm: tq7k2m, hosts: [nas.alice.test], tunnel: tq7k2m01, origin: http://192.168.1.10:5000 }
  tb4x9p.nas: { realm: tb4x9p, hosts: [nas.bob.test], tunnel: tb4x9p01, origin: http://192.168.1.10:5000 }
EOF
mv "$TMP/conf/config.yaml.new" "$TMP/conf/config.yaml"
expect "serve applies the realms config" "Apply config.yaml change" he history -n1
expect "edge reports no pending changes" "No changes." he diff

curl_host() { in_client curl -sS --max-time 3 -k --resolve "$1:443:198.51.100.1" "https://$1/"; }
expect "tenant A's hostname reaches tenant A's origin" "hello from tenant A" curl_host nas.alice.test
expect "tenant B's hostname reaches tenant B's origin" "hello from tenant B" curl_host nas.bob.test
for _ in 1 2 3; do
	[[ $(curl_host nas.alice.test 2>&1) == *"tenant B"* ]] && fail "tenant A's hostname reached tenant B"
	[[ $(curl_host nas.bob.test 2>&1) == *"tenant A"* ]] && fail "tenant B's hostname reached tenant A"
done

# Routing: virtual prefixes in the main table, each real LAN only in its
# tunnel's own (explicit) table.
expect "virtual prefix A routed to tunnel A" "10.0.4.0/24 dev ix-tq7k2m01" in_edge ip route show table main
expect "virtual prefix B routed to tunnel B" "10.0.5.0/24 dev ix-tb4x9p01" in_edge ip route show table main
if in_edge ip route show table main | grep -q '192.168.1.0/24'; then fail "real LAN subnet in the main table"; else pass "real LAN subnet not in the main table"; fi
expect "table 1201 routes the LAN to tunnel A" "192.168.1.0/24 dev ix-tq7k2m01" in_edge ip route show table 1201
expect "table 1202 routes the LAN to tunnel B" "192.168.1.0/24 dev ix-tb4x9p01" in_edge ip route show table 1202
expect "stable rule for table 1201" "10201:" in_edge ip rule show
expect "stable rule for table 1202" "10202:" in_edge ip rule show

# Restricted tunnel input: through its tunnel a site reaches its control
# port only. Port 22 gets a listener so "dropped" is not "nothing there".
in_edge python3 -m http.server 22 --bind 0.0.0.0 >/dev/null 2>&1 &
PIDS+=($!)
expect "SSH port open from the internet" "200" in_client curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://198.51.100.1:22/
code() { "$@" -s -o /dev/null -w '%{http_code}' --max-time 2 2>/dev/null || true; }
in_site_b() { ip netns exec "$SITEB" "$@"; }
expect "restricted: proxy :80 dropped through tunnel A" "000" code in_site curl http://10.100.1.1/
expect "restricted: proxy :443 dropped through tunnel A" "000" code in_site curl -k --resolve nas.bob.test:443:10.100.1.1 https://nas.bob.test/
expect "restricted: SSH port dropped through tunnel A" "000" code in_site curl http://10.100.1.1:22/
expect "restricted: proxy :443 dropped through tunnel B" "000" code in_site_b curl -k --resolve nas.alice.test:443:10.100.2.1 https://nas.alice.test/
reject "restricted: control port answers through tunnel A" bash -c "[[ \$(ip netns exec $SITE curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://10.100.1.1:51819/) == 000 ]]"
expect "nft drops other tunnel input" "tunnel drop rule" bash -c "ip netns exec $EDGE nft list chain inet ingressd input | grep -q 'iifname {.*ix-tq7k2m01.*} drop' && echo 'tunnel drop rule'"
# Tenant A's LAN cannot reach tenant B's virtual addresses either: the edge
# does not forward.
reject "tenant A cannot reach tenant B's virtual origin" in_lan curl -s --max-time 2 http://10.0.5.10:5000/

# Output denylist: the proxy's user cannot reach metadata; root can.
in_edge ip addr add 169.254.169.254/32 dev lo
in_edge python3 -m http.server 80 --bind 169.254.169.254 --directory "$TMP" >/dev/null 2>&1 &
PIDS+=($!)
# A dropped SYN fails the connect with EPERM or (retransmits) a timeout.
probe='import socket
s=socket.socket(); s.settimeout(2)
try: s.connect(("169.254.169.254", 80)); print("connected")
except (PermissionError, TimeoutError): print("blocked")
except OSError as e: print("errno", e.errno)'
expect "root reaches the metadata address" "connected" in_edge python3 -c "$probe"
expect "unprivileged user refused by the output denylist" "blocked" in_edge setpriv --reuid=65534 --regid=65534 --clear-groups python3 -c "$probe"

wait_for "connector A still polls the control channel" "Control channel: ok" 40 bash -c "ip netns exec $SITE $BIN/ingressd-connector --state $TMP/conn-tq7k2m01/connector.json status | tr -s ' \t' ' '"

if [[ $FAIL -ne 0 ]]; then
	for f in serve conn-tq7k2m01 conn-tb4x9p01; do echo "--- $f.log (tail) ---"; tail -40 "$TMP/$f.log" 2>/dev/null || true; done
	in_edge nft list ruleset 2>/dev/null | head -80 || true
fi
finish
