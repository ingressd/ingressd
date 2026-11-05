#!/usr/bin/env bash
# e2e realms: two tenants share one edge. Both sites are connectors with the
# same LAN (192.168.1.0/24) and an origin at the same address
# (192.168.1.10:5000) behind apps of the same base name. The connectors enrol
# under the realms config itself (machine endpoints on the public IPv4,
# internal CA pinned, as managed nodes do). Each hostname reaches only its
# own origin, each realm signs in on its own portal with its own keys, a
# site reaches nothing on the edge through its tunnel but its control port,
# and the proxy's user cannot connect to cloud metadata.
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
in_site_b() { ip netns exec "$SITEB" "$@"; }

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

# The merged realms config, as a panel writes it: no admin hostname.
mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  acme: { ca: internal }
security: { tunnel_input: restricted }
realms:
  tq7k2m:
    access: { portal_url: https://auth.realm-a.test/a/tq7k2m, session_key: secret://tq7k2m_session, jwt_key: secret://tq7k2m_jwt }
    shape: { rate_mbit: 50 }
  tb4x9p:
    access: { portal_url: https://auth.realm-b.test/a/tb4x9p, session_key: secret://tb4x9p_session, jwt_key: secret://tb4x9p_jwt }
tunnels:
  tq7k2m01: { realm: tq7k2m, site: connector, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24, table: 1201 }
  tb4x9p01: { realm: tb4x9p, site: connector, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24, table: 1202 }
policies:
  tq7k2m.alice: { realm: tq7k2m, action: allow, include: [{ email: alice@example.com }] }
  tb4x9p.alice: { realm: tb4x9p, action: allow, include: [{ email: alice@example.com }] }
apps:
  tq7k2m.nas: { realm: tq7k2m, hosts: [nas.alice.test], tunnel: tq7k2m01, origin: http://192.168.1.10:5000 }
  tb4x9p.nas: { realm: tb4x9p, hosts: [nas.bob.test], tunnel: tb4x9p01, origin: http://192.168.1.10:5000 }
  tq7k2m.vault: { realm: tq7k2m, hosts: [vault.alice.test], tunnel: tq7k2m01, origin: http://192.168.1.10:5000, access: [tq7k2m.alice] }
  tb4x9p.vault: { realm: tb4x9p, hosts: [vault.bob.test], tunnel: tb4x9p01, origin: http://192.168.1.10:5000, access: [tb4x9p.alice] }
EOF
he init >/dev/null
read -r A_SESSION A_JWT < <("$BIN/realmtool" keys)
read -r B_SESSION B_JWT < <("$BIN/realmtool" keys)
for kv in "tq7k2m_session=$A_SESSION" "tq7k2m_jwt=$A_JWT" "tb4x9p_session=$B_SESSION" "tb4x9p_jwt=$B_JWT"; do
	he secret set "${kv%%=*}" --value "${kv#*=}"
done
expect "apply realms config" "Applied." he apply --author e2e -m "Realms"
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve applies at startup" "Applied." cat "$TMP/serve.log"

# Connectors enrol through the public IPv4 with the internal CA pinned (site
# A reaches it over its WAN, not its tunnel).
ROOT_CA=$TMP/state/caddy/pki/authorities/local/root.crt
wait_for "edge internal CA exists" "BEGIN CERTIFICATE" 20 cat "$ROOT_CA"
expect "machine host serves only the landing text" "ingressd edge node" in_site curl -sS --max-time 3 --cacert "$ROOT_CA" https://172.16.1.1/
expect "machine host serves no other pages" "404" in_site curl -s -o /dev/null -w '%{http_code}' --max-time 3 --cacert "$ROOT_CA" https://172.16.1.1/login
start_conn() { # start_conn <ns> <tunnel>
	local ns=$1 tunnel=$2 state=$TMP/conn-$2/connector.json join
	join=$(he tunnel enroll-token "$tunnel" --join --ca "$ROOT_CA" 2>/dev/null)
	expect "connector of $tunnel enrols under the realms config" "Enrolled tunnel \"$tunnel\"" \
		ip netns exec "$ns" "$BIN/ingressd-connector" --state "$state" enroll "$join" --mode tun
	ip netns exec "$ns" "$BIN/ingressd-connector" --state "$state" run --udp-timeout 5s >"$TMP/conn-$tunnel.log" 2>&1 &
	PIDS+=($!)
	wait_for "connector of $tunnel up" "Transport: udp" 20 bash -c "ip netns exec $ns $BIN/ingressd-connector --state $state status | tr -s ' \t' ' '"
}
start_conn "$SITE" tq7k2m01
start_conn "$SITEB" tb4x9p01

curl_host() { in_client curl -sS --max-time 3 -k --resolve "$1:443:198.51.100.1" "https://$1/"; }
expect "tenant A's hostname reaches tenant A's origin" "hello from tenant A" curl_host nas.alice.test
expect "tenant B's hostname reaches tenant B's origin" "hello from tenant B" curl_host nas.bob.test
for _ in 1 2 3; do
	[[ $(curl_host nas.alice.test 2>&1) == *"tenant B"* ]] && fail "tenant A's hostname reached tenant B"
	[[ $(curl_host nas.bob.test 2>&1) == *"tenant A"* ]] && fail "tenant B's hostname reached tenant A"
done

# Access: each realm signs in on its own portal, with its own keys.
hdrs() { # hdrs <host> <path> [curl args...]
	local host=$1 path=$2
	shift 2
	in_client curl -sS -o /dev/null -D - --max-time 3 -k --resolve "$host:443:198.51.100.1" "$@" "https://$host$path"
}
expect "realm A app sends visitors to realm A's portal" "location: https://auth.realm-a.test/a/tq7k2m/login?" hdrs vault.alice.test /
expect "realm B app sends visitors to realm B's portal" "location: https://auth.realm-b.test/a/tb4x9p/login?" hdrs vault.bob.test /
CODE=$("$BIN/realmtool" seal "$A_SESSION" "$A_JWT" tq7k2m.vault https://vault.alice.test/ alice@example.com)
COOKIE=$(hdrs vault.alice.test "/.ingressd/callback?code=$CODE" | sed -n 's/^set-cookie: __edge_tq7k2m\.vault=\([^;]*\).*/\1/Ip' | tr -d '\r')
[[ -n $COOKIE ]] && pass "realm A callback sets the app cookie" || fail "realm A callback sets the app cookie"
expect "realm A cookie opens realm A's app" "hello from tenant A" in_client curl -sS --max-time 3 -k --resolve vault.alice.test:443:198.51.100.1 -b "__edge_tq7k2m.vault=$COOKIE" https://vault.alice.test/
expect "realm A cookie rejected by realm B's app" "location: https://auth.realm-b.test/" hdrs vault.bob.test / -b "__edge_tb4x9p.vault=$COOKIE"
CROSS=$("$BIN/realmtool" seal "$A_SESSION" "$A_JWT" tb4x9p.vault https://vault.bob.test/ alice@example.com)
expect "realm A code rejected at realm B's callback" "HTTP/2 403" hdrs vault.bob.test "/.ingressd/callback?code=$CROSS"

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

wait_for "connector A polls the control channel" "Control channel: ok" 40 bash -c "ip netns exec $SITE $BIN/ingressd-connector --state $TMP/conn-tq7k2m01/connector.json status | tr -s ' \t' ' '"
wait_for "connector B polls the control channel" "Control channel: ok" 40 bash -c "ip netns exec $SITEB $BIN/ingressd-connector --state $TMP/conn-tb4x9p01/connector.json status | tr -s ' \t' ' '"

if [[ $FAIL -ne 0 ]]; then
	for f in serve conn-tq7k2m01 conn-tb4x9p01; do echo "--- $f.log (tail) ---"; tail -40 "$TMP/$f.log" 2>/dev/null || true; done
	in_edge nft list ruleset 2>/dev/null | head -80 || true
fi
finish
