#!/usr/bin/env bash
# e2e smartdns: a home node (with a site tunnel to a "home"
# router and a TV behind it) and an exit node in "NL", joined by the node
# mesh. A fake CDN answers DNS by the querying resolver's address (NL vs UK
# edges) and reports which source address connected to it.
#
#   TV 192.168.0.17 ── site ══ wg tunnel ══ home node (edge) ── cdn ── exit node (nl)
#                       │ 198.51.100.10        198.51.100.1     │        198.51.100.6
#                       └──────────── direct internet ──────────┘
#   cdn: DNS 192.0.2.53, UK edge 192.0.2.10, NL edges 192.0.2.21 (geolocates
#   the NL exit as GB: bad) and 192.0.2.20 (NL: good)
#   mesh: home 10.255.0.1, nl 10.255.0.2 (ix-mesh, UDP 51900)
#
# Needs bin/ingressd, bin/ingressd-edge and bin/ingressd-sdtool
# (go build -o bin/ingressd-sdtool ./test/netns/sdtool).
set -euo pipefail
P=he-sd
source "$(dirname "$0")/lib.sh"
NL=$P-nl CDN=$P-cdn VPN=$P-vpn
NAMESPACES=("$EDGE" "$SITE" "$LAN" "$NL" "$CDN" "$VPN")
SD=$BIN/ingressd-sdtool
[[ -x $SD ]] || { echo "missing $SD (go build -o bin/ingressd-sdtool ./test/netns/sdtool)" >&2; exit 1; }

in_nl() { ip netns exec "$NL" "$@"; }
in_cdn() { ip netns exec "$CDN" "$@"; }
node() { # node <ns> <dir> <args...>
	local ns=$1 dir=$2
	shift 2
	ip netns exec "$ns" env SSL_CERT_FILE="$TMP/certs/ca.pem" "$BIN/ingressd" --config-dir "$dir/conf" --key "$dir/keys/age.key" \
		--state-dir "$dir/state" --run-dir "$dir/run" "$@"
}
he_home() { node "$EDGE" "$TMP/home" "$@"; }
he_nl() { node "$NL" "$TMP/nl" "$@"; }

start_proxy() { # start_proxy <ns> <dir>
	mkdir -p "$2/run" "$2/state" "$2/xdg" "$2/conf"
	echo "{\"admin\": {\"listen\": \"unix/$2/run/caddy-admin.sock\"}}" >"$2/bootstrap.json"
	XDG_DATA_HOME=$2/xdg XDG_CONFIG_HOME=$2/xdg ip netns exec "$1" "$BIN/ingressd-edge" run --config "$2/bootstrap.json" >"$2/caddy.log" 2>&1 &
	PIDS+=($!)
	for _ in $(seq 50); do [[ -S $2/run/caddy-admin.sock ]] && return; sleep 0.1; done
	echo "ingressd-edge did not start in $1" >&2
	cat "$2/caddy.log" >&2
	exit 1
}

# --- topology ---
ns_add "${NAMESPACES[@]}"
veth "$EDGE" pub0 198.51.100.1/30 "$CDN" e0 198.51.100.2/30
veth "$NL" pub0 198.51.100.6/30 "$CDN" e1 198.51.100.5/30
veth "$SITE" wan1 198.51.100.10/30 "$CDN" e2 198.51.100.9/30
veth "$VPN" pub0 198.51.100.14/30 "$CDN" e3 198.51.100.13/30
veth "$EDGE" wan0 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$SITE" lan0 192.168.0.1/24 "$LAN" eth0 192.168.0.17/24
ip -n "$EDGE" route add default via 198.51.100.2
ip -n "$NL" route add default via 198.51.100.5
ip -n "$SITE" route add default via 198.51.100.9
ip -n "$VPN" route add default via 198.51.100.13
ip -n "$LAN" route add default via 192.168.0.1
in_site sysctl -qw net.ipv4.ip_forward=1
in_cdn sysctl -qw net.ipv4.ip_forward=1
for a in 192.0.2.53 192.0.2.10 192.0.2.20 192.0.2.21 192.0.2.30; do ip -n "$CDN" addr add $a/32 dev lo; done
# The home router masquerades the LAN onto the tunnel and its own uplink.
in_site nft -f - <<'EOF'
table ip site_nat {
	chain post { type nat hook postrouting priority 100; oifname { "wg0", "wan1" } masquerade; }
}
EOF

# A WireGuard "VPN provider" (a stand-in for Proton) in front of the CDN:
# the NL node egresses its "de" exit through it. Test keys only.
VPN_PRIV=$(wg genkey) CLIENT_PRIV=$(wg genkey)
VPN_PUB=$(echo "$VPN_PRIV" | wg pubkey) CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
echo "$VPN_PRIV" >"$TMP/vpn.key"
ip -n "$VPN" link add wg0 type wireguard
ip netns exec "$VPN" wg set wg0 private-key "$TMP/vpn.key" listen-port 51820 peer "$CLIENT_PUB" allowed-ips 10.2.0.2/32
ip -n "$VPN" addr add 10.2.0.1/24 dev wg0
ip -n "$VPN" link set wg0 up
ip netns exec "$VPN" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$VPN" nft -f - <<'EOF'
table ip vpn_nat {
	chain post { type nat hook postrouting priority 100; oifname "pub0" masquerade; }
}
EOF
cat >"$TMP/vpn-de.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.2.0.2/32
DNS = 192.0.2.53

[Peer]
PublicKey = $VPN_PUB
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.14:51820
EOF

# --- fake CDN ---
mkdir -p "$TMP/certs"
"$SD" gencert "$TMP/certs" stream.example '*.stream.example' streamtv.example '*.streamtv.example' watch-stream.example other.test '*.other.test' vpn.test '*.vpn.test'
touch "$TMP/cdn-dns.log" "$TMP/cdn-http.log"
in_cdn "$SD" fakedns -listen 192.0.2.53:53 -nl-src 198.51.100.6 -nl 192.0.2.21,192.0.2.20 -uk 192.0.2.10 -ttl 2 \
	-by-src 198.51.100.14=192.0.2.30 -fail-file "$TMP/fail-nl" >>"$TMP/cdn-dns.log" 2>&1 &
PIDS+=($!)
in_cdn "$SD" cdn -addrs 192.0.2.10,192.0.2.20,192.0.2.21,192.0.2.30 -countries 192.0.2.10=GB,192.0.2.20=NL,192.0.2.21=GB,192.0.2.30=DE \
	-certs "$TMP/certs" >>"$TMP/cdn-http.log" 2>&1 &
PIDS+=($!)
sleep 0.5
expect "fake CDN answers UK resolvers with UK edges" "NOERROR 192.0.2.10" in_edge "$SD" query 192.0.2.53:53 tv.stream.example A
expect "fake CDN answers NL resolvers with NL edges" "NOERROR 192.0.2.21,192.0.2.20" in_nl "$SD" query 192.0.2.53:53 tv.stream.example A

# --- nodes ---
start_proxy "$EDGE" "$TMP/home"
start_proxy "$NL" "$TMP/nl"
for n in home nl; do
	printf 'version: 1\nedge: { acme: { ca: internal } }\n' >"$TMP/$n/conf/config.yaml"
done
he_home init >/dev/null
he_nl init >/dev/null
HOME_KEY=$(he_home smartdns mesh-key)
NL_KEY=$(he_nl smartdns mesh-key)
[[ ${#HOME_KEY} -eq 44 && ${#NL_KEY} -eq 44 ]] && pass "mesh keys generated" || fail "mesh keys: '$HOME_KEY' '$NL_KEY'"

cat >"$TMP/home/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 198.51.100.1
  acme: { ca: internal }
tunnels:
  home: { site: router, vendor: unifi, listen_port: 51820, transit: 10.100.1.0/24 }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_nl: { public_key: "$NL_KEY", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32, name: nl }
smartdns:
  enabled: true
  upstream: [192.0.2.53]
  exits:
    nl: { node: nod_nl, country: NL }
    de: { node: nod_nl, country: DE }
  services:
    streamtv: { domains: [stream.example, streamtv.example, watch-stream.example], exit: nl, catalog: streamtv }
    vpnsvc: { domains: [vpn.test], exit: de }
  checks:
    - { domains: [stream.example, streamtv.example, watch-stream.example], host: tv.stream.example, path: /v1/location, field: countryCode, cache_buster: cb }
EOF
cat >"$TMP/nl/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 198.51.100.6
  acme: { ca: internal }
mesh:
  address: 10.255.0.2/16
  peers:
    nod_home: { public_key: "$HOME_KEY", endpoint: "198.51.100.1:51900", address: 10.255.0.1/32, name: home }
smartdns:
  enabled: false  # no homes here: this node only hosts the NL exit
  upstream: [192.0.2.53]
  exits:
    nl: { node: self, country: NL }
    de: { node: self, country: DE, vpn: "secret://vpn-de" }
  checks:
    - { domains: [stream.example, streamtv.example, watch-stream.example], host: tv.stream.example, path: /v1/location, field: countryCode, cache_buster: cb }
EOF
he_nl secret set vpn-de --from-file "$TMP/vpn-de.conf"
expect "home node applies" "Applied." he_home apply --author e2e -m "Smart DNS"
expect "exit node applies" "Applied." he_nl apply --author e2e -m "NL exit"

# Site router: import the generated tunnel config.
he_home tunnel config home --format wg --endpoint 172.16.1.1 >"$TMP/site-home.conf"
addr=$(he_home tunnel config home --endpoint 172.16.1.1 | sed -n 's/^Address = //p')
ip -n "$SITE" link add wg0 type wireguard
in_site wg setconf wg0 "$TMP/site-home.conf"
ip -n "$SITE" addr add "$addr" dev wg0
ip -n "$SITE" link set wg0 up

he_home serve --watch-interval 1s >"$TMP/home-serve.log" 2>&1 &
PIDS+=($!)
he_nl serve --watch-interval 1s >"$TMP/nl-serve.log" 2>&1 &
PIDS+=($!)

expect "home node serve started" "listening" cat "$TMP/home-serve.log"
expect "exit node serve started" "exit-relay" cat "$TMP/nl-serve.log"

# --- mesh ---
expect "mesh interface up on the home node" "ix-mesh" in_edge ip -br addr show ix-mesh
expect "mesh handshake" "latest handshake" in_edge wg show ix-mesh
expect "mesh ping over WireGuard" "bytes from 10.255.0.2" in_edge ping -c1 -W2 10.255.0.2
expect "firewall opens the mesh port" "51900" bash -c "ip netns exec $EDGE nft list table inet ingressd | grep 'udp dport'"
expect "mesh API restricted to peers" 'iifname "ix-mesh" ip saddr 10.255.0.2 tcp dport { 51901, 51902 } accept' in_edge nft list table inet ingressd
expect "mesh API answers peers" '"ok":true' in_edge curl -s --max-time 3 http://10.255.0.2:51901/v1/ping
reject "mesh API not reachable from the internet" in_cdn curl -s --max-time 2 http://198.51.100.6:51901/v1/ping
reject "resolver not reachable from the internet" in_cdn "$SD" query 198.51.100.1:53 tv.stream.example A
jq() { python3 -c "import json,sys; s=json.load(sys.stdin); print($1)"; }
home_status() { he_home smartdns status --json | jq "$1"; }
nl_status() { he_nl smartdns status --json | jq "$1"; }
expect "home node sees the exit node up" "True" home_status "s['mesh'][0]['up'] and all(x['up'] for x in s['remote_exits'])"
expect "mesh RTT measured" "rtt-ok" home_status "'rtt'+'-ok' if s['mesh'][0].get('rtt_ms', 0) > 0 else 'none'"

# --- resolver ---
TV=(in_lan "$SD" query 10.100.1.1:53)
: >"$TMP/cdn-dns.log"
expect "service name answered with the home node's transit IP" "NOERROR 10.100.1.1" "${TV[@]}" tv.stream.example A
expect "service name over TCP" "NOERROR 10.100.1.1" "${TV[@]}" watch-stream.example A tcp
expect "service name resolved at the exit (NL resolver asked)" "198.51.100.6 tv.stream.example." cat "$TMP/cdn-dns.log"
if grep -q "^198.51.100.1 tv.stream.example" "$TMP/cdn-dns.log"; then fail "service name resolved from the home node"; else pass "service name never resolved from the home node"; fi
expect "AAAA suppressed for service names" "NOERROR " "${TV[@]}" tv.stream.example AAAA
if [[ $("${TV[@]}" tv.stream.example AAAA) != "NOERROR " ]]; then fail "AAAA answer for a service name"; else pass "no AAAA records for service names"; fi
expect "HTTPS records suppressed" "NOERROR " "${TV[@]}" tv.stream.example HTTPS
expect "non-service names resolve normally (UK edge)" "NOERROR 192.0.2.10" "${TV[@]}" www.other.test A
expect "non-service AAAA passes through" "NOERROR 2001:db8::1" "${TV[@]}" www.other.test AAAA

# --- relay ---
TVCURL=(in_lan curl -sS --max-time 10 --cacert "$TMP/certs/ca.pem")
expect "relayed HTTPS reaches the CDN from the exit with the good NL edge" "edge=192.0.2.20 src=198.51.100.6 host=tv.stream.example" \
	"${TVCURL[@]}" --resolve tv.stream.example:443:10.100.1.1 https://tv.stream.example/
expect "relayed HTTP (Host header) egresses at the exit" "edge=192.0.2.20 src=198.51.100.6 host=watch-stream.example" \
	"${TVCURL[@]}" --resolve watch-stream.example:80:10.100.1.1 http://watch-stream.example/
expect "edge check found the bad edge" "192.0.2.21 bad GB" nl_status "' '.join(e['ip']+' '+e['verdict']+' '+e['seen'] for e in s['edges'])"
expect "exit status reports the NL country" "nl NL True" nl_status "' '.join(str(x) for e in s['exits'] for x in (e['name'], e['country'], e['up']))"
expect "exit status shows edge results" "192.0.2.21 sees GB" nl_status "[e['message'] for e in s['exits'] if e['name']=='nl']"
if grep -qE "edge=192.0.2.21 src=198.51.100.6 host=tv.stream.example path=/$" "$TMP/cdn-http.log"; then fail "relay used the bad edge"; else pass "relay avoided the bad edge"; fi
expect "non-service names go direct (home line)" "edge=192.0.2.10 src=198.51.100.10" "${TVCURL[@]}" --resolve www.other.test:443:192.0.2.10 https://www.other.test/
reject "relay refuses non-service hostnames" "${TVCURL[@]}" --resolve www.other.test:443:10.100.1.1 https://www.other.test/
reject "relay refuses connections from the internet" in_cdn curl -sk --max-time 3 --resolve tv.stream.example:443:198.51.100.1 https://tv.stream.example/
usage_bytes() {
	he_home smartdns status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); print(sum(u["bytes"] for u in s["usage"] if u["service"]=="streamtv"))' || echo 0
}
B1=$(usage_bytes)
"${TVCURL[@]}" --resolve tv.stream.example:443:10.100.1.1 https://tv.stream.example/more >/dev/null || true
sleep 2.5
B2=$(usage_bytes)
if [[ $B1 -gt 0 && $B2 -gt $B1 ]]; then pass "per-service byte counter increases ($B1 -> $B2)"; else fail "byte counter $B1 -> $B2"; fi
expect "recent lookups recorded" "tv.stream.example" he_home smartdns recent
expect "recent lookups show non-service names" "www.other.test" he_home smartdns recent

# --- VPN exit (kernel WireGuard, own table + fwmark, DNS through the tunnel) ---
expect "VPN interface up on the exit node" "ix-x-de" in_nl ip -br addr show ix-x-de
expect "VPN handshake" "latest handshake" in_nl wg show ix-x-de
expect "VPN fwmark rule" "fwmark 0x76c lookup 1900" in_nl ip rule
expect "VPN routing table" "dev ix-x-de" in_nl ip route show table 1900
expect "VPN exit up" "de True True" nl_status "' '.join(str(x) for e in s['exits'] if e['name']=='de' for x in (e['name'], e['up'], e['vpn']))"
: >"$TMP/cdn-dns.log"
expect "VPN service answered with the transit IP" "NOERROR 10.100.1.1" "${TV[@]}" www.vpn.test A
expect "VPN service resolved through the tunnel DNS" "198.51.100.14 www.vpn.test." cat "$TMP/cdn-dns.log"
expect "VPN service egresses through the VPN" "edge=192.0.2.30 src=198.51.100.14 host=www.vpn.test" "${TVCURL[@]}" --resolve www.vpn.test:443:10.100.1.1 https://www.vpn.test/
# Sockets are bound to the VPN interface: without the VPN routes they still
# leave through it (never by the main route), and with the interface down
# they fail.
in_nl ip route flush table 1900
expect "egress stays on the VPN without its routes" "src=198.51.100.14" "${TVCURL[@]}" --resolve www.vpn.test:443:10.100.1.1 https://www.vpn.test/x
: >"$TMP/cdn-http.log"
ip -n "$NL" link set ix-x-de down
reject "no egress with the VPN interface down" "${TVCURL[@]}" --max-time 15 --resolve www.vpn.test:443:10.100.1.1 https://www.vpn.test/
if grep -q "host=www.vpn.test" "$TMP/cdn-http.log"; then fail "VPN service traffic leaked: $(cat "$TMP/cdn-http.log")"; else pass "VPN service traffic never left by the node's own IP"; fi
expect "VPN routes restored by a forced apply" "Applied." he_nl apply --force --author e2e -m "Restore"
expect "VPN egress works again" "src=198.51.100.14" "${TVCURL[@]}" --resolve www.vpn.test:443:10.100.1.1 https://www.vpn.test/

# --- stale cache ---
# The cached answer expires after the 30 s floor; then the exit's DNS fails.
touch "$TMP/fail-nl"
expect "exit resolver now fails" "SERVFAIL" in_nl "$SD" query 192.0.2.53:53 tv.stream.example A
sleep 31
expect "stale answer served after the exit's DNS failed" "NOERROR 10.100.1.1" "${TV[@]}" tv.stream.example A
expect "lookup marked stale" "stale" he_home smartdns recent -n 3
expect "relay still works on the stale answer" "edge=192.0.2.20 src=198.51.100.6" "${TVCURL[@]}" --resolve tv.stream.example:443:10.100.1.1 https://tv.stream.example/
expect "uncached service name fails closed when the exit cannot resolve" "SERVFAIL" "${TV[@]}" api.stream.example A
rm -f "$TMP/fail-nl"

# --- exit node down ---
: >"$TMP/cdn-http.log"
ip -n "$NL" link set pub0 down
ok=0
for _ in $(seq 40); do
	if [[ $("${TV[@]}" tv.stream.example A 2>&1) == SERVFAIL* ]]; then ok=1; break; fi
	sleep 0.5
done
[[ $ok -eq 1 ]] && pass "service names fail closed (SERVFAIL) with the exit node down" || fail "no SERVFAIL with the exit node down"
expect "uncached service names fail closed too" "SERVFAIL" "${TV[@]}" id.stream.example A
expect "non-service names still resolve" "NOERROR 192.0.2.10" "${TV[@]}" www.other.test A
reject "no relayed connection with the exit node down" "${TVCURL[@]}" --resolve tv.stream.example:443:10.100.1.1 https://tv.stream.example/
sleep 1
if grep -q "host=tv.stream.example" "$TMP/cdn-http.log"; then fail "service traffic leaked: $(cat "$TMP/cdn-http.log")"; else pass "nothing leaked direct while the exit was down"; fi
expect "home node reports the exit down" "False" home_status "any(x['up'] for x in s['remote_exits'])"
ip -n "$NL" link set pub0 up
ip -n "$NL" route add default via 198.51.100.5 2>/dev/null || true
ok=0
for _ in $(seq 60); do
	if [[ $("${TV[@]}" tv.stream.example A 2>&1) == "NOERROR 10.100.1.1" ]]; then ok=1; break; fi
	sleep 0.5
done
[[ $ok -eq 1 ]] && pass "service names recover when the exit node returns" || fail "no recovery after the exit node returned"

if [[ $FAIL -ne 0 ]]; then
	echo "--- home serve log (tail) ---"; tail -40 "$TMP/home-serve.log"
	echo "--- nl serve log (tail) ---"; tail -40 "$TMP/nl-serve.log"
	echo "--- cdn dns log (tail) ---"; tail -20 "$TMP/cdn-dns.log"
	echo "--- cdn http log ---"; tail -20 "$TMP/cdn-http.log"
	in_edge wg show 2>/dev/null || true
	in_edge nft list ruleset 2>/dev/null | head -80 || true
fi
exit "$FAIL"
