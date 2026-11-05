#!/usr/bin/env bash
# e2e connector-smartdns: Smart DNS on the connector
# (docs/rev1/CONNECTOR-SMARTDNS.md). A TV on the LAN asks the connector's
# resolver; the connector relays its streams through a node exit (leaving
# from the edge node's own IP) or, when that is down, through a VPN that
# terminates on the connector itself. A fake CDN answers DNS by the
# resolver's source address and reports who connected.
#
#   TV 192.168.0.17 ── site (connector, resolver on 192.168.0.1)
#                       ║ tunnel 10.100.1.0/24 ── edge node 198.51.100.1 ── cdn
#                       └ wan1 198.51.100.10 ── cdn ── vpn 198.51.100.14 (WireGuard "provider")
#   cdn: DNS 192.0.2.53; edge-resolved answer 192.0.2.20, VPN-resolved 192.0.2.30
#
# Checks: answers point at the connector, streams leave from the node's IP,
# the signed config is verified (tampered and replayed configs refused),
# losing the node exit fails over to the connector's VPN, and with every exit
# down service names fail closed.
#
# Needs bin/ingressd, bin/ingressd-edge, bin/ingressd-connector and
# bin/ingressd-sdtool (go build -o bin/ingressd-sdtool ./test/netns/sdtool).
set -euo pipefail
P=he-cs
source "$(dirname "$0")/lib.sh"
CDN=$P-cdn VPN=$P-vpn
NAMESPACES=("$EDGE" "$SITE" "$LAN" "$CDN" "$VPN")
SD=$BIN/ingressd-sdtool
[[ -x $SD ]] || { echo "missing $SD (go build -o bin/ingressd-sdtool ./test/netns/sdtool)" >&2; exit 1; }

in_cdn() { ip netns exec "$CDN" "$@"; }
in_vpn() { ip netns exec "$VPN" "$@"; }

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

TRACE=http://192.0.2.10/cdn-cgi/trace

# --- topology ---
ns_add "${NAMESPACES[@]}"
veth "$EDGE" pub0 198.51.100.1/30 "$CDN" e0 198.51.100.2/30
veth "$SITE" wan1 198.51.100.10/30 "$CDN" e2 198.51.100.9/30
veth "$VPN" pub0 198.51.100.14/30 "$CDN" e3 198.51.100.13/30
veth "$EDGE" wan0 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$SITE" lan0 192.168.0.1/24 "$LAN" eth0 192.168.0.17/24
ip -n "$EDGE" route add default via 198.51.100.2
ip -n "$SITE" route add default via 198.51.100.9
ip -n "$VPN" route add default via 198.51.100.13
ip -n "$LAN" route add default via 192.168.0.1
in_cdn sysctl -qw net.ipv4.ip_forward=1
for a in 192.0.2.53 192.0.2.10 192.0.2.20 192.0.2.30; do ip -n "$CDN" addr add $a/32 dev lo; done

# The WireGuard "VPN provider": the connector's VPN exit terminates here.
VPN_PRIV=$(wg genkey) CLIENT_PRIV=$(wg genkey)
VPN_PUB=$(echo "$VPN_PRIV" | wg pubkey) CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
echo "$VPN_PRIV" >"$TMP/vpn.key"
ip -n "$VPN" link add wg0 type wireguard
in_vpn wg set wg0 private-key "$TMP/vpn.key" listen-port 51820 peer "$CLIENT_PUB" allowed-ips 10.2.0.2/32
ip -n "$VPN" addr add 10.2.0.1/24 dev wg0
ip -n "$VPN" link set wg0 up
in_vpn sysctl -qw net.ipv4.ip_forward=1
in_vpn nft -f - <<'EOF'
table ip vpn_nat {
	chain post { type nat hook postrouting priority 100; oifname "pub0" masquerade; }
}
EOF
cat >"$TMP/vpn-nl.conf" <<EOF
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
"$SD" gencert "$TMP/certs" tv.stream.example stream.example >/dev/null
touch "$TMP/cdn-dns.log" "$TMP/cdn-http.log"
in_cdn "$SD" fakedns -listen 192.0.2.53:53 -nl-src 198.51.100.1 -nl 192.0.2.20 -uk 192.0.2.10 -ttl 2 \
	-by-src 198.51.100.14=192.0.2.30 >>"$TMP/cdn-dns.log" 2>&1 &
PIDS+=($!)
in_cdn "$SD" cdn -addrs 192.0.2.10,192.0.2.20,192.0.2.30 -countries 192.0.2.10=GB,192.0.2.20=NL,192.0.2.30=NL \
	-geo 198.51.100.1=NL,198.51.100.14=NL -certs "$TMP/certs" >>"$TMP/cdn-http.log" 2>&1 &
PIDS+=($!)
expect "fake CDN answers the edge's resolver" "NOERROR 192.0.2.20" in_edge "$SD" query 192.0.2.53:53 tv.stream.example A

# --- edge node ---
start_edge_proxy
mkdir -p "$TMP/conf"
# write_conf <smartdns config JSON or ""> <exit: yes|no>
write_conf() {
	local blob=$1 exit=$2
	{
		cat <<EOF
version: 1
edge:
  name: ams1
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
tunnels:
  cloud:
    site: connector
    listen_port: 51820
    transit: 10.100.1.0/24
EOF
		[[ -n $blob ]] && printf "    smartdns: '%s'\n" "$blob"
		if [[ $exit == yes ]]; then
			cat <<EOF
smartdns:
  exit: { country: NL, sites: [cloud], upstream: [192.0.2.53] }
EOF
		fi
	} >"$TMP/conf/config.yaml.new"
	mv "$TMP/conf/config.yaml.new" "$TMP/conf/config.yaml"
}
write_conf "" no
he init >/dev/null
expect "apply succeeds" "Applied." he apply --author e2e -m "First apply"
ip netns exec "$EDGE" env INGRESSD_SMARTDNS_TRACE_URL=$TRACE "$BIN/ingressd" --config-dir "$TMP/conf" --key "$TMP/keys/age.key" \
	--state-dir "$TMP/state" --run-dir "$TMP/run" serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve applies at startup" "Applied." cat "$TMP/serve.log"
ROOT_CA=$TMP/state/caddy/pki/authorities/local/root.crt
wait_for "edge internal CA exists" "BEGIN CERTIFICATE" 20 cat "$ROOT_CA"

# --- connector ---
STATE=$TMP/conn/connector.json
conn() { in_site "$BIN/ingressd-connector" --state "$STATE" "$@"; }
sdstatus() { conn smartdns status 2>&1 | tr -s " 	" " "; }
JOIN=$(he tunnel enroll-token cloud --join --ca "$ROOT_CA" 2>/dev/null)
expect "connector enrolls" "Enrolled tunnel \"cloud\"" conn enroll "$JOIN" --edge-addr 172.16.1.1 --mode tun
ip netns exec "$SITE" env INGRESSD_SMARTDNS_TRACE_URL=$TRACE INGRESSD_SMARTDNS_PROBE_ADDR=192.0.2.10:443 \
	"$BIN/ingressd-connector" --state "$STATE" run --udp-timeout 5s >"$TMP/conn.log" 2>&1 &
PIDS+=($!)
wait_for "connector up over UDP" "Transport: udp" 20 bash -c "ip netns exec $SITE $BIN/ingressd-connector --state $STATE status"
wait_for "connector created its age key" "age_identity" 20 cat "$STATE"
wait_for "edge learns the connector's age recipient" "age1" 60 cat "$TMP/state/connector.json"
wait_for "connector learns the edge's node name" '"node": "ams1"' 60 cat "$STATE"

CONN_KEY=$("$SD" connkey "$STATE")
SEED=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
OTHER_SEED=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
VPN_SEALED=$("$SD" seal "$STATE" "$TMP/vpn-nl.conf")
# site_json <exits JSON list>
site_json() {
	python3 - "$1" "$VPN_SEALED" <<'EOF'
import json, sys
print(json.dumps({
    "listen": "192.168.0.1",
    "failback_after": "0s",
    "services": {"tv": {"domains": ["stream.example"], "exits": json.loads(sys.argv[1])}},
    "exits": {
        "nl-node": {"at": "node", "node": "ams1", "country": "NL"},
        "nl-vpn": {"at": "connector", "country": "NL", "vpn": sys.argv[2]},
    },
}))
EOF
}
signed() { # signed <seed> <issued> <exits JSON list>
	site_json "$3" | "$SD" sign -seed "$1" -connector "$CONN_KEY" -issued "$2"
}
T1=2026-11-05T12:00:00Z T2=2026-11-05T12:01:00Z T0=2026-11-05T11:00:00Z
BLOB1=$(signed "$SEED" $T1 '["nl-node", "nl-vpn"]')

write_conf "$BLOB1" yes
wait_for "node renders the exit API rule" "tcp dport { 51901, 51902 } accept" 30 in_edge nft list ruleset
wait_for "connector applies the signed config" "smart DNS config applied" 60 cat "$TMP/conn.log"
wait_for "connector pins the org key on first use" "pinned the org key" 10 cat "$TMP/conn.log"
wait_for "resolver listens on the LAN address" "listening on 192.168.0.1" 20 sdstatus
wait_for "node exit is up" "nl-node node ams1 true" 30 sdstatus
wait_for "VPN exit is up" "nl-vpn VPN on this connector true" 60 sdstatus

# --- routing through the node exit ---
wait_for "service names resolve to the connector" "NOERROR 192.168.0.1" 20 in_lan "$SD" query 192.168.0.1:53 tv.stream.example A
expect "AAAA for service names is suppressed" "NOERROR " in_lan "$SD" query 192.168.0.1:53 tv.stream.example AAAA
expect "names no service routes are refused" "REFUSED" in_lan "$SD" query 192.168.0.1:53 other.example A
CURL=(in_lan curl -sk --max-time 8)
wait_for "HTTPS leaves from the node's own IP" "edge=192.0.2.20 src=198.51.100.1" 20 \
	"${CURL[@]}" --resolve tv.stream.example:443:192.168.0.1 https://tv.stream.example/
expect "HTTP leaves from the node's own IP" "edge=192.0.2.20 src=198.51.100.1" \
	"${CURL[@]}" --resolve tv.stream.example:80:192.168.0.1 http://tv.stream.example/
expect "the edge resolved the name at its location" "198.51.100.1 tv.stream.example." cat "$TMP/cdn-dns.log"
reject "the relay refuses names of no service" "${CURL[@]}" --fail --resolve other.example:80:192.168.0.1 http://other.example/
wait_for "relay usage reaches the edge" '"service": "tv"' 60 cat "$TMP/state/connector.json"

# --- the signed config cannot be changed or replayed by an edge ---
TAMPERED=${BLOB1/stream.example/bank.example}
write_conf "$TAMPERED" yes
wait_for "tampered config refused" "bad org signature" 60 cat "$TMP/state/connector.json"
expect "the config in effect stays" "edge=192.0.2.20 src=198.51.100.1" \
	"${CURL[@]}" --resolve tv.stream.example:443:192.168.0.1 https://tv.stream.example/
write_conf "$(signed "$OTHER_SEED" $T2 '["nl-node", "nl-vpn"]')" yes
wait_for "config from another org key refused" "another org key" 60 cat "$TMP/state/connector.json"
write_conf "$(signed "$SEED" $T0 '["nl-node", "nl-vpn"]')" yes
wait_for "replayed older config refused" "older than the one in effect" 60 cat "$TMP/state/connector.json"
write_conf "$BLOB1" yes
wait_for "the current config clears the error" "cleared" 60 bash -c "grep -q 'older than the one in effect' $TMP/state/connector.json || echo cleared"

# --- failover: the node exit goes away, the connector's VPN takes over ---
write_conf "$BLOB1" no
wait_for "node exit reported down" "nl-node node ams1 false" 60 sdstatus
wait_for "streams fail over to the connector's VPN" "edge=192.0.2.30 src=198.51.100.14" 30 \
	"${CURL[@]}" --resolve tv.stream.example:443:192.168.0.1 https://tv.stream.example/
wait_for "the service reports the failover" "tv nl-node,nl-vpn nl-vpn" 20 sdstatus
expect "the VPN resolved the name at its location" "198.51.100.14 tv.stream.example." cat "$TMP/cdn-dns.log"

# --- fail closed: with every exit down nothing is relayed elsewhere ---
ip -n "$VPN" link del wg0
wait_for "VPN exit reported down" "nl-vpn VPN on this connector false" 150 sdstatus
wait_for "service names get SERVFAIL" "SERVFAIL" 30 in_lan "$SD" query 192.168.0.1:53 tv.stream.example A
reject "nothing is relayed with every exit down" "${CURL[@]}" --fail --resolve tv.stream.example:443:192.168.0.1 https://tv.stream.example/

# --- Smart DNS off ---
write_conf "" yes
wait_for "connector stops Smart DNS without a config" "turned off" 60 cat "$TMP/conn.log"

if [[ $FAIL -ne 0 ]]; then
	for f in serve conn cdn-dns cdn-http; do echo "--- $f.log (tail) ---"; tail -40 "$TMP/$f.log" 2>/dev/null || true; done
	echo "--- connector smartdns status ---"; sdstatus || true
fi
finish
