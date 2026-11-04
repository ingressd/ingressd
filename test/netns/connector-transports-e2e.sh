#!/usr/bin/env bash
# e2e connector-transports: ingressd-connector on the site enrolls with a one-time
# token and links the site to the edge; the app is reachable through it over
# UDP, over WebSocket when the site's UDP is blocked (and back to UDP when it
# is unblocked), and in netstack mode as an unprivileged user without kernel
# WireGuard.
set -euo pipefail
P=he-p5
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
  cloud:
    site: connector
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
    fallback_ws: true
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: cloud
EOF

he init >/dev/null
expect "apply succeeds" "Applied." he apply --author e2e -m "First apply"
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve applies at startup" "Applied." cat "$TMP/serve.log"
expect "admin host reaches control server" "ingressd edge node" in_client curl -sk --max-time 3 --resolve edge.example.test:443:198.51.100.1 https://edge.example.test/

CURL=(in_client curl -sS --max-time 3 -k --resolve web.example.test:443:198.51.100.1)
STATE=$TMP/conn/connector.json
conn() { in_site "$BIN/ingressd-connector" --state "$STATE" "$@"; }
cstatus() { conn status | tr -s " 	" " "; }
# start_conn <log> <run flags...>: runs the connector in the site namespace.
start_conn() {
	local log=$1
	shift
	ip netns exec "$SITE" "$BIN/ingressd-connector" --state "$STATE" run "$@" >"$log" 2>&1 &
	CONN_PID=$!
	PIDS+=($CONN_PID)
}
ENROLL_FLAGS=(--edge-addr 172.16.1.1 --insecure)

reject "unknown tunnel refuses enroll token" he tunnel enroll-token nosuch
TOKEN=$(he tunnel enroll-token cloud 2>/dev/null)
[[ -n $TOKEN ]] && pass "enroll token created" || fail "enroll token created"
reject "bad token is rejected" conn enroll https://edge.example.test not-a-token "${ENROLL_FLAGS[@]}"
expect "connector enrolls (tun mode)" "Enrolled tunnel \"cloud\"" conn enroll https://edge.example.test "$TOKEN" "${ENROLL_FLAGS[@]}" --mode tun
expect "state file is private" "600" stat -c %a "$STATE"
if grep -q "$TOKEN" "$TMP/state/connector.json"; then fail "edge stores token in plaintext"; else pass "edge stores only token hashes"; fi
reject "token is single use" in_site "$BIN/ingressd-connector" --state "$TMP/conn-reuse/c.json" enroll https://edge.example.test "$TOKEN" "${ENROLL_FLAGS[@]}"
expect "edge peer uses the enrolled key" "$(sed -n 's/.*"public_key": "\(.*\)".*/\1/p' "$TMP/state/connector.json")" in_edge wg show ix-cloud peers

start_conn "$TMP/conn-tun.log" --udp-timeout 5s --udp-retry 15s
wait_for "connector up over UDP" "Transport: udp" 20 cstatus
expect "kernel WireGuard interface on the site" "ingressd0" in_site wg show interfaces
expect "HTTPS through the connector reaches LAN service" "hello from lan" "${CURL[@]}" https://web.example.test/
wait_for "edge shows connector health" "tun/udp" 20 he tunnel status
wait_for "control channel polls" "Control channel: ok" 40 cstatus
he doctor >"$TMP/doctor.txt" 2>&1 || true
if grep -q "cloud connector" "$TMP/doctor.txt"; then fail "doctor warns about the connector: $(grep "cloud connector" "$TMP/doctor.txt")"; else pass "doctor reports a healthy connector"; fi

# Block UDP on the site's WAN: a fresh connector falls back to WebSocket.
in_site nft -f - <<'EOF'
table inet p5block {
	chain out {
		type filter hook output priority filter; policy accept;
		oifname "wan0" udp dport 51820 drop
	}
}
EOF
kill "$CONN_PID"; wait "$CONN_PID" 2>/dev/null || true
start_conn "$TMP/conn-ws.log" --udp-timeout 5s --udp-retry 15s
wait_for "connector falls back to WebSocket" "Transport: websocket" 40 cstatus
expect "WebSocket MTU is 1280" "MTU: 1280" cstatus
expect "HTTPS through the WebSocket tunnel" "hello from lan" "${CURL[@]}" https://web.example.test/
wait_for "edge shows WebSocket transport" "tun/websocket" 40 he tunnel status
expect "edge peer endpoint is the loopback bridge" "endpoint: 127.0.0.1" in_edge wg show ix-cloud

# Unblock: the periodic UDP retry moves back to UDP.
in_site nft delete table inet p5block
wait_for "connector returns to UDP" "Transport: udp" 60 cstatus
expect "HTTPS after returning to UDP" "hello from lan" "${CURL[@]}" https://web.example.test/
kill "$CONN_PID"; wait "$CONN_PID" 2>/dev/null || true
reject "TUN interface removed on exit" in_site ip link show ingressd0

# Netstack mode: unprivileged, no kernel WireGuard on the site.
NS=$TMP/ns
mkdir -p "$NS"
chown 65534:65534 "$NS"
nsconn() { ip netns exec "$SITE" setpriv --reuid=65534 --regid=65534 --clear-groups -- "$BIN/ingressd-connector" --state "$NS/connector.json" "$@"; }
nsstatus() { nsconn status | tr -s " 	" " "; }
TOKEN=$(he tunnel enroll-token cloud 2>/dev/null)
expect "connector enrolls (netstack mode, as nobody)" "netstack mode" nsconn enroll https://edge.example.test "$TOKEN" "${ENROLL_FLAGS[@]}" --mode netstack
ip netns exec "$SITE" setpriv --reuid=65534 --regid=65534 --clear-groups -- "$BIN/ingressd-connector" --state "$NS/connector.json" run --udp-timeout 5s >"$TMP/conn-ns.log" 2>&1 &
PIDS+=($!)
wait_for "netstack connector up over UDP" "Transport: udp" 20 nsstatus
reject "no WireGuard interface on the site" bash -c "ip -n $SITE -d link show type wireguard | grep -q ."
expect "HTTPS through the netstack connector" "hello from lan" "${CURL[@]}" https://web.example.test/
wait_for "edge shows netstack health" "netstack/udp" 40 he tunnel status

if [[ $FAIL -ne 0 ]]; then
	for f in serve conn-tun conn-ws conn-ns; do echo "--- $f.log (tail) ---"; tail -40 "$TMP/$f.log" 2>/dev/null || true; done
fi
finish
