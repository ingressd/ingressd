#!/usr/bin/env bash
# e2e multi-edge: one site connector, two edge nodes.
# The connector enrols on edge A only; edge B accepts it by the configured
# public_key. When A's config gains B as a sibling, the connector adds B as
# a second WireGuard peer (learned, no enrolment) and the app is reachable
# through both edges. With A cut off, B keeps serving and the connector
# still refreshes its config from B over the tunnel.
#
#   client 198.51.100.2 ── 198.51.100.1 edge A 172.16.1.1 ── 172.16.1.2 ┐
#          198.51.100.6 ── 198.51.100.5 edge B 172.16.2.1 ── 172.16.2.2 ┴ site ── lan 192.168.0.17
set -euo pipefail
P=he-me
source "$(dirname "$0")/lib.sh"

EDGE_B=$P-edgeb
NAMESPACES+=("$EDGE_B")
in_edge_b() { ip netns exec "$EDGE_B" "$@"; }

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

# --- Topology ----------------------------------------------------------------
build_topology # client, edge (A), site, lan
ns_add "$EDGE_B"
veth "$CLIENT" eth1 198.51.100.6/30 "$EDGE_B" pub0 198.51.100.5/30
veth "$EDGE_B" wan0 172.16.2.1/30 "$SITE" wanb 172.16.2.2/30
# The site resolves the edges' hostnames (ip netns exec bind-mounts this;
# lib.sh cleanup removes it).
mkdir -p "/etc/netns/$SITE"
printf '172.16.1.1 edge-a.example.test\n172.16.2.1 edge-b.example.test\n' >"/etc/netns/$SITE/hosts"

lan_http 8080 "hello from lan"
lan_http 8123 "second app"

# --- Edges -----------------------------------------------------------------
# edge_env <A|B>: sets NS and D (namespace and data directory) for an edge.
edge_env() {
	if [[ $1 == A ]]; then NS=$EDGE D=$TMP/a; else NS=$EDGE_B D=$TMP/b; fi
}
# hx <A|B> <args...>: the control plane CLI of an edge.
hx() {
	local NS D
	edge_env "$1"
	shift
	ip netns exec "$NS" "$BIN/ingressd" --config-dir "$D/conf" --key "$D/keys/age.key" \
		--state-dir "$D/state" --run-dir "$D/run" "$@"
}
start_edge() {
	local NS D
	edge_env "$1"
	mkdir -p "$D/run" "$D/state" "$D/xdg" "$D/conf"
	echo "{\"admin\": {\"listen\": \"unix/$D/run/caddy-admin.sock\"}}" >"$D/bootstrap.json"
	XDG_DATA_HOME=$D/xdg XDG_CONFIG_HOME=$D/xdg ip netns exec "$NS" "$BIN/ingressd-edge" run --config "$D/bootstrap.json" >"$D/caddy.log" 2>&1 &
	PIDS+=($!)
	for _ in $(seq 50); do [[ -S $D/run/caddy-admin.sock ]] && break; sleep 0.1; done
}
start_serve() {
	local NS D
	edge_env "$1"
	ip netns exec "$NS" "$BIN/ingressd" --config-dir "$D/conf" --key "$D/keys/age.key" \
		--state-dir "$D/state" --run-dir "$D/run" serve --watch-interval 1s >>"$D/serve.log" 2>&1 &
	PIDS+=($!)
	eval "SERVE_$1=$!"
}

# edge_config <host> <public ip> <listen port> <transit> [extra tunnel yaml] [extra apps yaml]
edge_config() {
	cat <<EOF
version: 1
edge:
  public_ipv4: $2
  admin: { hostname: $1 }
  acme: { ca: internal }
tunnels:
  cloud:
    site: connector
    listen_port: $3
    transit: $4
    subnets: [192.168.0.0/24]
    fallback_ws: true
${5-}
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: cloud
${6-}
EOF
}

start_edge A
start_edge B
edge_config edge-a.example.test 172.16.1.1 51820 100.64.0.0/30 >"$TMP/a/conf/config.yaml"
edge_config edge-b.example.test 172.16.2.1 51821 100.64.0.4/30 >"$TMP/b/conf/config.yaml"
for e in A B; do
	hx $e init >/dev/null
	expect "edge $e: apply succeeds" "Applied." hx $e apply --author e2e -m "First apply"
	start_serve $e
done
expect "edge A serves" "Applied." cat "$TMP/a/serve.log"
expect "edge B serves" "Applied." cat "$TMP/b/serve.log"
# wait_applied <A|B> <n> <description>: waits for the n-th successful apply.
wait_applied() {
	local NS D
	edge_env "$1"
	for _ in $(seq 60); do
		[[ $(grep -c "Applied\." "$D/serve.log" || true) -ge $2 ]] && { pass "$3"; return; }
		sleep 0.5
	done
	fail "$3: $(grep -c "Applied\." "$D/serve.log" || true) applies; $(tail -5 "$D/serve.log")"
}
edge_key() { hx "$1" tunnel config cloud --endpoint 127.0.0.1 | sed -n 's/^PublicKey = //p'; }
KEY_A=$(edge_key A)
KEY_B=$(edge_key B)
[[ -n $KEY_A && -n $KEY_B && $KEY_A != "$KEY_B" ]] && pass "edges have distinct tunnel keys" || fail "edge keys: '$KEY_A' '$KEY_B'"

# --- Enrol on edge A only ----------------------------------------------------
ROOT_A=$TMP/a/state/caddy/pki/authorities/local/root.crt
wait_for "edge A internal CA exists" "BEGIN CERTIFICATE" 20 cat "$ROOT_A"
STATE=$TMP/conn/connector.json
conn() { ip netns exec "$SITE" "$BIN/ingressd-connector" --state "$STATE" "$@"; }
cstatus() { conn status | tr -s " 	" " "; }
JOIN=$(hx A tunnel enroll-token cloud --join --ca "$ROOT_A" 2>/dev/null)
expect "connector enrols on edge A" 'Enrolled tunnel "cloud"' conn enroll "$JOIN" --mode tun
CONN_KEY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["connectors"]["cloud"]["public_key"])' "$TMP/a/state/connector.json")
[[ -n $CONN_KEY ]] && pass "edge A recorded the connector key" || fail "no connector key on edge A"
if grep -q '"edges"' "$STATE"; then pass "state uses the multi-edge format"; else fail "state format: $(cat "$STATE")"; fi

# Edge B: the same site with the connector's key (as the panel would set
# it on every attached node) and A as its sibling.
edge_config edge-b.example.test 172.16.2.1 51821 100.64.0.4/30 "    public_key: \"$CONN_KEY\"
    siblings:
      - { node: nod_a, endpoint: \"edge-a.example.test:51820\", edge_public_key: \"$KEY_A\", transit: 100.64.0.0/30, ws_url: \"wss://edge-a.example.test/.ingressd/tunnel/cloud\" }" >"$TMP/b/conf/config.yaml"
wait_applied B 2 "edge B applies the connector key and siblings"

ip netns exec "$SITE" "$BIN/ingressd-connector" --state "$STATE" run --udp-timeout 5s >"$TMP/conn.log" 2>&1 &
CONN_PID=$!
PIDS+=($CONN_PID)
web() { in_client curl -sS --max-time 3 -k --resolve "web.example.test:443:$1" https://web.example.test/; }
wait_for "connector up over UDP to edge A" "Transport: udp" 30 cstatus
wait_for "app reachable via edge A" "hello from lan" 20 web 198.51.100.1
if web 198.51.100.5 2>/dev/null | grep -q "hello from lan"; then fail "app reachable via edge B before the connector knows B"; else pass "edge B not linked before it is a sibling"; fi

# --- Edge A gains B as a sibling: the connector picks it up -----------------
edge_config edge-a.example.test 172.16.1.1 51820 100.64.0.0/30 "    siblings:
      - { node: nod_b, endpoint: \"edge-b.example.test:51821\", edge_public_key: \"$KEY_B\", transit: 100.64.0.4/30, ws_url: \"wss://edge-b.example.test/.ingressd/tunnel/cloud\" }" >"$TMP/a/conf/config.yaml"
wait_for "connector adds the sibling edge B" "edge added" 60 cat "$TMP/conn.log"
wait_for "state lists edge B as learned" '"learned": true' 30 cat "$STATE"
wait_for "app reachable via edge B" "hello from lan" 60 web 198.51.100.5
expect "app still reachable via edge A" "hello from lan" web 198.51.100.1
wait_for "status shows both edges up" "2 of 2 edges up" 60 cstatus
expect "status lists edge B" "Edge 2: nod_b https://edge-b.example.test (learned) site 100.64.0.6/30: up udp" cstatus
expect "edge B handshakes with the connector" "latest handshake" in_edge_b wg show ix-cloud
# B never saw an enrolment, yet it stores the connector's reports (sent
# over the tunnel to its control port) and its tunnel config was fetched.
wait_for "edge B stores the connector's health report" '"transport": "udp"' 60 cat "$TMP/b/state/connector.json"
wait_for "connector fetched edge B's own config" fetched 30 python3 -c '
import json,sys
s=json.load(open(sys.argv[1]))
c=[e["config"] for e in s["edges"] if e["config"]["edge_public_key"]==sys.argv[2]][0]
print("fetched" if c["revision"] else "not yet")' "$STATE" "$KEY_B"
# The control port answers only the site address through the tunnel.
reject "edge B's control port refuses the public side" in_client curl -s --max-time 3 -f http://198.51.100.5:51819/.ingressd/connector/poll

# --- Edge A goes down: B keeps serving --------------------------------------
ip -n "$EDGE" link set wan0 down
ip -n "$EDGE" link set pub0 down
kill "$SERVE_A" 2>/dev/null || true
expect "app reachable via edge B with edge A down" "hello from lan" web 198.51.100.5
sleep 10
expect "app still reachable via edge B 10 s later" "hello from lan" web 198.51.100.5
# A config change on B reaches the connector without the enrolment edge.
edge_config edge-b.example.test 172.16.2.1 51821 100.64.0.4/30 "    public_key: \"$CONN_KEY\"
    siblings:
      - { node: nod_a, endpoint: \"edge-a.example.test:51820\", edge_public_key: \"$KEY_A\", transit: 100.64.0.0/30, ws_url: \"wss://edge-a.example.test/.ingressd/tunnel/cloud\" }" "  second:
    hosts: [second.example.test]
    origin: http://192.168.0.17:8123
    tunnel: cloud" >"$TMP/b/conf/config.yaml"
wait_for "connector refreshes from edge B without edge A" "192.168.0.17:8123" 90 cat "$STATE"
expect "second app reachable via edge B" "second app" in_client curl -sS --max-time 3 -k --resolve second.example.test:443:198.51.100.5 https://second.example.test/
starts=$(grep -c "connector starting" "$TMP/conn.log" || true)
[[ $starts == 1 ]] && pass "edges were added and refreshed without rebuilding the link" || fail "link was rebuilt: $starts starts"

if [[ $FAIL -ne 0 ]]; then
	for f in a/serve b/serve conn; do echo "--- $f.log (tail) ---"; tail -60 "$TMP/$f.log" 2>/dev/null || true; done
	echo "--- connector state ---"; cat "$STATE" 2>/dev/null || true
	echo "--- site wg ---"; in_site wg show 2>/dev/null || true
	echo "--- edge B wg ---"; in_edge_b wg show 2>/dev/null || true
fi
finish
