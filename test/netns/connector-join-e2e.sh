#!/usr/bin/env bash
# e2e connector-join: ingressd-connector enrols with a single join
# string that pins the edge's CA (no --insecure), links the site, and on
# request from the edge discovers the LAN's web services (address, title,
# Server header) and reports them; --no-discovery refuses requests.
set -euo pipefail
P=he-rc
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
lan_http 8080 "<html><head><title>LAN Grafana</title></head><body>hello from lan</body></html>"
lan_http 8123 "<html><head><title>Home Assistant</title></head></html>"
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

# The edge's certificate comes from Caddy's internal CA: that root is what
# a panel would put in the join string for an edge without a public cert.
ROOT_CA=$TMP/state/caddy/pki/authorities/local/root.crt
wait_for "edge internal CA exists" "BEGIN CERTIFICATE" 20 cat "$ROOT_CA"

CURL=(in_client curl -sS --max-time 3 -k --resolve web.example.test:443:198.51.100.1)
STATE=$TMP/conn/connector.json
conn() { in_site "$BIN/ingressd-connector" --state "$STATE" "$@"; }
cstatus() { conn status | tr -s " 	" " "; }
start_conn() {
	local log=$1
	shift
	ip netns exec "$SITE" "$BIN/ingressd-connector" --state "$STATE" run "$@" >"$log" 2>&1 &
	CONN_PID=$!
	PIDS+=($CONN_PID)
}

# A join string with an unrelated CA must not be trusted.
if command -v openssl >/dev/null; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=wrong-ca \
		-keyout "$TMP/wrong.key" -out "$TMP/wrong.crt" >/dev/null 2>&1
	BAD_JOIN=$(he tunnel enroll-token cloud --join --ca "$TMP/wrong.crt" 2>/dev/null)
	reject "join string with a different CA is rejected (CA pinned)" in_site "$BIN/ingressd-connector" --state "$TMP/conn-bad/c.json" enroll "$BAD_JOIN" --edge-addr 172.16.1.1 --mode tun
fi
reject "garbage join string is rejected" conn enroll "eyJub3QiOiJqc29uIn0" --edge-addr 172.16.1.1

JOIN=$(he tunnel enroll-token cloud --join --ca "$ROOT_CA" 2>/dev/null)
[[ $JOIN == ey* ]] && pass "join string created" || fail "join string created: $JOIN"
# Install and enrol with the one-line installer (local artifacts, verified
# against SHA256SUMS; no service so the test controls the process).
DIST=$TMP/dist
mkdir -p "$DIST"
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
cp "$BIN/ingressd-connector" "$DIST/ingressd-connector_linux_$ARCH"
(cd "$DIST" && sha256sum ingressd-connector_linux_* >SHA256SUMS)
INSTALL=(in_site sh "$ROOT/deploy/install-connector.sh" --bin-dir "$DIST" --prefix "$TMP/inst" --state "$STATE" --no-service --edge-addr 172.16.1.1 --mode tun)
mkdir -p "$TMP/bad"
cp "$DIST/ingressd-connector_linux_$ARCH" "$TMP/bad/"
echo "0000000000000000000000000000000000000000000000000000000000000000  ingressd-connector_linux_$ARCH" >"$TMP/bad/SHA256SUMS"
reject "installer refuses a binary with a wrong checksum" in_site sh "$ROOT/deploy/install-connector.sh" --bin-dir "$TMP/bad" --prefix "$TMP/inst-bad" --state "$TMP/conn-bad2/c.json" --no-service "$JOIN"
"${INSTALL[@]}" --join "$JOIN" >"$TMP/install.log" 2>&1 || true
expect "installer verifies the checksum" "verified ingressd-connector_linux_$ARCH" cat "$TMP/install.log"
expect "installer enrolls with the join string (no --insecure)" "Enrolled tunnel \"cloud\"" cat "$TMP/install.log"
expect "installer installs the binary" "ingressd-connector" "$TMP/inst/ingressd-connector" version
expect "installer re-run keeps the enrolment" "already enrolled" "${INSTALL[@]}"
expect "installer re-run sees the binary up to date" "up to date" "${INSTALL[@]}"
expect "state pins the edge CA" "ca_pem" cat "$STATE"
if grep -q '"insecure"' "$STATE"; then fail "state is insecure"; else pass "state does not skip verification"; fi

start_conn "$TMP/conn.log" --udp-timeout 5s
wait_for "connector up over UDP" "Transport: udp" 20 cstatus
expect "HTTPS through the connector reaches LAN service" "hello from lan" "${CURL[@]}" https://web.example.test/
wait_for "control channel works with the pinned CA" "Control channel: ok" 40 cstatus
wait_for "edge records that the connector accepts discovery" '"discovery": true' 40 cat "$TMP/state/connector.json"

# Local scan preview: LAN and WAN subnets, never the tunnel transit.
conn discover --list-subnets >"$TMP/subnets.txt" 2>&1 || true
expect "scan covers the LAN subnet" "192.168.0.0/24" cat "$TMP/subnets.txt"
if grep -q "10.100.1." "$TMP/subnets.txt"; then fail "scan includes the tunnel transit network"; else pass "scan excludes the tunnel transit network"; fi

# Edge-initiated discovery. Run from the CLI, the request reaches the
# connector on its next poll (<= 25 s), then the scan takes ~15 s.
he tunnel discover cloud --wait 120s >"$TMP/discover.txt" 2>"$TMP/discover.err" || true
expect "discovery reports the LAN web server" "http://192.168.0.17:8080" cat "$TMP/discover.txt"
expect "discovery reports the page title" "LAN Grafana" cat "$TMP/discover.txt"
expect "discovery reports the Server header" "SimpleHTTP" cat "$TMP/discover.txt"
expect "discovery reports a second service" "Home Assistant" cat "$TMP/discover.txt"
expect "discovery lists the scanned subnet" "192.168.0.0/24" cat "$TMP/discover.txt"
if grep -q "10.100.1." "$TMP/discover.txt"; then fail "discovery scanned the transit network"; else pass "discovery skipped the transit network"; fi
expect "report stored in the edge's connector store" "LAN Grafana" cat "$TMP/state/connector.json"
expect "last report readable without a new scan" "LAN Grafana" he tunnel discover cloud --last
expect "connector logged the scan" "LAN discovery finished" cat "$TMP/conn.log"
expect "link was not restarted by the request" "1" bash -c "grep -c 'connector starting' $TMP/conn.log"

# Opt out: a connector run with --no-discovery tells the edge, which then
# refuses requests.
kill "$CONN_PID"; wait "$CONN_PID" 2>/dev/null || true
start_conn "$TMP/conn-nodisc.log" --udp-timeout 5s --no-discovery
wait_for "connector up again (--no-discovery)" "Transport: udp" 20 cstatus
wait_for "edge sees discovery disabled" "does not accept discovery" 60 he tunnel discover cloud --wait 1s

if [[ $FAIL -ne 0 ]]; then
	for f in serve conn conn-nodisc; do echo "--- $f.log (tail) ---"; tail -40 "$TMP/$f.log" 2>/dev/null || true; done
	echo "--- discover ---"; cat "$TMP/discover.txt" "$TMP/discover.err" 2>/dev/null || true
fi
finish
