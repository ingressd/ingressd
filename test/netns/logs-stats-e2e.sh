#!/usr/bin/env bash
# e2e logs-stats: access logs reach `ingressd logs` / `stats` and
# /metrics; a tunnel outage fires a tunnel_down alert (and a recovery) to a
# webhook; export → restore into fresh directories → apply brings the edge
# back, with and without a passphrase.
set -euo pipefail
P=he-p10
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

# Webhook sink in the edge namespace: appends each POST body to sink.log.
cat >"$TMP/sink.py" <<'EOF'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(sys.argv[2], "a") as f:
            f.write(body.decode() + "\n")
        self.send_response(204)
        self.end_headers()
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
touch "$TMP/sink.log"
in_edge python3 "$TMP/sink.py" 9099 "$TMP/sink.log" &
PIDS+=($!)

mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  name: e2e
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
    keepalive: 2
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
alerts:
  channels:
    hook: { type: webhook, url: "http://127.0.0.1:9099/hook" }
  rules:
    - { on: [tunnel_down, apply_failed], notify: [hook] }
logging:
  retention: 1d
  access_log_sampling: 1.0
EOF

he init >/dev/null
expect "first apply" "Applied." he apply --author e2e -m "First apply"
connect_site home

he serve --watch-interval 1s --metrics-listen 127.0.0.1:9464 >"$TMP/serve.log" 2>&1 &
SERVE=$!
PIDS+=($SERVE)
expect "serve applies at startup" "Applied." cat "$TMP/serve.log"
expect "ops socket up" "ops.sock" ls "$TMP/run"
# Caddy's net log writer redials at most every 10s; its first attempts
# (certificate logs during the apply before serve ran) failed, so lines in the
# next 10s go to its stderr. Production serve owns the socket from the start.
sleep 11

CURL=(in_client curl -sk --max-time 3 --resolve web.example.test:443:198.51.100.1)
wait_for "request through tunnel" "hello from lan" 15 "${CURL[@]}" "https://web.example.test/?probe=e2e"
"${CURL[@]}" -o /dev/null https://web.example.test/missing-page || true
"${CURL[@]}" -o /dev/null https://web.example.test/ || true

# Access logs, aggregates and metrics.
wait_for "logs show the request" "web.example.test/?probe=e2e" 20 he logs --host web.example.test
expect "logs --status filters" "/missing-page" he logs --status 404
if he logs --status 404 | grep -q probe=e2e; then fail "status filter leaked a 200"; else pass "status filter excludes 200s"; fi
expect "logs --json" '"client_ip":"198.51.100.2"' he logs --json -n 1
wait_for "stats counts the host" "web.example.test" 10 he stats --since 1h
expect "stats --json totals" '"requests": ' he stats --json
METRICS=(in_edge curl -s --max-time 3 http://127.0.0.1:9464/metrics)
expect "metrics: per-host counters" 'ingressd_http_requests_total{host="web.example.test",code="2xx"}' "${METRICS[@]}"
expect "metrics: 404s counted" 'ingressd_http_requests_total{host="web.example.test",code="4xx"} 1' "${METRICS[@]}"
expect "metrics: tunnel up" 'ingressd_tunnel_up{tunnel="home"} 1' "${METRICS[@]}"
expect "metrics: handshake age" 'ingressd_tunnel_handshake_age_seconds{tunnel="home"}' "${METRICS[@]}"
expect "metrics: applies" 'ingressd_applies_total{result="ok"} 1' "${METRICS[@]}"
expect "metrics on ops socket" "ingressd_build_info" in_edge curl -s --max-time 3 --unix-socket "$TMP/run/ops.sock" http://ops/metrics

# Live tail.
he logs -f --host web.example.test -n 0 >"$TMP/tail.log" 2>&1 &
TAIL=$!
PIDS+=($TAIL)
sleep 1
"${CURL[@]}" -o /dev/null "https://web.example.test/?live-tail" || true
wait_for "logs -f streams new requests" "/?live-tail" 10 cat "$TMP/tail.log"
kill $TAIL 2>/dev/null || true

# Alerts.
expect "alerts test reaches the webhook" "Sent a test notification" he alerts test hook
expect "webhook received test" "ingressd test notification" cat "$TMP/sink.log"
if grep -q '"event":"tunnel_down"' "$TMP/sink.log"; then fail "tunnel_down fired while healthy"; else pass "no false tunnel_down"; fi
ip -n "$SITE" link del wg0
wait_for "tunnel_down alert fires" '"event":"tunnel_down","key":"home","status":"firing"' 45 cat "$TMP/sink.log"
expect "alerts list shows it" "tunnel_down" he alerts list
connect_site home
wait_for "tunnel recovery notice" '"event":"tunnel_down","key":"home","status":"resolved"' 45 cat "$TMP/sink.log"
N=$(grep -c '"event":"tunnel_down","key":"home","status":"firing"' "$TMP/sink.log" || true)
if [[ $N -eq 1 ]]; then pass "tunnel_down sent once (dedup)"; else fail "tunnel_down sent $N times"; fi
expect "doctor reports disk space" "disk space for" he doctor

kill $SERVE 2>/dev/null || true
wait $SERVE 2>/dev/null || true

# Export / restore drills.
expect "export (key)" "secrets: key" he export -o "$TMP/backup-key.tar.gz"
expect "export (passphrase)" "secrets: passphrase" env INGRESSD_BACKUP_PASSPHRASE=drill-pass "$BIN/ingressd" \
	--config-dir "$TMP/conf" --key "$TMP/keys/age.key" export --passphrase -o "$TMP/backup-pass.tar.gz"
expect "export (no secrets)" "secrets: none" he export --no-secrets -o "$TMP/backup-cfg.tar.gz"
if tar -xOzf "$TMP/backup-pass.tar.gz" secrets.age | grep -q "scrypt"; then pass "passphrase export uses scrypt"; else fail "passphrase export is not scrypt-encrypted"; fi

# redial_site: restarts the site's WireGuard with its ORIGINAL config, as a
# router does after the edge moves (it re-handshakes within ~2 minutes; this
# just skips the wait). Working afterwards proves the edge keys survived.
redial_site() {
	ip -n "$SITE" link del wg0 2>/dev/null || true
	ip -n "$SITE" link add wg0 type wireguard
	in_site wg setconf wg0 "$TMP/site-home.conf"
	ip -n "$SITE" addr add 10.100.1.2/24 dev wg0
	ip -n "$SITE" link set wg0 up
}

# he_at <dir> <args...>: CLI with config/key/state under <dir> (fresh VM).
he_at() {
	local d=$1
	shift
	in_edge "$BIN/ingressd" --config-dir "$d/conf" --key "$d/age.key" --state-dir "$d/state" --run-dir "$TMP/run" "$@"
}

# Drill 1: key-encrypted backup + the separately backed-up key file.
ip -n "$EDGE" link del ix-home
reject "edge broken before restore" "${CURL[@]}" --fail https://web.example.test/
mkdir -p "$TMP/r1"
cp "$TMP/keys/age.key" "$TMP/r1/age.key"
expect "restore (key) applies" "Applied." he_at "$TMP/r1" restore "$TMP/backup-key.tar.gz"
redial_site
wait_for "edge works after key restore" "hello from lan" 20 "${CURL[@]}" https://web.example.test/
expect "history restored" "First apply" he_at "$TMP/r1" history
expect "restore refuses to overwrite" "--force" he_at "$TMP/r1" restore "$TMP/backup-key.tar.gz"

# Drill 2: passphrase backup on a machine without the key file.
ip -n "$EDGE" link del ix-home
mkdir -p "$TMP/r2"
reject "passphrase restore needs the passphrase" he_at "$TMP/r2" restore "$TMP/backup-pass.tar.gz" </dev/null
echo drill-pass >"$TMP/pass.txt"
restore_pass() { he_at "$TMP/r2" restore --passphrase "$TMP/backup-pass.tar.gz" <"$TMP/pass.txt"; }
expect "restore (passphrase) applies" "Applied." restore_pass
[[ -f $TMP/r2/age.key ]] && pass "new key generated" || fail "no key generated"
redial_site
wait_for "edge works after passphrase restore (same WireGuard keys)" "hello from lan" 20 "${CURL[@]}" https://web.example.test/
expect "restored config is valid" "is valid" he_at "$TMP/r2" validate

finish
