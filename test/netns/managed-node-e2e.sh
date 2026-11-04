#!/usr/bin/env bash
# e2e managed-node: a node enrols with the fake panel
# (test/fakepanel), applies signed snapshots, rejects a tampered one
# (and legacy v1, other-node and expired ones, and unsigned requests),
# meters usage across an agent restart, streams live logs, answers
# diagnostics, site-config and connector-token requests, signs users in
# with hosted Access (email provider panel: codes from the fake panel, org
# keys from the snapshot, login-to-play, revocation and l4_allow relays),
# and keeps serving standalone after detach.
#
#   fake panel 198.51.100.2:8443 (client ns) ── edge (node) ── site router ── lan
set -euo pipefail
P=he-rn
source "$(dirname "$0")/lib.sh"
# The fake panel speaks plain http: test-only escape hatch (nodeagent.InsecurePanelEnv).
export INGRESSD_INSECURE_PANEL=1
command -v python3 >/dev/null || { echo "missing python3" >&2; exit 1; }

PANEL=198.51.100.2:8443
build_topology
lan_http 8080 "hello from lan"
start_edge_proxy

PMAIL=$TMP/panel-mail.log
in_client "$BIN/fakepanel" --listen "$PANEL" --tokens tok-e2e --mail-log "$PMAIL" >"$TMP/panel.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do in_client curl -s -o /dev/null "http://$PANEL/test/" && break; sleep 0.1; done

# JSON helpers (python3 is required by lib.sh anyway).
pj() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
pstate() { in_client curl -s --max-time 5 "http://$PANEL/test/state"; }
preq() { in_client curl -s --max-time 70 -X POST "http://$PANEL/test/request" -d "$1"; }
psend() { in_client curl -s --max-time 10 -X POST "http://$PANEL/test/send" -d "$1"; }
# psnap <config-file> [extra JSON fields]: signs and sends a snapshot.
psnap() {
	local body
	body=$(python3 -c 'import json,sys; d={"config_yaml": open(sys.argv[1]).read()}; d.update(json.loads(sys.argv[2])); print(json.dumps(d))' "$1" "${2:-{\}}")
	in_client curl -s --max-time 120 -X POST "http://$PANEL/test/snapshot" -d "$body"
}
# wait_state <description> <python condition on d>: retries for ~30s.
wait_state() {
	local desc=$1 cond=$2
	for _ in $(seq 60); do
		if [[ $(pstate | pj "bool($cond)" 2>/dev/null) == True ]]; then pass "$desc"; return; fi
		sleep 0.5
	done
	fail "$desc: condition '$cond' not met; state: $(pstate | pj '{k: d[k] for k in ("connected","connects","revision","usage_seqs","usage_msgs","apps","sites")}')"
}
diag() { preq "{\"type\":\"diag_request\",\"data\":{\"request_id\":\"$1\",\"kind\":\"origin\",\"app\":\"$2\",\"timeout\":8000000000}}" | pj 'd["data"]["code"]'; }
CURL=(in_client curl -sS --max-time 3 -k)
web() { "${CURL[@]}" --resolve "$1:443:198.51.100.1" "https://$1${2:-/}"; }

# --- Enrolment -------------------------------------------------------------
printf 'tok-e2e\n' >"$TMP/enroll-token" # token from a file: never in argv
expect "enrolment refuses a plain-http panel without the test escape hatch" "uses plain http" \
	in_edge env -u INGRESSD_INSECURE_PANEL "$BIN/ingressd" --state-dir "$TMP/state0" --key "$TMP/keys/age0.key" --config-dir "$TMP/conf0" \
	node enroll --panel "http://$PANEL" --token-file "$TMP/enroll-token"
expect "node enrols with the panel" "Enrolled as nod_" he node enroll --panel "http://$PANEL" --token-file "$TMP/enroll-token" --public-ip 172.16.1.1
reject "enrolment token is single use" he --state-dir "$TMP/state2" node enroll --panel "http://$PANEL" --token tok-e2e
[[ $(stat -c %a "$TMP/state/node.json") == 600 ]] && pass "node.json is 0600" || fail "node.json mode $(stat -c %a "$TMP/state/node.json")"
expect "node status shows managed" "Mode:              managed" he node status

start_serve() {
	# ip netns exec directly (not the in_edge function) so $! is ingressd itself.
	ip netns exec "$EDGE" env INGRESSD_AGENT_USAGE_INTERVAL=2s INGRESSD_AGENT_STATUS_INTERVAL=1s \
		"$BIN/ingressd" --config-dir "$TMP/conf" --key "$TMP/keys/age.key" \
		--state-dir "$TMP/state" --run-dir "$TMP/run" serve --watch-interval 1s >>"$TMP/serve.log" 2>&1 &
	SERVE=$!
	PIDS+=($SERVE)
}
start_serve
wait_state "agent connects and says hello with a mesh key" 'd["connected"] and d["hello"]["mesh_public_key"] and d["hello"]["age_recipient"]'

# --- Signed snapshot ------------------------------------------------------
ip -n "$LAN" addr add 192.168.0.18/24 dev eth0
mkdir -p "$TMP/www-probe"
echo probe >"$TMP/www-probe/index.html"
ip netns exec "$LAN" python3 -m http.server 8090 --bind 192.168.0.18 --directory "$TMP/www-probe" >/dev/null 2>&1 &
PROBE=$!
PIDS+=($PROBE)
cat >"$TMP/snap1.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  acme: { ca: internal }
tunnels:
  home:
    site: router
    vendor: unifi
    listen_port: 51820
    transit: 10.100.1.0/24
  conn:
    site: connector
    listen_port: 51821
    transit: 10.100.2.0/24
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
  count:
    hosts: [count.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
  probe:
    hosts: [probe.example.test]
    origin: http://192.168.0.18:8090
    tunnel: home
EOF
expect "signed snapshot applied" '"ok":true' psnap "$TMP/snap1.yaml" '{"secrets":{"smtp_password":"s3cret-value"}}'
expect "config.yaml is the snapshot" "probe.example.test" cat "$TMP/conf/config.yaml"
expect "secret decrypted into the store" "smtp_password" he secret list
expect "history records the panel revision" "Apply panel revision 1" he history -n3

# --- Site config (router site) through the panel ---------------------------
SITECONF=$(preq '{"type":"site_config_request","data":{"site":"home"}}' | pj 'd["data"]["config"]')
[[ $SITECONF == *"DNS = "* ]] && pass "site config has a DNS line" || fail "site config: $SITECONF"
[[ $SITECONF == *"Endpoint = 172.16.1.1:51820"* ]] && pass "site config endpoint is the node's public IP" || fail "endpoint: $SITECONF"
preq '{"type":"site_config_request","data":{"site":"home","format":"wg"}}' | pj 'd["data"]["config"]' >"$TMP/site-home.conf"
ip -n "$SITE" link add wg0 type wireguard
in_site wg setconf wg0 "$TMP/site-home.conf"
ip -n "$SITE" addr add "$(sed -n 's/^Address = //p' <<<"$SITECONF")" dev wg0
ip -n "$SITE" link set wg0 up
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true
expect "app reachable through the WireGuard tunnel" "hello from lan" web web.example.test
wait_state "status reports the tunnel up" 'any(t["site"]=="home" and t["up"] for t in d["status"]["tunnels"])'
wait_state "status reports the certificate valid" 'any(c["host"]=="web.example.test" and c["state"]=="valid" for c in d["status"]["certs"])'
wait_state "status reports applied revision 1" 'd["status"]["applied_revision"]==1 and d["status"]["health"] in ("ok","degraded")'

# --- Tampered snapshot ------------------------------------------------------
sed 's/192.168.0.17:8080/192.168.0.17:9999/' "$TMP/snap1.yaml" >"$TMP/snap-bad.yaml"
expect "tampered snapshot rejected" "signature does not match" psnap "$TMP/snap-bad.yaml" '{"tamper":true}'
expect "old config keeps serving" "hello from lan" web web.example.test
if grep -q 9999 "$TMP/conf/config.yaml"; then fail "tampered config written"; else pass "tampered config not written"; fi
expect "stale revision rejected" "not newer than the applied revision" psnap "$TMP/snap1.yaml" '{"revision":1,"tamper":false,"secrets":{"x":"yyyyyy"}}'
# Snapshot v2 binding (no downgrade to the replayable v1 format).
expect "legacy v1 snapshot rejected" "legacy (v1) snapshot" psnap "$TMP/snap-bad.yaml" '{"force":true,"legacy":true}'
expect "snapshot for another node rejected" "not this node" psnap "$TMP/snap-bad.yaml" '{"force":true,"for_node":"nod_other"}'
expect "expired (replayed) snapshot rejected" "expired" psnap "$TMP/snap-bad.yaml" '{"force":true,"signed_at":"2020-01-01T00:00:00Z"}'
if grep -q 9999 "$TMP/conf/config.yaml"; then fail "rejected v2 snapshot written"; else pass "rejected snapshots not written"; fi
# Sensitive requests must be org-signed.
expect "unsigned site_config_request rejected" "unsigned" preq '{"type":"site_config_request","unsigned":true,"data":{"site":"home"}}'
psend '{"type":"detach","unsigned":true,"data":{"reason":"forged"}}' >/dev/null
wait_state "unsigned detach rejected" 'any(e["kind"]=="request_rejected" and e["fields"]["type"]=="detach" for e in d["events"])'
[[ -f $TMP/state/node.json ]] && pass "unsigned detach ignored" || fail "unsigned detach removed node.json"

# --- Live preview -----------------------------------------------------------
psend '{"type":"live_subscribe","data":{"subscription_id":"live1","apps":["web"],"until":"2099-01-01T00:00:00Z","max_per_second":50}}' >/dev/null
sleep 1
web web.example.test "/live-check?token=topsecret&x=1" >/dev/null
wait_state "live subscription streams the request" 'any(e["path"]=="/live-check?token=&x=" and e["app"]=="web" for e in d["logs"])'
if pstate | grep -q topsecret; then fail "query value leaked in live logs"; else pass "query values redacted"; fi
psend '{"type":"live_unsubscribe","data":{"subscription_id":"live1"}}' >/dev/null

# --- Usage: deltas with seq, across an agent restart ------------------------
for i in 1 2 3 4 5; do web count.example.test "/c$i" >/dev/null || fail "count request $i"; done
wait_state "usage counts 5 requests for the app" 'd["apps"].get("count",{}).get("requests")==5'
in_client curl -s -X POST "http://$PANEL/test/ack?on=0" >/dev/null
for i in 6 7; do web count.example.test "/c$i" >/dev/null || fail "count request $i"; done
wait_state "unacknowledged usage delivered" 'd["apps"]["count"]["requests"]==7'
SEQ_BEFORE=$(pstate | pj 'max(d["usage_seqs"])')
kill -TERM "$SERVE"
wait "$SERVE" 2>/dev/null || true
start_serve
wait_state "agent reconnects after restart" 'd["connected"] and d["connects"]>=2'
wait_state "hello reports the persisted usage seq" "d['hello']['usage_seq']>=$SEQ_BEFORE"
in_client curl -s -X POST "http://$PANEL/test/ack?on=1" >/dev/null
wait_state "pending usage was resent after the restart" 'd["usage_msgs"]>len(d["usage_seqs"])'
for i in 8 9 10; do web count.example.test "/c$i" >/dev/null || fail "count request $i"; done
wait_state "usage counts 10 requests after restart" 'd["apps"]["count"]["requests"]==10'
sleep 5
wait_state "no double counting" 'd["apps"]["count"]["requests"]==10'
wait_state "usage seqs are contiguous and increasing" 'd["usage_seqs"]==list(range(d["usage_seqs"][0], d["usage_seqs"][0]+len(d["usage_seqs"])))'
wait_state "site usage recorded from WireGuard counters" 'd["sites"].get("home",[0,0])[0]>0'

# --- Diagnostics: origin through the tunnel --------------------------------
expect "diag origin ok" "ok" diag d1 probe
in_site nft add table inet he_rn_drop
in_site nft add chain inet he_rn_drop fw '{ type filter hook forward priority 0; }'
in_site nft add rule inet he_rn_drop fw iifname wg0 tcp flags syn / syn,ack drop
expect "diag origin no_reply when the site router drops SYNs" "no_reply" diag d2 probe
in_site nft delete table inet he_rn_drop
expect "diag origin ok again" "ok" diag d3 probe
kill "$PROBE"
sleep 0.5
expect "diag origin refused when the port is closed" "refused" diag d4 probe

# --- Connector token: join string and bare-IP connector endpoints -----------
JOIN=$(preq '{"type":"connector_token_request","data":{"site":"conn"}}' | pj 'd["data"]["join_string"]')
python3 -c 'import base64,json,sys; s=sys.argv[1]; d=json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4))); open(sys.argv[2],"w").write(d["ca"]); print(d["u"]); print(d["t"])' "$JOIN" "$TMP/ca.pem" >"$TMP/join.txt"
[[ $(sed -n 1p "$TMP/join.txt") == "https://172.16.1.1" ]] && pass "join string carries the bare-IP edge URL" || fail "join url: $(cat "$TMP/join.txt")"
grep -q "BEGIN CERTIFICATE" "$TMP/ca.pem" && pass "join string carries the internal CA" || fail "no CA in join string"
expect "connector endpoint served on the bare IP with the pinned CA" "unauthorized" in_site curl -sS --max-time 5 --cacert "$TMP/ca.pem" https://172.16.1.1/.ingressd/connector/poll
TOKEN=$(sed -n 2p "$TMP/join.txt")
PUB=$(wg genkey | wg pubkey)
in_site curl -sS --max-time 70 --cacert "$TMP/ca.pem" -H 'Content-Type: application/json' \
	-d "{\"token\":\"$TOKEN\",\"public_key\":\"$PUB\"}" https://172.16.1.1/.ingressd/connector/enroll >"$TMP/cenroll.json" || true
grep -q '"credential"' "$TMP/cenroll.json" && pass "connector enrols through the bare-IP endpoint" || fail "connector enrol: $(head -c 300 "$TMP/cenroll.json")"
CRED=$(pj 'd["credential"]' <"$TMP/cenroll.json")
CREV=$(pj 'd["config"]["revision"]' <"$TMP/cenroll.json")

# --- LAN discovery relay (connector side simulated with curl) ---------------
preq '{"type":"discover_request","data":{"site":"conn"}}' >"$TMP/disc.json" &
DPID=$!
sleep 1
CAUTH=(-H "Authorization: Bearer conn.$CRED")
in_site curl -s --max-time 30 --cacert "$TMP/ca.pem" "${CAUTH[@]}" "https://172.16.1.1/.ingressd/connector/poll?rev=$CREV&wait=20s&discover=" >"$TMP/poll.json" || true
[[ -n $(pj 'd.get("discover_id","")' <"$TMP/poll.json") ]] && pass "connector poll carries the discover request" || fail "poll: $(head -c 300 "$TMP/poll.json")"
DID=$(pj 'd.get("discover_id","")' <"$TMP/poll.json")
in_site curl -s --max-time 10 --cacert "$TMP/ca.pem" "${CAUTH[@]}" -H 'Content-Type: application/json' \
	-d "{\"id\":\"$DID\",\"services\":[{\"address\":\"192.168.0.17\",\"port\":8080,\"scheme\":\"http\",\"title\":\"LAN app\"}]}" \
	https://172.16.1.1/.ingressd/connector/discovery >/dev/null || true
wait "$DPID" || true
grep -q '"LAN app"' "$TMP/disc.json" && pass "discovery results relayed to the panel" || fail "discovery: $(head -c 300 "$TMP/disc.json")"

# --- Hosted Access: codes via the panel, org keys from the snapshot ---------
SESSKEY=$(head -c 32 /dev/urandom | base64 -w0)
JWTKEY=$(openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0)
python3 - "$TMP/snap1.yaml" "$TMP/snap2.yaml" <<'EOF'
import sys
cfg = open(sys.argv[1]).read()
head, apps = cfg.split("apps:\n", 1)
extra = """email: { provider: panel }
access:
  portal_host: auth.example.test
  session_key: secret://org_access_session_key
  jwt_key: secret://org_access_jwt_key
  otp: { resend_cooldown: 1s }
policies:
  members:
    action: allow
    include: [{ email_domain: [example.test] }]
l4:
  play:
    listen: [7004/udp]
    target: { tunnel: home, address: 192.168.0.17, port: 9000 }
    access: login_to_play
    login_to_play: { policy: members, ttl: 1h, portal_host: play.example.test }
"""
secure = """  secure:
    hosts: [secure.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    access: [members]
"""
open(sys.argv[2], "w").write(head + extra + "apps:\n" + secure + apps)
EOF
expect "hosted access snapshot applied" '"ok":true' psnap "$TMP/snap2.yaml" \
	"{\"secrets\":{\"org_access_session_key\":\"$SESSKEY\",\"org_access_jwt_key\":\"$JWTKEY\"}}"
if he secret list | grep -qw access_session_key; then fail "node generated its own access keys"; else pass "no node-local access keys generated"; fi
HA=(in_client curl -sS --max-time 8 -k --resolve secure.example.test:443:198.51.100.1 --resolve auth.example.test:443:198.51.100.1 --resolve play.example.test:443:198.51.100.1)
HJAR=$TMP/hosted-jar.txt
hform() { # hform <step> <email> [code]
	"${HA[@]}" -c "$HJAR" -b "$HJAR" -i -X POST https://auth.example.test/login -H "Origin: https://auth.example.test" \
		--data-urlencode app=secure --data-urlencode "rd=https://secure.example.test/docs" --data-urlencode "n=$HN" \
		--data-urlencode "step=$1" --data-urlencode "email=$2" --data-urlencode "code=${3:-}"
}
pcode() { # pcode <email>: latest code the fake panel mailed
	for _ in $(seq 40); do
		c=$(awk -v to="To: $1" '$0 == to { want = 1 } want && / is: [0-9]+$/ { code = $NF; want = 0 } END { print code }' "$PMAIL" 2>/dev/null)
		[[ -n $c ]] && { echo "$c"; return; }
		sleep 0.25
	done
}
expect "protected app redirects to the portal" "location: https://auth.example.test/login?app=secure" "${HA[@]}" -c "$HJAR" -I https://secure.example.test/docs
# The sign-in is bound to this browser: nonce cookie on the app host, its hash as n.
HN=$("${HA[@]}" -c "$HJAR" -b "$HJAR" -I https://secure.example.test/docs | sed -n 's/^location: .*[?&]n=\([A-Za-z0-9_-]*\).*/\1/Ip' | tr -d '\r')
[[ ${#HN} == 43 ]] && pass "login URL carries the sign-in nonce hash" || fail "no n in login URL: '$HN'"
expect "code requested through the panel" "is on its way to" hform email alice@example.test
HCODE=$(pcode alice@example.test)
[[ $HCODE =~ ^[0-9]{6}$ ]] && pass "panel mailed a 6-digit code" || fail "no code in panel mail log: $(cat "$PMAIL" 2>/dev/null)"
wait_state "panel saw auth_otp_start with host and client IP" 'any(s["email"]=="alice@example.test" and s["host"]=="auth.example.test" and s["client_ip"] for s in d["otp_starts"])'
expect "wrong code rejected by the panel" "invalid or has expired" hform code alice@example.test 000000
HOUT=$(hform code alice@example.test "$HCODE")
HCB=$(sed -n 's/^location: //Ip' <<<"$HOUT" | tr -d '\r')
[[ $HCB == "https://secure.example.test/.ingressd/callback?code=v4.local."* ]] && pass "verify redirects with a sealed callback code" || fail "verify: ${HOUT:0:400}"
expect "callback sets the app cookie" "__edge_secure=" "${HA[@]}" -c "$HJAR" -b "$HJAR" -i "$HCB"
expect "app reachable with identity" "hello from lan" "${HA[@]}" -b "$HJAR" https://secure.example.test/
SIGNED_IN_JAR=$HJAR HJAR=$TMP/hosted-jar-other.txt # a fresh jar: alice's portal session would skip the form
expect "outsider: no panel request, same answer" "is on its way to" hform email eve@other.test
HJAR=$SIGNED_IN_JAR
sleep 1
wait_state "panel never asked to mail an outsider" 'not any(s["email"]=="eve@other.test" for s in d["otp_starts"])'

# Login-to-play with the same flow.
PJAR=$TMP/play-jar.txt
pform() {
	"${HA[@]}" -c "$PJAR" -b "$PJAR" -X POST https://play.example.test/join/play -H "Origin: https://play.example.test" \
		--data-urlencode "step=$1" --data-urlencode "email=$2" --data-urlencode "code=${3:-}"
}
expect "play page asks for an email" 'value="email"' "${HA[@]}" https://play.example.test/join/play
expect "play code requested" "is on its way to" pform email bob@example.test
expect "player signed in and allowlisted" "You're in" pform code bob@example.test "$(pcode bob@example.test)"
wait_state "l4_allow reported to the panel" 'any(a["service"]=="play" and a["email"]=="bob@example.test" for a in d["l4_allows"])'
expect "play cookie skips the code next time" "You're in" "${HA[@]}" -b "$PJAR" https://play.example.test/join/play
psend '{"type":"l4_allow","data":{"service":"play","ip":"198.51.100.77","email":"carol@example.test","origin":"nod_other"}}' >/dev/null
for _ in $(seq 20); do he l4 list | grep -q 198.51.100.77 && break; sleep 0.5; done
expect "relayed l4_allow applied locally" "carol@example.test" he l4 list

# Sign-out is reported; a relayed revocation is applied.
expect "portal sign-out" "signed out of all apps" "${HA[@]}" -b "$HJAR" -X POST -H "Origin: https://auth.example.test" https://auth.example.test/logout
wait_state "sign-out reported to the panel" 'any(r["email"]=="alice@example.test" for r in d["revokes"])'
for _ in $(seq 20); do [[ $("${HA[@]}" -o /dev/null -w '%{http_code}' -b "$HJAR" https://secure.example.test/docs) == 302 ]] && break; sleep 0.5; done
expect "app cookie refused after sign-out" "302" "${HA[@]}" -o /dev/null -w '%{http_code}' -b "$HJAR" https://secure.example.test/docs
psend '{"type":"auth_revoke","data":{"sid":"sid-from-another-node","email":"dan@example.test"}}' >/dev/null
for _ in $(seq 20); do he sessions list | grep -q dan@example.test && break; sleep 0.5; done
expect "relayed revocation recorded" "revoked" he sessions list --email dan@example.test

# --- Central sign-in portal on the panel (access.portal_url) ----------------
# The panel signs visitors in and seals the callback code (the fake panel's
# /test/portal-code plays that part); the node checks the policy again.
python3 - "$TMP/snap2.yaml" "$TMP/snap3.yaml" <<'EOF'
import sys
cfg = open(sys.argv[1]).read()
cfg = cfg.replace("  portal_host: auth.example.test\n", "  portal_url: https://auth.ingressd.test/a/org_e2e\n", 1)
cfg = cfg.replace(", portal_host: play.example.test }", " }", 1)
open(sys.argv[2], "w").write(cfg)
EOF
expect "central portal snapshot applied" '"ok":true' psnap "$TMP/snap3.yaml" \
	"{\"secrets\":{\"org_access_session_key\":\"$SESSKEY\",\"org_access_jwt_key\":\"$JWTKEY\"}}"
for _ in $(seq 20); do "${HA[@]}" -I https://secure.example.test/docs 2>/dev/null | grep -qi "location: https://auth.ingressd.test/" && break; sleep 0.5; done
expect "protected app redirects to the panel portal" "location: https://auth.ingressd.test/a/org_e2e/login?app=secure" "${HA[@]}" -I https://secure.example.test/docs
portal_cb() { # portal_cb <email>: the fake panel signs <email> in and returns the callback URL
	in_client curl -s --max-time 10 -X POST "http://$PANEL/test/portal-code" \
		-d "{\"session_key\":\"$SESSKEY\",\"jwt_key\":\"$JWTKEY\",\"app\":\"secure\",\"rd\":\"https://secure.example.test/docs\",\"email\":\"$1\"}" | pj 'd["callback"]'
}
CJAR=$TMP/central-jar.txt
CCB=$(portal_cb alice@example.test)
expect "panel-sealed code redeemed for an allowed email" "__edge_secure=" "${HA[@]}" -c "$CJAR" -b "$CJAR" -i "$CCB"
expect "app reachable after the central portal" "hello from lan" "${HA[@]}" -b "$CJAR" https://secure.example.test/
expect "node enforces the policy at the callback" "Access denied: eve@other.test is not allowed" "${HA[@]}" -i "$(portal_cb eve@other.test)"
psend '{"type":"l4_allow","data":{"service":"play","ip":"198.51.100.78","email":"eve@other.test","origin":"panel"}}' >/dev/null
psend '{"type":"l4_allow","data":{"service":"play","ip":"198.51.100.79","email":"frank@example.test","origin":"panel"}}' >/dev/null
for _ in $(seq 20); do he l4 list | grep -q 198.51.100.79 && break; sleep 0.5; done
expect "relayed l4_allow from the panel portal applied" "frank@example.test" he l4 list
if he l4 list | grep -q 198.51.100.78; then fail "relayed l4_allow for an outsider applied"; else pass "relayed l4_allow refused by the game's policy"; fi

# --- Local edits are ignored while managed ---------------------------------
cat >>"$TMP/conf/config.yaml" <<'EOF'
  ignored:
    hosts: [ignored.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
EOF
expect "local edit logged and ignored" "edited locally" cat "$TMP/serve.log"
reject "locally added app is not rendered" bash -c "ip netns exec $EDGE curl -s --unix-socket $TMP/run/caddy-admin.sock http://localhost/config/ | grep -q ignored.example.test"

# --- Detach -----------------------------------------------------------------
psend '{"type":"detach","data":{"reason":"e2e"}}' >/dev/null
for _ in $(seq 20); do [[ -f $TMP/state/node.json ]] || break; sleep 0.5; done
[[ ! -f $TMP/state/node.json ]] && pass "detach removes node.json" || fail "node.json still present"
expect "node status shows standalone" "Standalone" he node status
expect "detached node keeps serving" "hello from lan" web web.example.test
expect "serve follows config.yaml again after detach" "hello from lan" web ignored.example.test
expect "connector endpoint still served after detach" "unauthorized" in_site curl -sS --max-time 5 --cacert "$TMP/ca.pem" https://172.16.1.1/.ingressd/connector/poll

if [[ $FAIL -ne 0 ]]; then
	echo "--- serve log (warnings) ---"
	grep -E "level=(WARN|ERROR)" "$TMP/serve.log" | tail -40 || true
fi
finish
