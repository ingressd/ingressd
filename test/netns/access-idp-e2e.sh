#!/usr/bin/env bash
# e2e access-idp: sign-in with identity providers and header tokens. The
# node runs its own portal with Discord, Google and Steam configured
# against fakes (test/fakeidp; the node binary is the idptest build, the
# only one that honours INGRESSD_IDP_TEST_BASE). Covers the provider
# buttons, the OAuth / OpenID round trip through the portal and the app
# callback, identity selectors (Discord role, Steam owned app, Google
# Workspace domain) enforced at the portal and by edge_auth on every
# request, Steam users without email, flow-cookie checks, and header tokens
# (constant-time check, IP condition, stripped before the origin).
set -euo pipefail
P=he-p9
source "$(dirname "$0")/lib.sh"

[[ -x $BIN/ingressd-idptest && -x $BIN/fakeidp ]] || { echo "build bin/ingressd-idptest and bin/fakeidp (scripts/e2e.sh or make build-e2e)" >&2; exit 1; }
# The control plane is the idptest build; everything else is unchanged.
he() {
	INGRESSD_IDP_TEST_BASE=http://127.0.0.1:9900 in_edge "$BIN/ingressd-idptest" --config-dir "$TMP/conf" --key "$TMP/keys/age.key" \
		--state-dir "$TMP/state" --run-dir "$TMP/run" "$@"
}

build_topology

cat >"$TMP/echo.py" <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("path=%s\n" % self.path + "".join("%s: %s\n" % (k, v) for k, v in self.headers.items())).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
in_lan python3 "$TMP/echo.py" >/dev/null 2>&1 &
PIDS+=($!)
in_edge "$BIN/fakeidp" -listen 127.0.0.1:9900 >"$TMP/fakeidp.log" 2>&1 &
PIDS+=($!)
start_edge_proxy

GUILD=100000000000000001 ROLE=200000000000000001 STEAMID=76561198000000001
mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
email:
  provider: log
  log: { path: $TMP/mail.log }
access:
  portal_host: auth.example.test
  providers:
    discord: { client_id: client-1, client_secret: secret://discord_secret }
    google: { client_id: client-1, client_secret: secret://google_secret }
    steam: { api_key: secret://steam_key, session: 2h }
service_tokens:
  bot: { header: X-Bot-Token, client_secret: secret://bot_token }
policies:
  bot:
    action: service_auth
    include: [{ service_token: bot }]
    require: [{ ip: 198.51.100.0/30 }]
  mods:
    action: allow
    include: [{ discord_role: ["$GUILD/$ROLE"] }]
  gamers:
    action: allow
    include: [{ steam_app: ["440"] }]
    require: [{ login_method: steam }]
  workspace:
    action: allow
    include: [{ google_hd: [corp.example] }]
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    access: [bot, mods, gamers, workspace]
    login_methods: [discord, google, steam]
EOF

he init >/dev/null
printf secret-1 | he secret set discord_secret >/dev/null
printf secret-1 | he secret set google_secret >/dev/null
printf steam-key | he secret set steam_key >/dev/null
printf bot-token-0123456789abcdef | he secret set bot_token >/dev/null
expect "apply succeeds" "Applied." he apply --author e2e -m "Access providers"
connect_site home
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve applies" "Applied." cat "$TMP/serve.log"
expect "test build uses the fake providers" "faked at http://127.0.0.1:9900" cat "$TMP/serve.log"

fake_user() { # fake_user <method> <json>
	in_edge curl -sS -X PUT --data "$2" "http://127.0.0.1:9900/_fake/user/$1" >/dev/null
}

C=(in_client curl -sS --max-time 5 -k --resolve web.example.test:443:198.51.100.1 --resolve auth.example.test:443:198.51.100.1)
W=https://web.example.test
A=https://auth.example.test
status() { "${C[@]}" -o /dev/null -w '%{http_code}' "$@"; }
hdr() { sed -n "s/^$1: //Ip" | tr -d '\r'; }

# sign_in <method> <jar>: a browser's provider sign-in for $W/docs; prints
# the portal's answer to the provider callback (headers and body).
sign_in() {
	local m=$1 jar=$2 n loc cb
	rm -f "$jar"
	n=$("${C[@]}" -c "$jar" -b "$jar" -I "$W/docs" | sed -n 's/^location: .*[?&]n=\([A-Za-z0-9_-]*\).*/\1/Ip' | tr -d '\r')
	loc=$("${C[@]}" -c "$jar" -b "$jar" -i -X POST "$A/oauth/start" -H "Origin: $A" --data-urlencode "provider=$m" \
		--data-urlencode app=web --data-urlencode "rd=$W/docs" --data-urlencode "n=$n" | hdr location)
	# The provider: the fake signs the configured user in at once.
	cb=$(in_edge curl -sS -o /dev/null -w '%{redirect_url}' "$loc")
	"${C[@]}" -c "$jar" -b "$jar" -i "$cb"
	echo "CB=$cb"
}

# 1. Login page offers the app's providers and no email form.
N0=$("${C[@]}" -I "$W/docs" | sed -n 's/^location: .*[?&]n=\([A-Za-z0-9_-]*\).*/\1/Ip' | tr -d '\r')
PAGE=$("${C[@]}" -i "$A/login?app=web&rd=$W/docs&n=$N0")
for p in Discord Google Steam; do
	[[ $PAGE == *"Continue with $p"* ]] && pass "login page offers $p" || fail "no $p button: ${PAGE:0:300}"
done
[[ $PAGE != *'value="email"'* ]] && pass "no email form for a providers-only app" || fail "email form shown"
[[ $PAGE == *"form-action 'self' http://127.0.0.1:9900"* ]] && pass "CSP lets the provider buttons redirect" || fail "CSP: $(hdr content-security-policy <<<"$PAGE")"
expect "cross-site start rejected" "403" status -X POST "$A/oauth/start" -H "Origin: https://evil.test" -d provider=discord -d app=web -d "rd=$W/docs"
expect "start with a foreign return URL rejected" "400" status -X POST "$A/oauth/start" -H "Origin: $A" -d provider=discord -d app=web -d "rd=https://evil.test/"

# 2. Discord: member with the role gets in; identity reaches the origin.
fake_user discord "{\"sub\":\"300000000000000003\",\"username\":\"ann\",\"email\":\"ann@mail.test\",\"email_verified\":true,\"guilds\":[\"$GUILD\"],\"members\":{\"$GUILD\":[\"$ROLE\"]}}"
OUT=$(sign_in discord "$TMP/d.jar")
APPCB=$(hdr location <<<"$OUT")
[[ $APPCB == "$W/.ingressd/callback?code="* ]] && pass "discord sign-in redirects to the app callback" || fail "discord: ${OUT:0:400}"
expect "app callback sets the app cookie" "__edge_web=" "${C[@]}" -c "$TMP/d.jar" -b "$TMP/d.jar" -i "$APPCB"
expect "discord member reaches the app" "X-Edge-User-Email: ann@mail.test" "${C[@]}" -b "$TMP/d.jar" "$W/docs"
expect "X-Edge-User set" "X-Edge-User: ann@mail.test" "${C[@]}" -b "$TMP/d.jar" "$W/docs"
CB=$(sed -n 's/^CB=//p' <<<"$OUT")
expect "provider callback is single use (flow cookie consumed)" "400" status -b "$TMP/d.jar" "$CB"
expect "provider callback from another browser rejected" "400" status "$CB"

# 3. Discord user without the role: denied at the portal.
fake_user discord "{\"sub\":\"300000000000000004\",\"username\":\"bob\",\"guilds\":[\"$GUILD\"],\"members\":{\"$GUILD\":[]}}"
OUT=$(sign_in discord "$TMP/d2.jar")
[[ $OUT == *"HTTP/"*" 403"* && $OUT == *"is not allowed"* ]] && pass "discord user without the role denied" || fail "role check: ${OUT:0:400}"

# 4. Steam: no email; the owned app decides; facts checked at the edge.
fake_user steam "{\"steam_id\":\"$STEAMID\",\"steam_apps\":[440]}"
OUT=$(sign_in steam "$TMP/s.jar")
APPCB=$(hdr location <<<"$OUT")
[[ $APPCB == "$W/.ingressd/callback?code="* ]] && pass "steam sign-in redirects to the app callback" || fail "steam: ${OUT:0:400}"
"${C[@]}" -c "$TMP/s.jar" -b "$TMP/s.jar" -o /dev/null "$APPCB"
expect "steam user reaches the app" "X-Edge-User: steam:$STEAMID" "${C[@]}" -b "$TMP/s.jar" "$W/docs"
if "${C[@]}" -b "$TMP/s.jar" "$W/docs" | grep -qi "x-edge-user-email"; then fail "steam user got an email header"; else pass "no email header for a steam user"; fi
expect "sessions list shows the steam user" "steam:$STEAMID" he sessions list
fake_user steam "{\"steam_id\":\"$STEAMID\",\"steam_apps\":[570]}"
OUT=$(sign_in steam "$TMP/s2.jar")
[[ $OUT == *"HTTP/"*" 403"* ]] && pass "steam user without the game denied" || fail "steam app check: ${OUT:0:300}"

# 5. Google: Workspace domain; a consumer account is denied.
fake_user google '{"sub":"1001","email":"ann@corp.example","email_verified":true,"hd":"corp.example"}'
OUT=$(sign_in google "$TMP/g.jar")
[[ $(hdr location <<<"$OUT") == "$W/.ingressd/callback?code="* ]] && pass "google workspace user allowed" || fail "google: ${OUT:0:400}"
fake_user google '{"sub":"1002","email":"eve@gmail.test","email_verified":true}'
OUT=$(sign_in google "$TMP/g2.jar")
[[ $OUT == *"HTTP/"*" 403"* ]] && pass "google account outside the workspace denied" || fail "google hd: ${OUT:0:300}"
# A forged ID token (bad signature) is refused.
in_edge curl -sS -X PUT --data '{"bad_signature":true}' http://127.0.0.1:9900/_fake/knobs >/dev/null
fake_user google '{"sub":"1001","email":"ann@corp.example","email_verified":true,"hd":"corp.example"}'
OUT=$(sign_in google "$TMP/g3.jar")
[[ $OUT == *"Sign-in failed"* ]] && pass "ID token with a bad signature refused" || fail "bad signature: ${OUT:0:300}"
in_edge curl -sS -X PUT --data '{}' http://127.0.0.1:9900/_fake/knobs >/dev/null

# 6. Header token.
expect "header token accepted" "X-Edge-Service-Token: bot" "${C[@]}" -H "X-Bot-Token: bot-token-0123456789abcdef" "$W/api/x"
if "${C[@]}" -H "X-Bot-Token: bot-token-0123456789abcdef" "$W/api/x" | grep -qi "bot-token"; then
	fail "header token reached the origin"
else pass "header token stripped before the origin"; fi
expect "wrong header token rejected" "401" status -H "X-Bot-Token: bot-token-0123456789abcdeX" "$W/api/x"
expect "no header token: sign-in required" "302" status "$W/api/x"

finish
