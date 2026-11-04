#!/usr/bin/env bash
# e2e access-login: Access. A protected app redirects to the login portal;
# the user signs in with an emailed one-time code (email provider "log", so
# the test reads codes from a file); edge_auth sets the app cookie and
# passes identity headers to the origin. Also covers denied emails, OTP
# lockout, bypass paths, service tokens, revocation, header spoofing and
# open-redirect protection.
set -euo pipefail
P=he-p3
source "$(dirname "$0")/lib.sh"

build_topology

# Origin that echoes the request headers it receives.
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
start_edge_proxy

MAIL=$TMP/mail.log
mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
email:
  provider: log
  log: { path: $MAIL }
access:
  portal_host: auth.example.test
  otp: { attempts: 5, resend_cooldown: 1s }
  branding: { name: ingressd E2E }
service_tokens:
  hook: { client_id: hook.access, client_secret: secret://svc_hook }
policies:
  members:
    action: allow
    include: [{ email_domain: [example.test] }]
    session: 1h
  hook:
    action: service_auth
    include: [{ service_token: hook }]
  public:
    action: bypass
    include: [{ everyone: true }]
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
    access: [members]
    paths:
      - { match: /public/*, access: [public] }
      - { match: /hook/*, access: [hook] }
EOF

he init >/dev/null
echo "hook-secret-value" | he secret set svc_hook >/dev/null
expect "apply succeeds" "Applied." he apply --author e2e -m "Access"
expect "access keys generated" "access_session_key" he secret list
connect_site home
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve applies" "Applied." cat "$TMP/serve.log"

JAR=$TMP/jar.txt FORMJAR=$TMP/jar.txt
C=(in_client curl -sS --max-time 5 -k --resolve web.example.test:443:198.51.100.1 --resolve auth.example.test:443:198.51.100.1)
W=https://web.example.test
A=https://auth.example.test
status() { "${C[@]}" -o /dev/null -w '%{http_code}' "$@"; }

# 1. Protected app redirects to the portal, binding the sign-in to this
# browser (nonce cookie on the app host, its hash as n).
expect "unauthenticated request redirects to portal" "location: $A/login?app=web&rd=https%3A%2F%2Fweb.example.test%2Fdocs&n=" \
	"${C[@]}" -c "$JAR" -I "$W/docs"
N=$("${C[@]}" -c "$JAR" -b "$JAR" -I "$W/docs" | sed -n 's/^location: .*[?&]n=\([A-Za-z0-9_-]*\).*/\1/Ip' | tr -d '\r')
[[ ${#N} == 43 ]] && pass "login URL carries the sign-in nonce hash" || fail "no n in login URL: '$N'"
grep -q "__edge_signin_web" "$JAR" && pass "sign-in nonce cookie set on the app host" || fail "no sign-in nonce cookie"
expect "portal shows sign-in form" 'value="email"' "${C[@]}" "$A/login?app=web&rd=$W/docs"
expect "JWKS published" '"alg":"ES256"' "${C[@]}" "$A/.well-known/jwks.json"
expect "open redirect rejected" "400" status "$A/login?app=web&rd=https://evil.test/"
expect "open redirect via lookalike host rejected" "400" status "$A/login?app=web&rd=https://web.example.test.evil.test/"

# 2. Request a code and read it from the mail log.
form() { # form <step> <email> [code]
	"${C[@]}" -c "$FORMJAR" -b "$FORMJAR" -i -X POST "$A/login" -H "Origin: $A" \
		--data-urlencode app=web --data-urlencode "rd=$W/docs" --data-urlencode "n=$N" \
		--data-urlencode "step=$1" --data-urlencode "email=$2" --data-urlencode "code=${3:-}"
}
mail_code() { # mail_code <email>: latest code mailed to email
	awk -v to="To: $1" '$0 == to { want = 1 } want && / is: [0-9]+$/ { code = $NF; want = 0 } END { print code }' "$MAIL" 2>/dev/null
}
wait_code() {
	local c=""
	for _ in $(seq 40); do c=$(mail_code "$1"); [[ -n $c ]] && { echo "$c"; return; }; sleep 0.25; done
}
expect "code requested" "is on its way to" form email alice@example.test
CODE=$(wait_code alice@example.test)
[[ $CODE =~ ^[0-9]{6}$ ]] && pass "6-digit code mailed" || fail "no code in mail log: $(cat "$MAIL" 2>/dev/null)"

# 3. Verify -> callback -> cookie -> app with identity headers.
OUT=$(form code alice@example.test "$CODE")
CB=$(sed -n 's/^location: //Ip' <<<"$OUT" | tr -d '\r')
[[ $CB == "$W/.ingressd/callback?code="* ]] && pass "verify redirects to app callback" || fail "verify: ${OUT:0:400}"
expect "callback from another browser rejected" "403" status "$CB"
expect "callback sets app cookie" "__edge_web=" "${C[@]}" -c "$JAR" -b "$JAR" -i "$CB"
expect "callback code is single use" "403" status "$CB"
expect "app reachable with identity" "X-Edge-User-Email: alice@example.test" "${C[@]}" -b "$JAR" "$W/docs"
expect "JWT assertion injected" "Edge-Jwt-Assertion: ey" "${C[@]}" -b "$JAR" "$W/docs"
expect "spoofed identity header replaced" "X-Edge-User-Email: alice@example.test" \
	"${C[@]}" -b "$JAR" -H "X-Edge-User-Email: mallory@evil.test" "$W/docs"
if "${C[@]}" -b "$JAR" -H "X-Edge-User-Email: mallory@evil.test" "$W/docs" | grep -q mallory; then
	fail "spoofed X-Edge-User-Email reached the origin"
else pass "spoofed X-Edge-User-Email stripped"; fi
if "${C[@]}" -b "$JAR" "$W/docs" | grep -q "__edge_web"; then fail "app cookie forwarded to origin"; else pass "app cookie hidden from origin"; fi
expect "sessions list shows the session" "alice@example.test" he sessions list
expect "policy simulator allows member" "result:   allow (policy members" he access test --app web --email alice@example.test --ip 198.51.100.2
expect "policy simulator denies outsider" "result:   deny" he access test --app web --email eve@other.test

# 4. Disallowed email domain: identical response, but no code is sent and
# no code works. A fresh cookie jar: the portal session would skip the OTP.
FORMJAR=$TMP/jar-others.txt
expect "outsider gets the same response" "is on its way to" form email eve@other.test
sleep 1
[[ -z $(mail_code eve@other.test) ]] && pass "no code mailed to disallowed domain" || fail "code mailed to eve@other.test"
expect "outsider cannot sign in" "invalid or has expired" form code eve@other.test 123456

# 5. Wrong codes lock out, even for the correct code.
expect "code requested for bob" "is on its way to" form email bob@example.test
BOB=$(wait_code bob@example.test)
WRONG=000000; [[ $BOB == "$WRONG" ]] && WRONG=111111
for _ in 1 2 3 4 5; do form code bob@example.test "$WRONG" >/dev/null; done
expect "correct code rejected after lockout" "invalid or has expired" form code bob@example.test "$BOB"
expect "new codes refused during lockout" "Too many sign-in attempts" form email bob@example.test

# 6. Bypass path needs no login; spoofed headers are stripped there too.
expect "bypass path open without login" "path=/public/info" "${C[@]}" "$W/public/info"
expect "ambiguous path refused on an app with path rules" "400" status "$W/public%2f..%2fdocs"
if "${C[@]}" -H "X-Edge-User-Email: mallory@evil.test" "$W/public/info" | grep -qi "x-edge-user-email"; then
	fail "spoofed header reached origin on bypass path"
else pass "spoofed header stripped on bypass path"; fi

# 7. Service token.
expect "service token accepted" "X-Edge-Service-Token: hook" \
	"${C[@]}" -H "Edge-Client-Id: hook.access" -H "Edge-Client-Secret: hook-secret-value" "$W/hook/run"
expect "wrong service secret rejected" "401" status -H "Edge-Client-Id: hook.access" -H "Edge-Client-Secret: nope" "$W/hook/run"
expect "service path without token forbidden" "403" status "$W/hook/run"

# 8. Revocation takes effect within seconds, without a config reload.
expect "still signed in before revoke" "200" status -b "$JAR" "$W/docs"
expect "revoke session" "Revoked 1 session(s)." he sessions revoke --email alice@example.test
expect "revoked session blocked" "302" status -b "$JAR" "$W/docs"

finish
