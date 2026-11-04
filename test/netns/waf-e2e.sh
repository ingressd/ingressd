#!/usr/bin/env bash
# e2e waf: edge security. WAF block/detect modes and a scoped
# exclusion created from a WAF event, rate limiting, IP deny lists, and the
# proof-of-work bot challenge, all configured through the ingressd CLI.
set -euo pipefail
P=he-p8
source "$(dirname "$0")/lib.sh"

build_topology
lan_http 8080 "hello from lan"
echo "search results" >"$TMP/www-8080/search"
start_edge_proxy

mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  acme: { ca: internal }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
apps:
  shop:
    hosts: [shop.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    waf:
      mode: block
      paranoia: 1
      exclusions:
#EXCLUSIONS
    rate_limit: [{ match: /login, requests: 3, per: 1m }]
  docs:
    hosts: [docs.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    waf: { mode: detect }
  bots:
    hosts: [bots.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    bot_challenge: { mode: always, difficulty: 12 }
  private:
    hosts: [private.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    security: { ip_deny: [198.51.100.0/30] }
EOF

he init >/dev/null
expect "apply succeeds" "Applied." he apply --author e2e -m "Security config"
connect_site home
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true

RESOLVE=()
for h in shop docs bots private; do RESOLVE+=(--resolve "$h.example.test:443:198.51.100.1"); done
CURL=(in_client curl -sS --max-time 5 -k "${RESOLVE[@]}")
code() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@"; }
BROWSER=(-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'
	-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-GB,en;q=0.5')
SQLI="q=1%27%20OR%20%271%27%3D%271"
XSS="q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# --- WAF ---
expect "normal browsing passes WAF at PL1" "hello from lan" "${CURL[@]}" "${BROWSER[@]}" "https://shop.example.test/?page=2&sort=price"
expect "SQLi probe blocked in block mode" "403" code "${BROWSER[@]}" "https://shop.example.test/search?$SQLI"
expect "XSS probe blocked in block mode" "403" code "${BROWSER[@]}" "https://shop.example.test/?$XSS"
expect "XSS probe passes in detect mode" "hello from lan" "${CURL[@]}" "${BROWSER[@]}" "https://docs.example.test/?$XSS"
expect "detect-mode event in audit log" "detect" he waf events --app docs
expect "block-mode event listed" "block" he waf events --app shop
expect "events as JSON" '"blocked":true' he waf events --app shop --json

# Treat the SQLi match on /search as a false positive: turn the event into
# an exclusion with suggest-exclusion, apply it, and check it is scoped.
ID=$(he waf events --app shop --json | grep '"uri":"/search' | tail -1 | sed 's/.*"id":"\([^"]*\)".*/\1/')
[[ -n $ID ]] && pass "found WAF event $ID" || fail "no WAF event for /search"
he waf suggest-exclusion "$ID" >"$TMP/excl.yaml" || true
expect "suggestion names the SQLi rule" "rule: 942100, path: /search, target: ARGS:q" cat "$TMP/excl.yaml"
grep '^        - {' "$TMP/excl.yaml" >"$TMP/excl-items.yaml" || true
sed -i "/^#EXCLUSIONS/r $TMP/excl-items.yaml" "$TMP/conf/config.yaml"
expect "config with exclusion is valid" "is valid" he validate
expect "apply exclusion" "Applied." he apply --author e2e -m "WAF exclusion"
expect "exclusion lets the false positive through" "search results" "${CURL[@]}" "${BROWSER[@]}" "https://shop.example.test/search?$SQLI"
expect "exclusion is scoped to its path" "403" code "${BROWSER[@]}" "https://shop.example.test/other?$SQLI"

# --- Rate limiting ---
for _ in 1 2 3; do code "${BROWSER[@]}" https://shop.example.test/login >/dev/null; done
expect "rate limit returns 429" "429" code "${BROWSER[@]}" https://shop.example.test/login
expect "429 carries Retry-After" "retry-after:" "${CURL[@]}" "${BROWSER[@]}" -I https://shop.example.test/login
expect "other paths are not rate limited" "200" code "${BROWSER[@]}" https://shop.example.test/

# --- IP rules ---
expect "IP deny list blocks the client" "403" code "${BROWSER[@]}" https://private.example.test/

# --- Bot challenge ---
"${CURL[@]}" -c "$TMP/jar" -b "$TMP/jar" https://bots.example.test/page >"$TMP/challenge.html" || true
expect "curl gets the interstitial" "Checking your browser" cat "$TMP/challenge.html"
expect "interstitial has a noscript message" "<noscript>" cat "$TMP/challenge.html"
expect "interstitial status is 403" "403" code https://bots.example.test/page
TOKEN=$(sed -n 's/.*name="token" value="\([^"]*\)".*/\1/p' "$TMP/challenge.html")
BITS=$(sed -n 's/.*data-difficulty="\([0-9]*\)".*/\1/p' "$TMP/challenge.html")
NONCE=$(python3 - "$TOKEN" "$BITS" <<'PY'
import hashlib, sys
token, bits = sys.argv[1], int(sys.argv[2])
i = 0
while int.from_bytes(hashlib.sha256((token + str(i)).encode()).digest(), "big") >> (256 - bits):
    i += 1
print(i)
PY
)
expect "solved challenge sets clearance cookie" "__edge_clearance" "${CURL[@]}" -c "$TMP/jar" -b "$TMP/jar" -i \
	--data-urlencode "token=$TOKEN" --data-urlencode "nonce=$NONCE" --data-urlencode "return=/page" \
	https://bots.example.test/.edge/challenge/verify
expect "clearance cookie passes the challenge" "hello from lan" "${CURL[@]}" -b "$TMP/jar" https://bots.example.test/
expect "wrong nonce gets a fresh challenge" "Checking your browser" "${CURL[@]}" \
	--data-urlencode "token=$TOKEN" --data-urlencode "nonce=x" https://bots.example.test/.edge/challenge/verify
expect "challenge key stored in secrets" "edge_challenge_key" he secret list

# --- GeoIP: no MaxMind credentials configured, so updates are skipped ---
expect "geoip update skips without credentials" "Skipped" he geoip update

expect "re-apply is a no-op" "No changes to apply." he apply --author e2e

finish
