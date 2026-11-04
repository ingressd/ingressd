#!/usr/bin/env bash
# e2e cache: response caching (hits, stale-if-error, purge) and
# Always Online snapshots (crawl, fallback with banner, static_mirror).
set -euo pipefail
P=he-p9
source "$(dirname "$0")/lib.sh"

build_topology

# A small multi-page site on the LAN host.
SITE_DIR=$TMP/site
mkdir -p "$SITE_DIR/img" "$SITE_DIR/private"
cat >"$SITE_DIR/index.html" <<'EOF'
<html><head><link rel="stylesheet" href="/style.css"></head>
<body><h1>Home page</h1><a href="/about.html">About</a> <a href="/page.html">Page</a> <a href="/private/secret.html">x</a> <img src="/img/logo.png"></body></html>
EOF
echo '<html><body><p>About us</p></body></html>' >"$SITE_DIR/about.html"
echo '<html><body><p>Page content</p></body></html>' >"$SITE_DIR/page.html"
echo '<html><body><p>Only in sitemap</p></body></html>' >"$SITE_DIR/hidden.html"
echo 'secret' >"$SITE_DIR/private/secret.html"
echo 'body { background: url(/img/bg.png) }' >"$SITE_DIR/style.css"
printf '\x89PNG\r\n\x1a\nlogo' >"$SITE_DIR/img/logo.png"
printf '\x89PNG\r\n\x1a\nbg' >"$SITE_DIR/img/bg.png"
printf 'User-agent: *\nDisallow: /private/\n' >"$SITE_DIR/robots.txt"
cat >"$SITE_DIR/sitemap.xml" <<'EOF'
<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://web.example.test/hidden.html</loc></url></urlset>
EOF

ORIGIN_PID=
origin_start() {
	in_lan python3 -m http.server 8080 --bind 0.0.0.0 --directory "$SITE_DIR" >/dev/null 2>&1 &
	ORIGIN_PID=$!
	PIDS+=("$ORIGIN_PID")
	for _ in $(seq 50); do in_lan curl -s -o /dev/null http://127.0.0.1:8080/ && return; sleep 0.1; done
}
origin_stop() {
	# $ORIGIN_PID is the backgrounded subshell; kill the server itself.
	pkill -f "http.server 8080 --bind 0.0.0.0 --directory $SITE_DIR" || true
	wait "$ORIGIN_PID" 2>/dev/null || true
	for _ in $(seq 50); do in_lan curl -s -o /dev/null http://127.0.0.1:8080/ || return 0; sleep 0.1; done
}

origin_start
# An origin whose responses set a cookie: they must never be cached.
in_lan python3 -c '
import http.server as h
class H(h.BaseHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200); s.send_header("Set-Cookie", "sid=secret"); s.send_header("Content-Type", "text/plain"); s.end_headers(); s.wfile.write(b"cookie page")
    def log_message(s, *a): pass
h.HTTPServer(("0.0.0.0", 8081), H).serve_forever()' >/dev/null 2>&1 &
PIDS+=($!)
start_edge_proxy

mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
access: { portal_host: auth.example.test }
email: { provider: log, log: { path: @TMP@/mail.log } }
policies:
  public: { action: bypass, include: [{ everyone: true }] }
  admins: { action: allow, include: [{ email: [admin@example.test] }] }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
apps:
  web:                     # short TTL so entries go stale quickly
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    access: [public]
    cache: { enabled: true, default_ttl: 2s, stale_if_error: 1h }
    always_online: { enabled: true, banner: true, crawl: { start: [/], keep: 2 } }
  blog:                    # long TTL for hit/purge checks
    hosts: [blog.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    cache: { enabled: true, default_ttl: 10m }
  cookie:
    hosts: [cookie.example.test]
    origin: http://192.168.0.17:8081
    tunnel: home
    cache: { enabled: true, default_ttl: 10m }
  mirror:
    hosts: [mirror.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
    always_online: { enabled: true, mode: static_mirror }
EOF
sed -i "s#@TMP@#$TMP#" "$TMP/conf/config.yaml"

he init >/dev/null
expect "apply succeeds" "Applied." he apply --author e2e -m "First apply"
connect_site home
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true

curl_host() { # curl_host <host> <curl args...>
	local host=$1
	shift
	in_client curl -sS --max-time 5 -k --resolve "$host:443:198.51.100.1" "$@"
}
web() { curl_host web.example.test -i "https://web.example.test$1"; }
blog() { curl_host blog.example.test -i "https://blog.example.test$1"; }
mirror() { curl_host mirror.example.test -i "https://mirror.example.test$1"; }

# --- Cache ---------------------------------------------------------------
expect "origin reachable through edge" "Home page" web /
blog /page.html >/dev/null
expect "second request is a cache hit" "cache-status: ingressd; hit" blog /page.html
if blog /page.html | grep -qi '^set-cookie'; then fail "unexpected cookie"; else pass "no cookies on cached response"; fi
expect "Authorization bypasses the cache" "200" curl_host blog.example.test -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer x' https://blog.example.test/page.html
if curl_host blog.example.test -i -H 'Authorization: Bearer x' https://blog.example.test/page.html | grep -qi 'cache-status: ingressd; hit'; then
	fail "authenticated request served from cache"
else
	pass "authenticated request not served from cache"
fi
cookie() { curl_host cookie.example.test -i "https://cookie.example.test$1"; }
expect "cookie origin reachable" "cookie page" cookie /c
expect "Set-Cookie responses are not stored" "PRIVATE-OR-AUTHENTICATED" cookie /c
if cookie /c | grep -qi 'cache-status: ingressd; hit'; then fail "Set-Cookie response cached"; else pass "Set-Cookie response never a hit"; fi
if blog /souin-api/souin | grep -q '^\['; then fail "cache API exposed publicly"; else pass "cache API not exposed publicly"; fi

# --- Purge ---------------------------------------------------------------
expect "hit before purge" "cache-status: ingressd; hit" blog /page.html
expect "purge by path" "Purged cached responses under /page.html of blog." he cache purge blog --path /page.html
if blog /page.html | grep -qi 'cache-status: ingressd; hit'; then fail "path purge left the entry"; else pass "path purge removed the entry"; fi
expect "re-cached after purge" "cache-status: ingressd; hit" blog /page.html
blog /about.html >/dev/null
expect "about cached" "cache-status: ingressd; hit" blog /about.html
expect "purge all" "Purged all cached responses of blog." he cache purge blog --all
if blog /about.html | grep -qi 'cache-status: ingressd; hit'; then fail "purge --all left an entry"; else pass "purge --all removed entries"; fi
reject "purge needs --path or --all" he cache purge blog

# The on-disk store must survive config reloads (Badger is reopened per load).
blog /page.html >/dev/null
expect "hit before reload" "cache-status: ingressd; hit" blog /page.html
sed -i 's/default_ttl: 10m/default_ttl: 11m/' "$TMP/conf/config.yaml"
expect "apply with changed cache config" "Applied." he apply --author e2e -m "Change TTL"
expect "cache entries survive a config reload" "cache-status: ingressd; hit" blog /page.html
if ls "$TMP"/state/cache/*.vlog >/dev/null 2>&1; then pass "cache stored on disk under state-dir/cache"; else fail "no Badger files in $TMP/state/cache"; fi
reject "purge refuses app without cache" he cache purge mirror --all

# --- Snapshot ------------------------------------------------------------
expect "snapshot now crawls the site" "Snapshot " he snapshot now web
expect "snapshot list shows latest" "latest" he snapshot list web
SNAP=$(readlink "$TMP/state/snapshots/web/latest")
for f in / /about.html /style.css /img/logo.png /img/bg.png /hidden.html; do
	if grep -q "\"$f\"" "$TMP/state/snapshots/web/$SNAP/manifest.json"; then pass "snapshot has $f"; else fail "snapshot lacks $f"; fi
done
if grep -q '"/private/secret.html"' "$TMP/state/snapshots/web/$SNAP/manifest.json"; then fail "robots.txt ignored"; else pass "robots.txt respected"; fi

# --- Origin down: stale cache first, then snapshot ------------------------
web /page.html >/dev/null           # store
sleep 3                             # older than default_ttl (2s): stale
origin_stop
OUT=$(web /page.html || true)
if [[ $OUT == *"Page content"* && ${OUT,,} == *"fwd=stale"* && ${OUT,,} != *"x-edge-served-from"* ]]; then
	pass "cached page served stale while origin is down"
else
	fail "stale cache: ${OUT:0:500}"
fi
expect "uncached page served from snapshot" "x-edge-served-from: snapshot" web /about.html
expect "snapshot page has the banner" "temporarily offline" web /about.html
expect "snapshot page content" "About us" web /about.html
expect "snapshot CSS content type" "content-type: text/css" web /style.css
expect "snapshot image content type" "content-type: image/png" web /img/logo.png
expect "sitemap-only page in snapshot" "Only in sitemap" web /hidden.html
expect "directory index from snapshot" "Home page" web /
expect "unknown page is a snapshot 404" "HTTP/2 404" web /nope.html
expect "disallowed page not in snapshot" "HTTP/2 404" web /private/secret.html

# --- Origin back: live again ---------------------------------------------
origin_start
expect "live response after origin returns" "About us" web /about.html
OUT=$(web /about.html)
if [[ ${OUT,,} == *"x-edge-served-from"* || $OUT == *"temporarily offline"* ]]; then fail "still serving snapshot: ${OUT:0:300}"; else pass "origin back: live, no banner"; fi

# --- static_mirror, snapshotted by serve's scheduler ---------------------
expect "mirror is live before its first snapshot" "Home page" mirror /
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve snapshots apps without a snapshot" "latest" he snapshot list mirror
expect "static_mirror serves the snapshot while origin is up" "x-edge-served-from: snapshot" mirror /about.html
if mirror /about.html | grep -q 'temporarily offline'; then fail "static_mirror shows offline banner"; else pass "static_mirror has no banner"; fi

# --- Validation ----------------------------------------------------------
mkdir -p "$TMP/bad"
sed 's/access: \[public\]/access: [admins]/' "$TMP/conf/config.yaml" >"$TMP/bad/config.yaml"
OUT=$("$BIN/ingressd" --config-dir "$TMP/bad" validate 2>&1 || true)
if [[ $OUT == *"apps.web.always_online: only allowed for public apps"* ]]; then
	pass "always_online on a protected app fails validation"
else
	fail "protected app validation: $OUT"
fi

finish
