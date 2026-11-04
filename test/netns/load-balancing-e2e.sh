#!/usr/bin/env bash
# e2e load-balancing: a load-balanced pool across two sites. Checks weighted
# splitting, sticky sessions, drain, forced tiers, failover when the
# priority-1 origins stop, failback after the hold, and instant failover
# when a tunnel goes down. Health checks run inside `ingressd serve` and
# reach Caddy through the edge_state admin API.
#
#   client ── edge ──wg ix-home── site (router) ── lan 192.168.0.17 (a), .18 (b)
#               └────wg ix-cloud─ site2 (router + 10.0.1.5 (c))
set -euo pipefail
P=he-p6
source "$(dirname "$0")/lib.sh"

SITE2=$P-site2
NAMESPACES+=("$SITE2")
in_site2() { ip netns exec "$SITE2" "$@"; }

build_topology
ns_add "$SITE2"
veth "$EDGE" wan1 172.16.2.1/30 "$SITE2" wan0 172.16.2.2/30
ip -n "$SITE2" link add lan0 type dummy
ip -n "$SITE2" addr add 10.0.1.5/24 dev lan0
ip -n "$SITE2" link set lan0 up
ip -n "$LAN" addr add 192.168.0.18/24 dev eth0

# serve_origin <name> <netns> <ip>: HTTP server answering "origin-<name>".
declare -A ORIGIN_PID
serve_origin() {
	local dir=$TMP/www-$1
	mkdir -p "$dir"
	echo "origin-$1" >"$dir/index.html"
	ip netns exec "$2" python3 -m http.server 8080 --bind "$3" --directory "$dir" >/dev/null 2>&1 &
	ORIGIN_PID[$1]=$!
	PIDS+=($!)
}
stop_origin() { kill "${ORIGIN_PID[$1]}" 2>/dev/null || true; wait "${ORIGIN_PID[$1]}" 2>/dev/null || true; }
serve_origin a "$LAN" 192.168.0.17
serve_origin b "$LAN" 192.168.0.18
serve_origin c "$SITE2" 10.0.1.5
start_edge_proxy

mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
  cloud:
    site: router
    listen_port: 51821
    transit: 10.100.2.0/24
    subnets: [10.0.1.0/24]
pools:
  web:
    steering: weighted
    sticky: { cookie: edge_aff, ttl: 1h }
    failback: auto
    failback_hold: 5s
    health: { path: /, interval: 1s, timeout: 500ms, unhealthy_after: 2, healthy_after: 2 }
    origins:
      - { name: a, tunnel: home,  address: http://192.168.0.17:8080, weight: 3, priority: 1 }
      - { name: b, tunnel: home,  address: http://192.168.0.18:8080, weight: 1, priority: 1 }
      - { name: c, tunnel: cloud, address: http://10.0.1.5:8080, priority: 2 }
apps:
  web:
    hosts: [web.example.test]
    pool: web
EOF

he init >/dev/null
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "serve applies the pool config" "Applied." cat "$TMP/serve.log"

connect_site home
he tunnel config cloud --format wg --endpoint 172.16.2.1 >"$TMP/site-cloud.conf"
ip -n "$SITE2" link add wg0 type wireguard
in_site2 wg setconf wg0 "$TMP/site-cloud.conf"
ip -n "$SITE2" addr add 10.100.2.2/24 dev wg0
ip -n "$SITE2" link set wg0 up
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true
in_site2 ping -c1 -W2 10.100.2.1 >/dev/null || true

CURL=(in_client curl -sk --max-time 3 --resolve web.example.test:443:198.51.100.1 https://web.example.test/)

# within <description> <seconds> <command...>: passes once the command succeeds.
within() {
	local desc=$1 secs=$2 end
	shift 2
	end=$((SECONDS + secs))
	while ((SECONDS < end)); do
		if "$@" >/dev/null 2>&1; then pass "$desc"; return 0; fi
		sleep 0.5
	done
	fail "$desc (not within ${secs}s)"
	return 1
}

# dist <n>: sends n cookie-less requests and prints "a=.. b=.. c=.. err=..".
dist() {
	local a=0 b=0 c=0 err=0 out
	for _ in $(seq "$1"); do
		out=$("${CURL[@]}" 2>/dev/null || true)
		case $out in
		origin-a) a=$((a + 1)) ;;
		origin-b) b=$((b + 1)) ;;
		origin-c) c=$((c + 1)) ;;
		*) err=$((err + 1)) ;;
		esac
	done
	echo "a=$a b=$b c=$c err=$err"
}
# only <origins-regex> <n>: all of n requests went to matching origins.
only() {
	local d
	d=$(dist "$2")
	echo "$d"
	local IFS=' '
	for kv in $d; do
		[[ ${kv#*=} == 0 || ${kv%%=*} =~ ^($1)$ ]] || return 1
	done
}
status() { he pool status web; }
tier1_up() { status | grep -q "active tier 1" && ! status | grep -qE "DOWN|failing back"; }

within "pool healthy on tier 1" 30 tier1_up
within "tier 1 serves traffic" 15 only "a|b" 4

# Weighted 3:1 split (smooth weighted round robin: exactly 30/10 without retries).
D=$(dist 40)
read -r A B C ERR < <(sed -E 's/[a-z]+=//g' <<<"$D")
if ((A >= 26 && A <= 34 && B >= 6 && B <= 14 && C == 0 && ERR == 0)); then pass "weighted split 3:1 ($D)"; else fail "weighted split 3:1: $D"; fi

# Sticky: a cookie jar keeps one origin.
JAR=$TMP/jar
first=$("${CURL[@]}" -c "$JAR" -b "$JAR")
grep -q edge_aff "$JAR" && pass "sticky cookie set" || fail "sticky cookie set"
same=1
for _ in $(seq 10); do
	[[ $("${CURL[@]}" -c "$JAR" -b "$JAR") == "$first" ]] || same=0
done
((same)) && pass "sticky cookie pins $first" || fail "sticky cookie did not pin $first"

# Drain: pin a session to a, drain a; new sessions avoid a, the pinned one stays.
AJAR=$TMP/jar-a
for _ in $(seq 10); do
	rm -f "$AJAR"
	[[ $("${CURL[@]}" -c "$AJAR" -b "$AJAR") == origin-a ]] && break
done
expect "drain command" "now draining" he pool drain web a --reason e2e
within "drained origin gets no new sessions" 10 only "b" 8
expect "sticky session continues on draining origin" "origin-a" "${CURL[@]}" -c "$AJAR" -b "$AJAR"
expect "status shows runtime drain" "draining (runtime)" status
expect "enable command" "enabled" he pool enable web a
a_in_rotation() { [[ $(dist 8) != a=0* ]]; }
within "enabled origin back in rotation" 10 a_in_rotation

# Override: force tier 2, then clear.
expect "override command" "forced to tier 2" he pool override web --tier 2 --for 10m
within "override forces tier 2" 10 only "c" 6
expect "status shows override banner" "OVERRIDE: forced to tier 2" status
expect "clear-override command" "cleared" he pool clear-override web
within "traffic returns after clearing override" 10 only "a|b" 6

# Failover: stop both priority-1 origins.
stop_origin a
stop_origin b
t0=$SECONDS
if within "failover to tier 2 when priority-1 origins stop" 15 only "c" 4; then
	echo "     (failover took $((SECONDS - t0))s)"
fi
expect "status shows tier 2" "active tier 2" status
expect "pool_failover event recorded" '"type": "pool_failover"' cat "$TMP/state/pool-health.json"

# Failback after the hold (5s), not before.
serve_origin a "$LAN" 192.168.0.17
serve_origin b "$LAN" 192.168.0.18
failback_pending() { status | grep -q "failing back to tier 1"; }
within "failback pending while tier 1 is held" 15 failback_pending
D=$(dist 4)
[[ $D == "a=0 b=0 c=4 err=0" ]] && pass "still on tier 2 during failback hold" || fail "still on tier 2 during failback hold: $D"
# Caddy's passive health may still hold a/b out for up to 30s after their failures.
within "failback to tier 1 after hold" 40 only "a|b" 6
expect "pool_failback event recorded" '"type": "pool_failback"' cat "$TMP/state/pool-health.json"

# Tunnel down: the home interface disappears; origins on it are down at once.
in_edge ip link del ix-home
t0=$SECONDS
within "tunnel down fails over to tier 2" 8 only "c" 4
echo "     (tunnel failover took $((SECONDS - t0))s)"
expect "status names the tunnel" "tunnel home down" status
expect "tunnel_down event recorded" '"type": "tunnel_down"' cat "$TMP/state/pool-health.json"
expect "re-apply restores the tunnel" "Applied." he apply --force --author e2e -m "Restore tunnel"
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true
within "tier 1 back after tunnel recovery" 45 only "a|b" 4

# The edge state is visible through Caddy's admin API.
expect "edge_state API serves pool state" '"pools"' in_edge curl -s --unix-socket "$TMP/run/caddy-admin.sock" http://localhost/ingressd/state

if [[ $FAIL -ne 0 ]]; then
	echo "--- pool status ---"
	status || true
	echo "--- serve log (tail) ---"
	tail -40 "$TMP/serve.log" || true
fi
finish
