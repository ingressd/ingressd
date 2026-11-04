# shellcheck shell=bash
# Shared helpers for the netns end-to-end tests. Source from a test script
# after setting P (the suite's short name, e.g. P=he-p1).
#
# Standard topology built by build_topology:
#
#   client 198.51.100.2 ──── 198.51.100.1 edge 172.16.1.1 ──── 172.16.1.2 site (router)
#                                                                   │ 192.168.0.1
#                                                               lan 192.168.0.17
#
# Parallel-safe conventions (see docs/TESTING.md, "Writing a suite"):
#   - Sourcing this file appends the run ID to P (P=he-p1 -> he-p1-3fa9c2).
#     Name every namespace "$P-<role>" and create extra ones with ns_add,
#     which registers them for cleanup. Never hard-code a namespace name.
#   - Everything a suite starts runs inside one of its namespaces (in_*,
#     ip netns exec, ip -n). Nothing binds a port or adds a link, nft table,
#     ip rule or route in the root namespace. Interface names only have to
#     be unique inside their namespace (max 15 characters).
#   - Files go under $TMP (mktemp -d below $TMPDIR), never fixed /tmp paths.
#     /etc/netns/<ns> is only written for the suite's own namespaces;
#     cleanup removes it.
#   - cleanup runs on EXIT and on INT/TERM/HUP: it runs the on_cleanup hooks,
#     kills every process inside the run's namespaces (TERM, then KILL after
#     2s; this includes setsid'd daemons and private mount namespaces
#     entered with nsenter), deletes the namespaces, their /etc/netns
#     entries and $TMP. scripts/e2e.sh additionally reaps any namespace
#     whose name contains "-$E2E_RUN-" after the suite exits.

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for bin in ip wg nft python3 curl; do
	command -v "$bin" >/dev/null || { echo "missing $bin" >&2; exit 1; }
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BIN=${BIN:-$ROOT/bin}
# The suites run `ingressd init` (git init): never let them act on a caller's repo.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY
# E2E_RUN ([a-z0-9], up to 8 characters) makes every name of this run unique.
# scripts/e2e.sh sets it so it can reap leftovers; standalone runs pick one.
E2E_RUN=${E2E_RUN:-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')}
P=$P-$E2E_RUN
EDGE=$P-edge SITE=$P-site LAN=$P-lan CLIENT=$P-client
NAMESPACES=("$EDGE" "$SITE" "$LAN" "$CLIENT")
# $TMP must be reachable by every user (connector-transports runs the connector as nobody
# on files below it): if a directory above $TMPDIR is closed to others (a CI
# runner's temp below a mode 750 home, say), use /tmp instead.
_tmp_base=${TMPDIR:-/tmp}
_d=$_tmp_base
while [[ $_d != / && $_d != . ]]; do
	if [[ ! -d $_d ]] || (((8#$(stat -c %a "$_d") & 1) == 0)); then
		echo "lib.sh: $_tmp_base is not traversable by other users; using /tmp" >&2
		_tmp_base=/tmp
		break
	fi
	_d=$(dirname "$_d")
done
TMP=$(mktemp -d "$_tmp_base/ingressd-e2e.XXXXXX")
unset _tmp_base _d
chmod 755 "$TMP"
PIDS=()
CLEANUP_HOOKS=()
FAIL=0

in_edge() { ip netns exec "$EDGE" "$@"; }
in_site() { ip netns exec "$SITE" "$@"; }
in_lan() { ip netns exec "$LAN" "$@"; }
in_client() { ip netns exec "$CLIENT" "$@"; }

# ns_pids: every process inside the run's namespaces.
ns_pids() {
	local ns
	for ns in "${NAMESPACES[@]}"; do ip netns pids "$ns" 2>/dev/null || true; done
}

# kill_ns_procs: TERM everything inside the run's namespaces plus our own
# background jobs, wait up to 2s, then KILL whatever is left.
kill_ns_procs() {
	local pids sig
	for sig in TERM KILL; do
		pids="$(ns_pids) ${PIDS[*]} $(jobs -p 2>/dev/null)"
		[[ -z ${pids// /} ]] && return 0
		# shellcheck disable=SC2086
		kill -"$sig" $pids 2>/dev/null || true
		[[ $sig == KILL ]] && break
		for _ in $(seq 20); do [[ -z $(ns_pids) ]] && break; sleep 0.1; done
	done
}

# on_cleanup <command>: runs <command> (eval) first thing in cleanup.
on_cleanup() { CLEANUP_HOOKS+=("$1"); }

CLEANED=0
cleanup() {
	[[ $CLEANED == 1 ]] && return
	CLEANED=1
	set +e
	trap '' INT TERM HUP
	local h ns
	for h in "${CLEANUP_HOOKS[@]}"; do eval "$h"; done
	kill_ns_procs
	wait 2>/dev/null
	for ns in "${NAMESPACES[@]}"; do
		[[ -n $ns ]] || continue
		# shellcheck disable=SC2046
		kill -KILL $(ip netns pids "$ns" 2>/dev/null) 2>/dev/null
		ip netns del "$ns" 2>/dev/null
		rm -rf "/etc/netns/$ns"
	done
	rm -rf "$TMP"
}
trap cleanup EXIT
# Ctrl-C or timeout(1) must run cleanup too (bash skips the EXIT trap when
# killed by an untrapped signal).
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ns_add <name>...: (re)creates namespaces with lo up and registers them for
# cleanup. Names must be "$P-<role>".
ns_add() {
	local ns
	for ns in "$@"; do
		[[ $ns == "$P"-* ]] || { echo "ns_add: $ns does not start with \$P-" >&2; exit 1; }
		[[ " ${NAMESPACES[*]} " == *" $ns "* ]] || NAMESPACES+=("$ns")
		# Deleting a namespace does not stop what runs inside it (those
		# processes would become invisible orphans): kill them first.
		# shellcheck disable=SC2046
		kill -KILL $(ip netns pids "$ns" 2>/dev/null) 2>/dev/null || true
		ip netns del "$ns" 2>/dev/null || true
		ip netns add "$ns"
		ip -n "$ns" link set lo up
	done
}

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }

# expect <description> <want-substring> <command...>: retries for ~10s.
expect() {
	local desc=$1 want=$2 got=""
	shift 2
	for _ in $(seq 20); do
		got=$("$@" 2>&1 || true)
		[[ $got == *"$want"* ]] && { pass "$desc"; return; }
		sleep 0.5
	done
	fail "$desc: want '$want', got: ${got:0:400}"
}

# reject <description> <command...>: passes if the command fails.
reject() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

veth() { # veth <ns1> <if1> <addr1> <ns2> <if2> <addr2>
	# Both ends are created directly inside their namespaces: the names never
	# exist in the root namespace, so they cannot collide across runs.
	ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
	ip -n "$1" addr add "$3" dev "$2"
	ip -n "$4" addr add "$6" dev "$5"
	ip -n "$1" link set "$2" up
	ip -n "$4" link set "$5" up
}

build_topology() {
	ns_add "$EDGE" "$SITE" "$LAN" "$CLIENT"
	veth "$CLIENT" eth0 198.51.100.2/30 "$EDGE" pub0 198.51.100.1/30
	veth "$EDGE" wan0 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
	veth "$SITE" lan0 192.168.0.1/24 "$LAN" eth0 192.168.0.17/24
	ip -n "$LAN" route add default via 192.168.0.1
	in_site sysctl -qw net.ipv4.ip_forward=1
}

# lan_http <port> <body>: serves <body> for every GET on the LAN host.
lan_http() {
	local dir=$TMP/www-$1
	mkdir -p "$dir"
	echo "$2" >"$dir/index.html"
	in_lan python3 -m http.server "$1" --bind 0.0.0.0 --directory "$dir" >/dev/null 2>&1 &
	PIDS+=($!)
}

# start_edge_proxy: runs ingressd-edge in the edge namespace.
start_edge_proxy() {
	mkdir -p "$TMP/run" "$TMP/state" "$TMP/xdg"
	cat >"$TMP/bootstrap.json" <<EOF
{"admin": {"listen": "unix/$TMP/run/caddy-admin.sock"}}
EOF
	XDG_DATA_HOME=$TMP/xdg XDG_CONFIG_HOME=$TMP/xdg in_edge "$BIN/ingressd-edge" run --config "$TMP/bootstrap.json" >"$TMP/caddy.log" 2>&1 &
	PIDS+=($!)
	for _ in $(seq 100); do [[ -S $TMP/run/caddy-admin.sock ]] && return; sleep 0.1; done
	echo "ingressd-edge did not start:" >&2
	cat "$TMP/caddy.log" >&2
	exit 1
}

# he <args...>: runs the control plane CLI in the edge namespace with test paths.
he() {
	in_edge "$BIN/ingressd" --config-dir "$TMP/conf" --key "$TMP/keys/age.key" \
		--state-dir "$TMP/state" --run-dir "$TMP/run" "$@"
}

# connect_site <tunnel>: imports the generated config on the site router.
connect_site() {
	he tunnel config "$1" --format wg --endpoint 172.16.1.1 >"$TMP/site-$1.conf"
	local addr
	addr=$(he tunnel config "$1" --endpoint 172.16.1.1 | sed -n 's/^Address = //p')
	ip -n "$SITE" link add wg0 type wireguard
	in_site wg setconf wg0 "$TMP/site-$1.conf"
	ip -n "$SITE" addr add "$addr" dev wg0
	ip -n "$SITE" link set wg0 up
}

finish() {
	if [[ $FAIL -ne 0 ]]; then
		echo "--- caddy log (tail) ---"
		tail -40 "$TMP/caddy.log" 2>/dev/null || true
		echo "--- edge state ---"
		in_edge wg show 2>/dev/null || true
		in_edge ip route 2>/dev/null || true
	fi
	exit "$FAIL"
}
