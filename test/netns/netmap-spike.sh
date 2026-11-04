#!/usr/bin/env bash
# Spike: reach two sites that both use 192.168.0.0/24 from the edge, by giving
# each tunnel a virtual prefix (10.201.0.0/24, 10.202.0.0/24) and using fwmark
# policy routing plus nftables prefix DNAT. See docs/spikes/03-netmap.md.
#
# Topology (all network namespaces, real WireGuard):
#
#   edge ──wan-a── site-a (router) ──lan── lan-a 192.168.0.17:8080 "site-a"
#        ──wan-b── site-b (router) ──lan── lan-b 192.168.0.17:8080 "site-b"
#
# Requires root, iproute2, wireguard-tools, nftables, python3, curl.
set -euo pipefail
umask 077 # WireGuard private keys are written to $TMP

P=he-spike
source "$(dirname "$0")/lib.sh" # root check, run-unique $P, $TMP, cleanup
ns_add "$EDGE" "$P-site-a" "$P-lan-a" "$P-site-b" "$P-lan-b"

edge() { ip netns exec "$EDGE" "$@"; }

# Replies from a site arrive with the real (overlapping) source address, which
# has no route in the main table, so strict reverse-path filtering must be off.
edge sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

# setup_site <letter> <n>: builds site router, LAN host and tunnel n.
setup_site() {
	local s=$1 n=$2
	local site=$P-site-$s lan=$P-lan-$s port=$((51819 + n))
	local mark=$((200 + n)) vprefix="10.20$n.0.0/24"

	# WAN link edge <-> site router.
	ip link add "wan-$s" netns "$EDGE" type veth peer name wan netns "$site"
	ip -n "$EDGE" addr add "172.16.$n.1/30" dev "wan-$s"
	ip -n "$site" addr add "172.16.$n.2/30" dev wan
	ip -n "$EDGE" link set "wan-$s" up
	ip -n "$site" link set wan up

	# Identical LAN behind each site.
	ip link add lan netns "$site" type veth peer name eth0 netns "$lan"
	ip -n "$site" addr add 192.168.0.1/24 dev lan
	ip -n "$lan" addr add 192.168.0.17/24 dev eth0
	ip -n "$site" link set lan up
	ip -n "$lan" link set eth0 up
	ip -n "$lan" route add default via 192.168.0.1
	ip netns exec "$site" sysctl -qw net.ipv4.ip_forward=1

	# WireGuard; the site dials the edge, as in production.
	wg genkey >"$TMP/edge-$s.key"
	wg genkey >"$TMP/site-$s.key"
	ip -n "$EDGE" link add "wg-$s" type wireguard
	ip -n "$site" link add wg0 type wireguard
	edge wg set "wg-$s" private-key "$TMP/edge-$s.key" listen-port "$port" \
		peer "$(wg pubkey <"$TMP/site-$s.key")" allowed-ips "10.100.$n.2/32,192.168.0.0/24"
	ip netns exec "$site" wg set wg0 private-key "$TMP/site-$s.key" \
		peer "$(wg pubkey <"$TMP/edge-$s.key")" allowed-ips "10.100.$n.0/24" \
		endpoint "172.16.$n.1:$port" persistent-keepalive 25
	ip -n "$EDGE" addr add "10.100.$n.1/24" dev "wg-$s"
	ip -n "$site" addr add "10.100.$n.2/24" dev wg0
	ip -n "$EDGE" link set "wg-$s" up
	ip -n "$site" link set wg0 up

	# Origin that answers with its site name.
	mkdir -p "$TMP/www-$s"
	echo "site-$s" >"$TMP/www-$s/index.html"
	ip netns exec "$lan" python3 -m http.server 8080 --bind 0.0.0.0 --directory "$TMP/www-$s" >/dev/null 2>&1 &
	PIDS+=($!)

	# Edge routing: the main-table route lets sockets connect to the virtual
	# prefix (and picks 10.100.n.1 as source); after DNAT the fwmark selects
	# a per-tunnel table that knows where the real subnet lives.
	ip -n "$EDGE" route add "$vprefix" dev "wg-$s"
	ip -n "$EDGE" route add 192.168.0.0/24 dev "wg-$s" table "$mark"
	ip -n "$EDGE" rule add fwmark "$mark" table "$mark" priority "$mark"

	# Bring the tunnel up from the site side.
	ip netns exec "$site" ping -c1 -W2 "10.100.$n.1" >/dev/null || true
}

setup_site a 1
setup_site b 2

edge nft -f - <<'EOF'
table ip ingressd_spike {
	map vprefix_mark {
		type ipv4_addr : mark
		flags interval
		elements = { 10.201.0.0/24 : 201, 10.202.0.0/24 : 202 }
	}

	# Mark locally generated traffic (from Caddy) by virtual prefix.
	chain output_route {
		type route hook output priority mangle; policy accept;
		meta mark set ip daddr map @vprefix_mark
	}

	# Translate virtual prefix -> real site subnet, host part preserved.
	chain output_nat {
		type nat hook output priority -100; policy accept;
		dnat ip prefix to ip daddr map { 10.201.0.0/24 : 192.168.0.0/24, 10.202.0.0/24 : 192.168.0.0/24 }
	}
}
EOF

fail=0
check() {
	local url=$1 want=$2 got=""
	for _ in 1 2 3 4 5; do
		got=$(edge curl -s --max-time 2 "$url" || true)
		[[ $got == "$want" ]] && break
		sleep 1
	done
	if [[ $got == "$want" ]]; then
		echo "PASS $url -> $got"
	else
		echo "FAIL $url -> '$got' (want $want)"
		fail=1
	fi
}

check http://10.201.0.17:8080/ site-a
check http://10.202.0.17:8080/ site-b

# The real, ambiguous subnet must not be routable from the edge.
if edge curl -s --max-time 2 http://192.168.0.17:8080/ >/dev/null; then
	echo "FAIL 192.168.0.17 is reachable without a virtual prefix"
	fail=1
else
	echo "PASS 192.168.0.17 is not routable from the edge (expected)"
fi

if [[ $fail -ne 0 ]]; then
	echo "--- debug ---"
	edge wg show
	edge ip rule
	edge nft list ruleset
fi
exit "$fail"
