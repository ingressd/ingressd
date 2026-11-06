#!/usr/bin/env bash
# e2e realms-shaping: per-realm bandwidth caps (realms.<r>.shape). Two
# realms share one edge, each with a router site serving the same file. A
# download from realm A's origin through the edge is held near A's rate,
# realm B (unshaped) is not held by it, a rate change applies in place
# while a transfer is running, and removing the shape removes the devices.
#
#   client 198.51.100.2 ─ 198.51.100.1 edge 172.16.1.1 ─ 172.16.1.2 site A ─ lan A 192.168.1.10
#                                       172.16.2.1 ─ 172.16.2.2 site B ─ lan B 192.168.1.10
set -euo pipefail
P=he-rs
source "$(dirname "$0")/lib.sh"
command -v tc >/dev/null || { echo "missing tc" >&2; exit 1; }

SITEB=$P-siteb LANB=$P-lanb
ns_add "$EDGE" "$CLIENT" "$SITE" "$LAN" "$SITEB" "$LANB"
veth "$CLIENT" eth0 198.51.100.2/30 "$EDGE" pub0 198.51.100.1/30
veth "$EDGE" wana 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$EDGE" wanb 172.16.2.1/30 "$SITEB" wan0 172.16.2.2/30
veth "$SITE" lan0 192.168.1.1/24 "$LAN" eth0 192.168.1.10/24
veth "$SITEB" lan0 192.168.1.1/24 "$LANB" eth0 192.168.1.10/24
for ns in "$SITE" "$SITEB"; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1; done
ip -n "$LAN" route add default via 192.168.1.1
ip -n "$LANB" route add default via 192.168.1.1

# 6 MB: 2.4 s at 20 Mbit/s.
for ns in "$LAN" "$LANB"; do
	mkdir -p "$TMP/www-$ns"
	head -c 6000000 /dev/urandom >"$TMP/www-$ns/blob"
	head -c 15000000 /dev/urandom >"$TMP/www-$ns/big"
	ip netns exec "$ns" python3 -m http.server 5000 --bind 192.168.1.10 --directory "$TMP/www-$ns" >/dev/null 2>&1 &
	PIDS+=($!)
done
start_edge_proxy

write_config() { # write_config <realm A rate in Mbit/s, or none>
	local a="{ shape: { rate_mbit: $1 } }"
	[[ $1 == none ]] && a="{}"
	cat >"$TMP/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 198.51.100.1
  acme: { ca: internal }
security: { tunnel_input: restricted }
realms:
  tq7k2m: $a
  tb4x9p: {}
tunnels:
  tq7k2m01: { realm: tq7k2m, site: router, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24, table: 1201 }
  tb4x9p01: { realm: tb4x9p, site: router, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24, table: 1202 }
apps:
  tq7k2m.files: { realm: tq7k2m, hosts: [files.alice.test], tunnel: tq7k2m01, origin: http://192.168.1.10:5000 }
  tb4x9p.files: { realm: tb4x9p, hosts: [files.bob.test], tunnel: tb4x9p01, origin: http://192.168.1.10:5000 }
EOF
}
mkdir -p "$TMP/conf"
write_config 20
he init >/dev/null
expect "apply shaped realms config" "Applied." he apply --author e2e -m "Shaped realms"

connect() { # connect <ns> <tunnel> <edge wan address>
	local ns=$1 t=$2 ep=$3 addr
	he tunnel config "$t" --format wg --endpoint "$ep" >"$TMP/site-$t.conf"
	addr=$(he tunnel config "$t" --endpoint "$ep" | sed -n 's/^Address = //p')
	ip -n "$ns" link add wg0 type wireguard
	ip netns exec "$ns" wg setconf wg0 "$TMP/site-$t.conf"
	ip -n "$ns" addr add "$addr" dev wg0
	ip -n "$ns" link set wg0 up
}
connect "$SITE" tq7k2m01 172.16.1.1
connect "$SITEB" tb4x9p01 172.16.2.1

curl_host() { # curl_host <host> <path> [curl args...]
	local host=$1 path=$2
	shift 2
	in_client curl -sS --max-time 30 -k --resolve "$host:443:198.51.100.1" "$@" "https://$host$path"
}
expect "realm A origin reachable" "200" curl_host files.alice.test /blob -o /dev/null -w '%{http_code}'
expect "realm B origin reachable" "200" curl_host files.bob.test /blob -o /dev/null -w '%{http_code}'

expect "realm A IFB exists" "ifb-tq7k2m" in_edge ip link show ifb-tq7k2m
expect "realm A IFB tagged as ingressd's" "alias ingressd-shape" in_edge ip link show ifb-tq7k2m
expect "IFB has an HTB root" "qdisc htb 1: root" in_edge tc qdisc show dev ifb-tq7k2m
expect "IFB class at 20 Mbit" "rate 20Mbit" in_edge tc class show dev ifb-tq7k2m
expect "IFB leaf is fq_codel" "qdisc fq_codel 10: parent 1:10" in_edge tc qdisc show dev ifb-tq7k2m
expect "tunnel A ingress redirected to the IFB" "Redirect to device ifb-tq7k2m" in_edge tc filter show dev ix-tq7k2m01 ingress
expect "tunnel A egress shaped" "rate 20Mbit" in_edge tc class show dev ix-tq7k2m01
if in_edge tc qdisc show dev ix-tb4x9p01 | grep -qE 'htb|ingress'; then fail "unshaped realm B got qdiscs"; else pass "unshaped realm B has no shaping qdiscs"; fi
if in_edge ip link show type ifb | grep -q ifb-tb4x9p; then fail "unshaped realm B got an IFB"; else pass "unshaped realm B has no IFB"; fi

# speed <host>: download rate in Mbit/s (best of two runs, so a slow
# first TLS handshake does not count).
speed() {
	local best=0 s
	for _ in 1 2; do
		s=$(curl_host "$1" /blob -o /dev/null -w '%{speed_download}' || echo 0)
		s=${s%.*}
		((s > best)) && best=$s
	done
	echo $((best * 8 / 1000000))
}
within() { # within <description> <mbit> <target>: ±25%
	local lo=$(($3 * 75 / 100)) hi=$(($3 * 125 / 100))
	if (($2 >= lo && $2 <= hi)); then pass "$1 ($2 Mbit/s, target $3)"; else fail "$1: $2 Mbit/s, want $lo-$hi"; fi
}
A=$(speed files.alice.test)
within "realm A download capped near 20 Mbit/s" "$A" 20
B=$(speed files.bob.test)
if ((B > 60)); then pass "realm B not held by realm A's cap ($B Mbit/s)"; else fail "realm B only reached $B Mbit/s"; fi

# Rate change in place: a running transfer survives it, the tunnel keeps its
# interface (no re-creation) and the new rate holds.
IFINDEX=$(in_edge cat /sys/class/net/ix-tq7k2m01/ifindex)
curl_host files.alice.test /big -o "$TMP/big.out" -w '%{http_code}' >"$TMP/big.code" 2>&1 &
BIG=$!
sleep 1.5
write_config 40
expect "apply new rate" "Applied." he apply --author e2e -m "Faster"
if wait "$BIG" && [[ $(cat "$TMP/big.code") == 200 ]] && [[ $(stat -c %s "$TMP/big.out") == 15000000 ]]; then
	pass "transfer running during the rate change completed"
else
	fail "transfer running during the rate change failed: $(cat "$TMP/big.code")"
fi
[[ $(in_edge cat /sys/class/net/ix-tq7k2m01/ifindex) == "$IFINDEX" ]] && pass "tunnel interface kept across the rate change" || fail "tunnel interface re-created"
expect "IFB class now at 40 Mbit" "rate 40Mbit" in_edge tc class show dev ifb-tq7k2m
A=$(speed files.alice.test)
within "realm A download capped near 40 Mbit/s" "$A" 40

# Removing the shape removes the IFB and the tunnel's qdiscs.
write_config none
expect "apply without shape" "Applied." he apply --author e2e -m "Unshaped"
reject "IFB removed" in_edge ip link show ifb-tq7k2m
if in_edge tc qdisc show dev ix-tq7k2m01 | grep -qE 'htb|ingress'; then fail "tunnel A qdiscs left behind"; else pass "tunnel A qdiscs removed"; fi
A=$(speed files.alice.test)
if ((A > 60)); then pass "realm A uncapped after removal ($A Mbit/s)"; else fail "realm A still capped: $A Mbit/s"; fi

if [[ $FAIL -ne 0 ]]; then
	in_edge tc -s qdisc show 2>/dev/null || true
	in_edge tc -s class show dev ifb-tq7k2m 2>/dev/null || true
fi
finish
