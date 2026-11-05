#!/usr/bin/env bash
# e2e pop-forward: PoP forwarding (edge.forward). One router site has a
# WireGuard tunnel to each of two edges, which share a mesh. With edge A's
# tunnel down, requests to A are proxied over the mesh to B's forward
# listener and reach the origin through B's tunnel; the forward listener
# refuses unsigned requests and never forwards again.
#
#   client 198.51.100.2 ─ 198.51.100.1 edge A 172.16.1.1 ─ 172.16.1.2 site ─ lan 192.168.0.17
#                          203.0.113.1 │ mesh 10.255.0.1         │
#                          203.0.113.2 │ mesh 10.255.0.2         │
#                                    edge B 172.16.2.1 ─ 172.16.2.2
set -euo pipefail
P=he-pf
source "$(dirname "$0")/lib.sh"

EDGEB=$P-edgeb
ns_add "$EDGE" "$EDGEB" "$SITE" "$LAN" "$CLIENT"
veth "$CLIENT" eth0 198.51.100.2/30 "$EDGE" pub0 198.51.100.1/30
veth "$EDGE" bb0 203.0.113.1/30 "$EDGEB" bb0 203.0.113.2/30
veth "$EDGE" wan0 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$EDGEB" wan0 172.16.2.1/30 "$SITE" wan1 172.16.2.2/30
veth "$SITE" lan0 192.168.0.1/24 "$LAN" eth0 192.168.0.17/24
ip -n "$LAN" route add default via 192.168.0.1
in_site sysctl -qw net.ipv4.ip_forward=1
in_edge_b() { ip netns exec "$EDGEB" "$@"; }

# The origin tells which edge it was reached from (the edge's transit
# address) and which visitor the edges reported.
in_lan python3 -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("from %s xff %s\n" % (self.client_address[0], self.headers.get("X-Forwarded-For"))).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("192.168.0.17", 8080), H).serve_forever()' &
PIDS+=($!)

start_proxy() { # start_proxy <ns> <dir>
	mkdir -p "$2/run" "$2/state" "$2/xdg" "$2/conf"
	echo "{\"admin\": {\"listen\": \"unix/$2/run/caddy-admin.sock\"}}" >"$2/bootstrap.json"
	XDG_DATA_HOME=$2/xdg XDG_CONFIG_HOME=$2/xdg ip netns exec "$1" "$BIN/ingressd-edge" run --config "$2/bootstrap.json" >"$2/caddy.log" 2>&1 &
	PIDS+=($!)
	for _ in $(seq 50); do [[ -S $2/run/caddy-admin.sock ]] && return; sleep 0.1; done
	echo "ingressd-edge did not start in $1" >&2
	cat "$2/caddy.log" >&2
	exit 1
}
node() { # node <ns> <dir> <args...>
	local ns=$1 dir=$2
	shift 2
	ip netns exec "$ns" "$BIN/ingressd" --config-dir "$dir/conf" --key "$dir/keys/age.key" \
		--state-dir "$dir/state" --run-dir "$dir/run" "$@"
}
he_a() { node "$EDGE" "$TMP/a" "$@"; }
he_b() { node "$EDGEB" "$TMP/b" "$@"; }

start_proxy "$EDGE" "$TMP/a"
start_proxy "$EDGEB" "$TMP/b"
for n in a b; do printf 'version: 1\nedge: { acme: { ca: internal } }\n' >"$TMP/$n/conf/config.yaml"; done
he_a init >/dev/null
he_b init >/dev/null
A_KEY=$(he_a smartdns mesh-key)
B_KEY=$(he_b smartdns mesh-key)
HOP=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
he_a secret set forward-hop --value "$HOP"
he_b secret set forward-hop --value "$HOP"

write_node() { # write_node <dir> <self mesh> <peer id> <peer key> <peer endpoint> <peer mesh> <transit> <public>
	cat >"$1/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: $8
  acme: { ca: internal }
  forward:
    listen_mesh: true
    secret: secret://forward-hop
    siblings: { home: [$3] }
tunnels:
  home: { site: router, listen_port: 51820, transit: $7 }
mesh:
  address: $2/16
  peers:
    $3: { public_key: "$4", endpoint: "$5:51900", address: $6/32 }
apps:
  web: { hosts: [web.example.test], tunnel: home, origin: http://192.168.0.17:8080 }
EOF
}
write_node "$TMP/a" 10.255.0.1 nod_b "$B_KEY" 203.0.113.2 10.255.0.2 10.100.1.0/24 198.51.100.1
write_node "$TMP/b" 10.255.0.2 nod_a "$A_KEY" 203.0.113.1 10.255.0.1 10.100.2.0/24 203.0.113.2
expect "edge A applies" "Applied." he_a apply --author e2e -m "PoP A"
expect "edge B applies" "Applied." he_b apply --author e2e -m "PoP B"

connect() { # connect <he> <wg if> <edge wan>
	local addr
	"$1" tunnel config home --format wg --endpoint "$3" >"$TMP/site-$2.conf"
	addr=$("$1" tunnel config home --endpoint "$3" | sed -n 's/^Address = //p')
	ip -n "$SITE" link add "$2" type wireguard
	in_site wg setconf "$2" "$TMP/site-$2.conf"
	ip -n "$SITE" addr add "$addr" dev "$2"
	ip -n "$SITE" link set "$2" up
}
connect he_a wg0 172.16.1.1
connect he_b wg1 172.16.2.1
he_a serve --watch-interval 1s >"$TMP/a-serve.log" 2>&1 &
PIDS+=($!)
he_b serve --watch-interval 1s >"$TMP/b-serve.log" 2>&1 &
PIDS+=($!)

expect "mesh handshake" "bytes from 10.255.0.2" in_edge ping -c1 -W1 10.255.0.2
expect "B's forward listener on its mesh address" "10.255.0.2:51880" in_edge_b ss -ltn
expect "firewall opens the forward port to mesh peers only" 'iifname "ix-mesh" ip saddr 10.255.0.1 tcp dport 51880 accept' in_edge_b nft list chain inet ingressd input

web() { in_client curl -sS --max-time "${1:-5}" -k --resolve web.example.test:443:198.51.100.1 https://web.example.test/; }
expect "with its tunnel up, A serves through its own tunnel" "from 10.100.1.1 xff 198.51.100.2" web

# The forward listener trusts only signed hops.
code() { "$@" -s -o /dev/null -w '%{http_code}' --max-time 3 2>/dev/null || true; }
expect "forward listener refuses an unsigned request" "403" code in_edge curl -H 'Host: web.example.test' http://10.255.0.2:51880/
expect "forward listener refuses a forged hop" "403" code in_edge curl -H 'Host: web.example.test' -H 'X-Ingressd-Hop: v1;10.255.0.1;web;1;AAAA' http://10.255.0.2:51880/
reject "forward listener unreachable from the internet" in_client curl -s --max-time 2 http://203.0.113.2:51880/

# A's tunnel goes down at the site: the first request waits out one local
# dial, then A forwards it to B (passive health); the next go to B at once.
ip -n "$SITE" link set wg0 down
expect "with A's tunnel down, requests via A reach the origin through B" "from 10.100.2.1 xff 198.51.100.2" web 20
start=$(date +%s%N)
got=$(web 5 2>&1 || true)
ms=$((($(date +%s%N) - start) / 1000000))
if [[ $got == "from 10.100.2.1 xff 198.51.100.2, 10.255.0.1" ]] && ((ms < 2000)); then pass "later requests go straight to B (${ms} ms)"; else fail "later request: '$got' in ${ms} ms"; fi

# With A's tunnel interface gone the control plane marks it down and the
# edge skips it without dialling.
ip -n "$SITE" link set wg0 up
in_edge ip link del ix-home
expect "control plane pushes the tunnel down to the edge" '"home":{"down":true}' in_edge curl -s --unix-socket "$TMP/a/run/caddy-admin.sock" http://localhost/ingressd/state
expect "tunnel marked down: A forwards to B" "from 10.100.2.1" web 5

# Max one hop: with B's tunnel down too, B answers from its own (failed)
# origin and never forwards back; A passes that on.
ip -n "$SITE" link set wg1 down
expect "both tunnels down: 502, no forwarding loop" "502" in_client curl -s -o /dev/null -w "%{http_code}" -k --max-time 20 --resolve web.example.test:443:198.51.100.1 https://web.example.test/
if grep -q "forward refused" "$TMP/a/caddy.log"; then fail "B forwarded a request back to A"; else pass "A's forward listener saw no hop back from B"; fi

if [[ $FAIL -ne 0 ]]; then
	for f in a/caddy.log b/caddy.log a-serve.log b-serve.log; do echo "--- $f (tail) ---"; tail -30 "$TMP/$f" 2>/dev/null || true; done
fi
finish
