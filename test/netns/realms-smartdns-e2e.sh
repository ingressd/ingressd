#!/usr/bin/env bash
# e2e realms-smartdns: per-realm Smart DNS. A home node carries two realms,
# each with a router site and its own resolver; an exit node in "NL" hosts
# one exit per realm, joined by the mesh. Each realm's resolver answers only
# on its own tunnel's transit address with its own services, the relay
# egresses through the realm's own exit, and the exit node refuses to
# resolve for a realm an exit does not belong to.
#
#   site A ══ wg ══ home node (edge) 198.51.100.1 ── cdn ── 198.51.100.6 exit node (nl)
#   site B ══ wg ══╝
#   cdn: DNS 192.0.2.53, UK edge 192.0.2.10, NL edge 192.0.2.20
#   mesh: home 10.255.0.1, nl 10.255.0.2
#
# Needs bin/ingressd, bin/ingressd-edge and bin/ingressd-sdtool.
set -euo pipefail
P=he-rd
source "$(dirname "$0")/lib.sh"
NL=$P-nl CDN=$P-cdn SITEB=$P-siteb
NAMESPACES=("$EDGE" "$SITE" "$SITEB" "$NL" "$CDN")
SD=$BIN/ingressd-sdtool
[[ -x $SD ]] || { echo "missing $SD (go build -o bin/ingressd-sdtool ./test/netns/sdtool)" >&2; exit 1; }

in_nl() { ip netns exec "$NL" "$@"; }
in_cdn() { ip netns exec "$CDN" "$@"; }
in_site_b() { ip netns exec "$SITEB" "$@"; }
node() { # node <ns> <dir> <args...>
	local ns=$1 dir=$2
	shift 2
	ip netns exec "$ns" env SSL_CERT_FILE="$TMP/certs/ca.pem" "$BIN/ingressd" --config-dir "$dir/conf" --key "$dir/keys/age.key" \
		--state-dir "$dir/state" --run-dir "$dir/run" "$@"
}
he_home() { node "$EDGE" "$TMP/home" "$@"; }
he_nl() { node "$NL" "$TMP/nl" "$@"; }
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

# --- topology ---
ns_add "${NAMESPACES[@]}"
veth "$EDGE" pub0 198.51.100.1/30 "$CDN" e0 198.51.100.2/30
veth "$NL" pub0 198.51.100.6/30 "$CDN" e1 198.51.100.5/30
veth "$EDGE" wana 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$EDGE" wanb 172.16.2.1/30 "$SITEB" wan0 172.16.2.2/30
ip -n "$EDGE" route add default via 198.51.100.2
ip -n "$NL" route add default via 198.51.100.5
in_cdn sysctl -qw net.ipv4.ip_forward=1
for a in 192.0.2.53 192.0.2.10 192.0.2.20; do ip -n "$CDN" addr add $a/32 dev lo; done

# --- fake CDN ---
mkdir -p "$TMP/certs"
"$SD" gencert "$TMP/certs" stream.example '*.stream.example' other.test '*.other.test'
touch "$TMP/cdn-dns.log" "$TMP/cdn-http.log"
in_cdn "$SD" fakedns -listen 192.0.2.53:53 -nl-src 198.51.100.6 -nl 192.0.2.20 -uk 192.0.2.10 -ttl 2 >>"$TMP/cdn-dns.log" 2>&1 &
PIDS+=($!)
in_cdn "$SD" cdn -addrs 192.0.2.10,192.0.2.20 -countries 192.0.2.10=GB,192.0.2.20=NL -certs "$TMP/certs" >>"$TMP/cdn-http.log" 2>&1 &
PIDS+=($!)
sleep 0.5

# --- nodes ---
start_proxy "$EDGE" "$TMP/home"
start_proxy "$NL" "$TMP/nl"
for n in home nl; do printf 'version: 1\nedge: { acme: { ca: internal } }\n' >"$TMP/$n/conf/config.yaml"; done
he_home init >/dev/null
he_nl init >/dev/null
HOME_KEY=$(he_home smartdns mesh-key)
NL_KEY=$(he_nl smartdns mesh-key)

# Realm A routes stream.example, realm B routes other.test, each through
# its own exit on the NL node.
cat >"$TMP/home/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 198.51.100.1
  acme: { ca: internal }
security: { tunnel_input: restricted }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_nl: { public_key: "$NL_KEY", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32, name: nl }
realms:
  tq7k2m:
    smartdns:
      enabled: true
      upstream: [192.0.2.53]
      exits: { tq7k2m.nl: { node: nod_nl, country: NL } }
      services: { tq7k2m.tv: { domains: [stream.example], exit: tq7k2m.nl } }
  tb4x9p:
    smartdns:
      enabled: true
      upstream: [192.0.2.53]
      exits: { tb4x9p.nl: { node: nod_nl, country: NL } }
      services: { tb4x9p.other: { domains: [other.test], exit: tb4x9p.nl } }
tunnels:
  tq7k2m01: { realm: tq7k2m, site: router, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24, table: 1201 }
  tb4x9p01: { realm: tb4x9p, site: router, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24, table: 1202 }
EOF
cat >"$TMP/nl/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 198.51.100.6
  acme: { ca: internal }
security: { tunnel_input: restricted }
mesh:
  address: 10.255.0.2/16
  peers:
    nod_home: { public_key: "$HOME_KEY", endpoint: "198.51.100.1:51900", address: 10.255.0.1/32, name: home }
realms:
  tq7k2m:
    smartdns: { enabled: false, upstream: [192.0.2.53], exits: { tq7k2m.nl: { node: self, country: NL } } }
  tb4x9p:
    smartdns: { enabled: false, upstream: [192.0.2.53], exits: { tb4x9p.nl: { node: self, country: NL } } }
EOF
expect "home node applies" "Applied." he_home apply --author e2e -m "Realm Smart DNS"
expect "exit node applies" "Applied." he_nl apply --author e2e -m "Realm exits"

connect() { # connect <ns> <tunnel> <edge wan>
	local addr
	he_home tunnel config "$2" --format wg --endpoint "$3" >"$TMP/site-$2.conf"
	addr=$(he_home tunnel config "$2" --endpoint "$3" | sed -n 's/^Address = //p')
	ip -n "$1" link add wg0 type wireguard
	ip netns exec "$1" wg setconf wg0 "$TMP/site-$2.conf"
	ip -n "$1" addr add "$addr" dev wg0
	ip -n "$1" link set wg0 up
}
connect "$SITE" tq7k2m01 172.16.1.1
connect "$SITEB" tb4x9p01 172.16.2.1
he_home serve --watch-interval 1s >"$TMP/home-serve.log" 2>&1 &
PIDS+=($!)
he_nl serve --watch-interval 1s >"$TMP/nl-serve.log" 2>&1 &
PIDS+=($!)
expect "exit node serves the realms' exits" "exit-relay" cat "$TMP/nl-serve.log"
expect "realm A resolver on its transit address" "dns-udp 10.100.1.1:53" cat "$TMP/home-serve.log"
expect "realm B resolver on its transit address" "dns-udp 10.100.2.1:53" cat "$TMP/home-serve.log"
expect "mesh handshake" "bytes from 10.255.0.2" in_edge ping -c1 -W2 10.255.0.2

# --- resolvers ---
A=(in_site "$SD" query 10.100.1.1:53)
B=(in_site_b "$SD" query 10.100.2.1:53)
expect "realm A routes its service through the exit" "NOERROR 10.100.1.1" "${A[@]}" tv.stream.example A
expect "realm A's service resolved at the NL exit" "198.51.100.6 tv.stream.example." cat "$TMP/cdn-dns.log"
expect "realm B does not route realm A's service" "NOERROR 192.0.2.10" "${B[@]}" tv.stream.example A
expect "realm B routes its own service" "NOERROR 10.100.2.1" "${B[@]}" www.other.test A
expect "realm A does not route realm B's service" "NOERROR 192.0.2.10" "${A[@]}" www.other.test A
reject "site A cannot reach realm B's resolver" in_site "$SD" query 10.100.2.1:53 www.other.test A
reject "site B cannot reach realm A's resolver" in_site_b "$SD" query 10.100.1.1:53 tv.stream.example A

# --- relays ---
CA=(--max-time 10 --cacert "$TMP/certs/ca.pem")
expect "realm A relay egresses at its NL exit" "edge=192.0.2.20 src=198.51.100.6 host=tv.stream.example" \
	in_site curl -sS "${CA[@]}" --resolve tv.stream.example:443:10.100.1.1 https://tv.stream.example/
expect "realm B relay egresses at its NL exit" "edge=192.0.2.20 src=198.51.100.6 host=www.other.test" \
	in_site_b curl -sS "${CA[@]}" --resolve www.other.test:443:10.100.2.1 https://www.other.test/
reject "realm B relay refuses realm A's hostname" in_site_b curl -sS "${CA[@]}" --resolve tv.stream.example:443:10.100.2.1 https://tv.stream.example/

# --- exit API: an exit serves its own realm only ---
api() { in_edge curl -sS --max-time 3 "$@"; }
expect "exit resolves for its own realm" '"exit_up":true' api -d '{"exit":"tq7k2m.nl","realm":"tq7k2m","name":"tv.stream.example"}' http://10.255.0.2:51901/v1/resolve
expect "exit refuses another realm" 'not hosted on this node for realm \"tb4x9p\"' api -d '{"exit":"tq7k2m.nl","realm":"tb4x9p","name":"tv.stream.example"}' http://10.255.0.2:51901/v1/resolve
expect "exit refuses a request naming no realm" 'belongs to a realm' api -d '{"exit":"tq7k2m.nl","name":"tv.stream.example"}' http://10.255.0.2:51901/v1/resolve
expect "exit health lists only the asking realm's exits" '{"exits":{"tb4x9p.nl":{"up":true}}}' api "http://10.255.0.2:51901/v1/exits?realm=tb4x9p"

services() {
	he_home smartdns status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); print(" ".join(x["name"]+"="+x["active"] for x in s["services"]))'
}
expect "home node reports both realms' services on their exits" "tb4x9p.other=tb4x9p.nl tq7k2m.tv=tq7k2m.nl" services

if [[ $FAIL -ne 0 ]]; then
	for f in home-serve.log nl-serve.log cdn-dns.log cdn-http.log; do echo "--- $f (tail) ---"; tail -30 "$TMP/$f" 2>/dev/null || true; done
	in_edge nft list ruleset 2>/dev/null | head -80 || true
fi
finish
