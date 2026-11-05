#!/usr/bin/env bash
# e2e smartdns-exit-failover (docs/rev1/EXIT-FAILOVER.md §10): a service
# lists two GB exits on two exit nodes, each egressing through its own
# (simulated) VPN provider. New connections leave through the first healthy
# exit, fail over within seconds when its VPN goes away, fail back only after
# failback_after, and get SERVFAIL when both exits are down.
#
#   TV 192.168.0.17 ── site ══ wg tunnel ══ home node (198.51.100.1) ── cdn
#                                            mesh │ 10.255.0.1
#              exit node A 198.51.100.6  (10.255.0.2) ══ provider A 198.51.100.14
#              exit node B 198.51.100.22 (10.255.0.3) ══ provider B 198.51.100.18
#   cdn: DNS 192.0.2.53 (answers by resolver source), edges 192.0.2.10 (home
#   line), 192.0.2.30 (provider A), 192.0.2.31 (provider B)
#
# "Provider A down" deletes exit node A's VPN interface, which its exit
# health reports at once. A provider that silently stops answering is only
# seen after the 3-minute handshake window, which this suite does not wait
# for. Needs bin/ingressd, bin/ingressd-edge and bin/ingressd-sdtool.
set -euo pipefail
P=he-xf
source "$(dirname "$0")/lib.sh"
XA=$P-xa XB=$P-xb CDN=$P-cdn VA=$P-va VB=$P-vb
NAMESPACES=("$EDGE" "$SITE" "$LAN" "$XA" "$XB" "$CDN" "$VA" "$VB")
SD=$BIN/ingressd-sdtool
[[ -x $SD ]] || { echo "missing $SD (go build -o bin/ingressd-sdtool ./test/netns/sdtool)" >&2; exit 1; }
FAILBACK=20

in_cdn() { ip netns exec "$CDN" "$@"; }
node() { # node <ns> <dir> <args...>
	local ns=$1 dir=$2
	shift 2
	ip netns exec "$ns" env SSL_CERT_FILE="$TMP/certs/ca.pem" "$BIN/ingressd" --config-dir "$dir/conf" --key "$dir/keys/age.key" \
		--state-dir "$dir/state" --run-dir "$dir/run" "$@"
}
he_home() { node "$EDGE" "$TMP/home" "$@"; }
he_a() { node "$XA" "$TMP/a" "$@"; }
he_b() { node "$XB" "$TMP/b" "$@"; }

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
veth "$XA" pub0 198.51.100.6/30 "$CDN" e1 198.51.100.5/30
veth "$SITE" wan1 198.51.100.10/30 "$CDN" e2 198.51.100.9/30
veth "$VA" pub0 198.51.100.14/30 "$CDN" e3 198.51.100.13/30
veth "$VB" pub0 198.51.100.18/30 "$CDN" e4 198.51.100.17/30
veth "$XB" pub0 198.51.100.22/30 "$CDN" e5 198.51.100.21/30
veth "$EDGE" wan0 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$SITE" lan0 192.168.0.1/24 "$LAN" eth0 192.168.0.17/24
ip -n "$EDGE" route add default via 198.51.100.2
ip -n "$XA" route add default via 198.51.100.5
ip -n "$SITE" route add default via 198.51.100.9
ip -n "$VA" route add default via 198.51.100.13
ip -n "$VB" route add default via 198.51.100.17
ip -n "$XB" route add default via 198.51.100.21
ip -n "$LAN" route add default via 192.168.0.1
in_site sysctl -qw net.ipv4.ip_forward=1
in_cdn sysctl -qw net.ipv4.ip_forward=1
for a in 192.0.2.53 192.0.2.10 192.0.2.30 192.0.2.31; do ip -n "$CDN" addr add $a/32 dev lo; done
in_site nft -f - <<'EOF'
table ip site_nat {
	chain post { type nat hook postrouting priority 100; oifname { "wg0", "wan1" } masquerade; }
}
EOF

# --- two VPN providers (test keys only) ---
provider() { # provider <ns> <server-addr/24> <client-addr> <conf-out> <endpoint>
	local ns=$1 srv=$2 client=$3 out=$4 ep=$5
	local spriv cpriv
	spriv=$(wg genkey) cpriv=$(wg genkey)
	echo "$spriv" >"$TMP/$ns.key"
	ip -n "$ns" link add wg0 type wireguard
	ip netns exec "$ns" wg set wg0 private-key "$TMP/$ns.key" listen-port 51820 peer "$(echo "$cpriv" | wg pubkey)" allowed-ips "$client/32"
	ip -n "$ns" addr add "$srv" dev wg0
	ip -n "$ns" link set wg0 up
	ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
	ip netns exec "$ns" nft -f - <<-'EOF'
		table ip vpn_nat {
			chain post { type nat hook postrouting priority 100; oifname "pub0" masquerade; }
		}
	EOF
	cat >"$out" <<-EOF
		[Interface]
		PrivateKey = $cpriv
		Address = $client/32
		DNS = 192.0.2.53

		[Peer]
		PublicKey = $(echo "$spriv" | wg pubkey)
		AllowedIPs = 0.0.0.0/0
		Endpoint = $ep:51820
		PersistentKeepalive = 15
	EOF
}
provider "$VA" 10.2.0.1/24 10.2.0.2 "$TMP/vpn-a.conf" 198.51.100.14
provider "$VB" 10.3.0.1/24 10.3.0.2 "$TMP/vpn-b.conf" 198.51.100.18

# --- fake CDN ---
mkdir -p "$TMP/certs"
"$SD" gencert "$TMP/certs" bbc.test '*.bbc.test' other.test '*.other.test'
touch "$TMP/cdn-dns.log" "$TMP/cdn-http.log"
in_cdn "$SD" fakedns -listen 192.0.2.53:53 -nl-src 192.0.2.254 -nl 192.0.2.10 -uk 192.0.2.10 -ttl 2 \
	-by-src "198.51.100.14=192.0.2.30;198.51.100.18=192.0.2.31" >>"$TMP/cdn-dns.log" 2>&1 &
PIDS+=($!)
in_cdn "$SD" cdn -addrs 192.0.2.10,192.0.2.30,192.0.2.31 -countries 192.0.2.10=GB,192.0.2.30=GB,192.0.2.31=GB \
	-certs "$TMP/certs" >>"$TMP/cdn-http.log" 2>&1 &
PIDS+=($!)
sleep 0.5

# --- nodes ---
start_proxy "$EDGE" "$TMP/home"
start_proxy "$XA" "$TMP/a"
start_proxy "$XB" "$TMP/b"
for n in home a b; do
	printf 'version: 1\nedge: { acme: { ca: internal } }\n' >"$TMP/$n/conf/config.yaml"
done
he_home init >/dev/null
he_a init >/dev/null
he_b init >/dev/null
HOME_KEY=$(he_home smartdns mesh-key)
A_KEY=$(he_a smartdns mesh-key)
B_KEY=$(he_b smartdns mesh-key)

home_config() { # home_config <exits list>
	cat >"$TMP/home/conf/config.yaml" <<-EOF
		version: 1
		edge:
		  public_ipv4: 198.51.100.1
		  acme: { ca: internal }
		tunnels:
		  home: { site: router, vendor: unifi, listen_port: 51820, transit: 10.100.1.0/24 }
		mesh:
		  address: 10.255.0.1/16
		  peers:
		    nod_a: { public_key: "$A_KEY", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32, name: a }
		    nod_b: { public_key: "$B_KEY", endpoint: "198.51.100.22:51900", address: 10.255.0.3/32, name: b }
		smartdns:
		  enabled: true
		  upstream: [192.0.2.53]
		  failback_after: ${FAILBACK}s
		  exits:
		    gb-a: { node: nod_a, country: GB }
		    gb-b: { node: nod_b, country: GB }
		    de: { node: nod_b, country: DE }
		  services:
		    bbc: { domains: [bbc.test], exits: $1 }
	EOF
}
exit_config() { # exit_config <dir> <mesh addr> <public addr> <exit> <secret>
	cat >"$1/conf/config.yaml" <<-EOF
		version: 1
		edge:
		  public_ipv4: $3
		  acme: { ca: internal }
		mesh:
		  address: $2/16
		  peers:
		    nod_home: { public_key: "$HOME_KEY", endpoint: "198.51.100.1:51900", address: 10.255.0.1/32, name: home }
		smartdns:
		  enabled: false
		  upstream: [192.0.2.53]
		  exits:
		    $4: { node: self, country: GB, vpn: "secret://$5" }
	EOF
}

# Fail closed across countries is a config rule: a list mixing GB and DE
# never reaches the runtime.
home_config "[gb-a, de]"
expect "mixed-country exit list rejected" "country DE differs from GB of exits[0]" he_home validate
home_config "[gb-a, gb-b]"
exit_config "$TMP/a" 10.255.0.2 198.51.100.6 gb-a vpn-a
exit_config "$TMP/b" 10.255.0.3 198.51.100.22 gb-b vpn-b
he_a secret set vpn-a --from-file "$TMP/vpn-a.conf"
he_b secret set vpn-b --from-file "$TMP/vpn-b.conf"
expect "home node applies an ordered exit list" "Applied." he_home apply --author e2e -m "exit failover"
expect "exit node A applies" "Applied." he_a apply --author e2e -m "gb-a"
expect "exit node B applies" "Applied." he_b apply --author e2e -m "gb-b"

he_home tunnel config home --format wg --endpoint 172.16.1.1 >"$TMP/site-home.conf"
addr=$(he_home tunnel config home --endpoint 172.16.1.1 | sed -n 's/^Address = //p')
ip -n "$SITE" link add wg0 type wireguard
in_site wg setconf wg0 "$TMP/site-home.conf"
ip -n "$SITE" addr add "$addr" dev wg0
ip -n "$SITE" link set wg0 up

he_home serve --watch-interval 1s >"$TMP/home-serve.log" 2>&1 &
PIDS+=($!)
he_a serve --watch-interval 1s >"$TMP/a-serve.log" 2>&1 &
PIDS+=($!)
he_b serve --watch-interval 1s >"$TMP/b-serve.log" 2>&1 &
PIDS+=($!)
expect "home node serve started" "listening" cat "$TMP/home-serve.log"
expect "exit node A serve started" "exit-relay" cat "$TMP/a-serve.log"
expect "exit node B serve started" "exit-relay" cat "$TMP/b-serve.log"
expect "provider A handshake" "latest handshake" ip netns exec "$XA" wg show ix-x-gb-a
expect "provider B handshake" "latest handshake" ip netns exec "$XB" wg show ix-x-gb-b
expect "mesh to exit node A" "bytes from 10.255.0.2" in_edge ping -c1 -W2 10.255.0.2
expect "mesh to exit node B" "bytes from 10.255.0.3" in_edge ping -c1 -W2 10.255.0.3
expect "exit node A reports its exit health" '"gb-a":{"up":true}' in_edge curl -s --max-time 3 http://10.255.0.2:51901/v1/exits

jq() { python3 -c "import json,sys; s=json.load(sys.stdin); print($1)"; }
home_status() { he_home smartdns status --json | jq "$1"; }
ACTIVE="' '.join('%s:%s:%s' % (x['name'], x.get('active',''), x.get('failover', False)) for x in s['services'])"
TV=(in_lan "$SD" query 10.100.1.1:53)
TVCURL=(in_lan curl -sS --max-time 10 --cacert "$TMP/certs/ca.pem")
egress() { "${TVCURL[@]}" --resolve "www.bbc.test:443:10.100.1.1" "https://www.bbc.test/$1" 2>&1 || true; }
# wait_egress <want-src> <seconds>: polls new connections until they leave
# from want-src and prints how long that took.
wait_egress() {
	local start=$SECONDS
	while ((SECONDS - start <= $2)); do
		[[ $(egress "wait") == *"src=$1 "* ]] && { echo $((SECONDS - start)); return 0; }
		sleep 1
	done
	return 1
}

# --- both exits up: the first one is used ---
expect "service answered with the transit IP" "NOERROR 10.100.1.1" "${TV[@]}" www.bbc.test A
expect "service leaves through exit A (provider A)" "edge=192.0.2.30 src=198.51.100.14 host=www.bbc.test" egress first
expect "status: gb-a active, no failover" "bbc:gb-a:False" home_status "$ACTIVE"

# --- provider A down: new connections fail over to B within seconds ---
ip -n "$XA" link del ix-x-gb-a
if t=$(wait_egress 198.51.100.18 20); then pass "failed over to provider B in ${t}s"; else fail "no failover to provider B: $(egress late)"; fi
expect "service still answered with the transit IP" "NOERROR 10.100.1.1" "${TV[@]}" www.bbc.test A
expect "status: gb-b active, failover" "bbc:gb-b:True" home_status "$ACTIVE"
expect "status explains why" "gb-a: exit node nod_a reports the exit down" home_status "[x.get('message','') for x in s['services']]"

# --- provider A back: stay on B until failback_after, then fail back ---
expect "exit node A restores its VPN" "Applied." he_a apply --force --author e2e -m "restore gb-a"
expect "provider A handshake again" "latest handshake" ip netns exec "$XA" wg show ix-x-gb-a
ok=0
for _ in $(seq 60); do
	[[ $(home_status "[x['up'] for x in s['remote_exits'] if x['name']=='gb-a'][0]" 2>&1) == True ]] && { ok=1; break; }
	sleep 0.5
done
[[ $ok -eq 1 ]] && pass "home node sees gb-a up again" || fail "home node never saw gb-a up again"
up_at=$SECONDS
[[ $(egress sticky) == *"src=198.51.100.18 "* ]] && pass "still on provider B right after A recovered (sticky)" || fail "left provider B before failback_after"
if wait_egress 198.51.100.14 $((FAILBACK + 15)) >/dev/null; then
	# The status file lags health by up to a few seconds.
	t=$((SECONDS - up_at))
	((t >= FAILBACK - 5)) && pass "failed back to provider A ${t}s after it recovered (failback_after ${FAILBACK}s)" || fail "failed back after ${t}s, before failback_after ${FAILBACK}s"
else
	fail "no failback to provider A"
fi
expect "status: gb-a active again" "bbc:gb-a:False" home_status "$ACTIVE"

# --- A down, then B's node loses the mesh: fail closed ---
ip -n "$XA" link del ix-x-gb-a
if t=$(wait_egress 198.51.100.18 20); then pass "failed over to provider B again in ${t}s"; else fail "no second failover"; fi
mark=$(wc -l <"$TMP/cdn-http.log")
ip -n "$XB" link set pub0 down
ok=0
for _ in $(seq 60); do
	if [[ $("${TV[@]}" www.bbc.test A 2>&1) == SERVFAIL* ]]; then ok=1; break; fi
	sleep 0.5
done
[[ $ok -eq 1 ]] && pass "SERVFAIL with every exit down" || fail "no SERVFAIL with every exit down"
expect "status: no active exit, both reasons" "gb-b: exit node nod_b" home_status "[x.get('active','-')+' '+x.get('message','') for x in s['services']]"
reject "no relayed connection with every exit down" "${TVCURL[@]}" --resolve www.bbc.test:443:10.100.1.1 https://www.bbc.test/closed
expect "non-service names still resolve" "NOERROR 192.0.2.10" "${TV[@]}" www.other.test A
sleep 1
if tail -n +$((mark + 1)) "$TMP/cdn-http.log" | grep -q "host=www.bbc.test"; then
	fail "service traffic leaked: $(tail -n +$((mark + 1)) "$TMP/cdn-http.log")"
else
	pass "nothing leaked while every exit was down"
fi

# The service only ever egressed through its two GB providers.
if grep "host=www.bbc.test" "$TMP/cdn-http.log" | grep -vqE "src=198\.51\.100\.(14|18) "; then
	fail "service egressed elsewhere: $(grep host=www.bbc.test "$TMP/cdn-http.log")"
else
	pass "service egressed only through its listed exits"
fi

if [[ $FAIL -ne 0 ]]; then
	echo "--- home serve log (tail) ---"; tail -60 "$TMP/home-serve.log"
	echo "--- exit A serve log (tail) ---"; tail -30 "$TMP/a-serve.log"
	echo "--- exit B serve log (tail) ---"; tail -30 "$TMP/b-serve.log"
	echo "--- cdn http log ---"; tail -20 "$TMP/cdn-http.log"
	he_home smartdns status 2>/dev/null || true
fi
exit "$FAIL"
