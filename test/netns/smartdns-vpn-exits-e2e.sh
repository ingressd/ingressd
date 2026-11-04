#!/usr/bin/env bash
# e2e smartdns-vpn-exits: ONE node hosts two exits that egress through two
# different (simulated) VPN providers, using the WireGuard .conf files the
# providers hand out. Service A must leave through provider 1, service B
# through provider 2, and the node's own traffic must keep its normal route.
#
#   TV 192.168.0.17 ── site ══ wg tunnel ══ node (edge, 198.51.100.1) ── cdn
#                                            │ ix-x-prov-…  ══ vpn1 198.51.100.14 (DE)
#                                            │ ix-x-fr      ══ vpn2 198.51.100.18 (FR),
#                                            │                   later 203.0.113.50
#   cdn: DNS 192.0.2.53 (answers by resolver source), UK edge 192.0.2.10,
#   DE edge 192.0.2.30, FR edge 192.0.2.31, trace 192.0.2.40/cdn-cgi/trace
#
# Provider 1's config is Proton-style (DNS inside the tunnel, keepalive 15);
# provider 2's is AirVPN-style (preshared key, MTU, IPv6 address and DNS,
# no keepalive, host name endpoint). Needs bin/ingressd, bin/ingressd-edge
# and bin/ingressd-sdtool.
set -euo pipefail
P=he-vx
source "$(dirname "$0")/lib.sh"
CDN=$P-cdn V1=$P-vpn1 V2=$P-vpn2
NAMESPACES=("$EDGE" "$SITE" "$LAN" "$CDN" "$V1" "$V2")
SD=$BIN/ingressd-sdtool
[[ -x $SD ]] || { echo "missing $SD (go build -o bin/ingressd-sdtool ./test/netns/sdtool)" >&2; exit 1; }
# ip netns exec bind-mounts /etc/netns/<ns>/hosts over /etc/hosts: the
# node resolves provider 2's endpoint host name from there.
# lib.sh cleanup removes it with the namespace.
HOSTS_DIR=/etc/netns/$EDGE

in_cdn() { ip netns exec "$CDN" "$@"; }
TRACE_URL=http://192.0.2.40/cdn-cgi/trace
he() {
	ip netns exec "$EDGE" env SSL_CERT_FILE="$TMP/certs/ca.pem" INGRESSD_SMARTDNS_TRACE_URL=$TRACE_URL "$BIN/ingressd" \
		--config-dir "$TMP/node/conf" --key "$TMP/node/keys/age.key" --state-dir "$TMP/node/state" --run-dir "$TMP/node/run" "$@"
}

# --- topology ---
ns_add "${NAMESPACES[@]}"
veth "$EDGE" pub0 198.51.100.1/30 "$CDN" e0 198.51.100.2/30
veth "$SITE" wan1 198.51.100.10/30 "$CDN" e2 198.51.100.9/30
veth "$V1" pub0 198.51.100.14/30 "$CDN" e3 198.51.100.13/30
veth "$V2" pub0 198.51.100.18/30 "$CDN" e4 198.51.100.17/30
veth "$EDGE" wan0 172.16.1.1/30 "$SITE" wan0 172.16.1.2/30
veth "$SITE" lan0 192.168.0.1/24 "$LAN" eth0 192.168.0.17/24
ip -n "$EDGE" route add default via 198.51.100.2
ip -n "$SITE" route add default via 198.51.100.9
ip -n "$V1" route add default via 198.51.100.13
ip -n "$V2" route add default via 198.51.100.17
ip -n "$LAN" route add default via 192.168.0.1
in_site sysctl -qw net.ipv4.ip_forward=1
in_cdn sysctl -qw net.ipv4.ip_forward=1
for a in 192.0.2.53 192.0.2.10 192.0.2.30 192.0.2.31 192.0.2.40; do ip -n "$CDN" addr add $a/32 dev lo; done
# Provider 2's second server address (for the endpoint move).
ip -n "$V2" addr add 203.0.113.50/32 dev lo
ip -n "$CDN" route add 203.0.113.50/32 via 198.51.100.18
in_site nft -f - <<'EOF'
table ip site_nat {
	chain post { type nat hook postrouting priority 100; oifname { "wg0", "wan1" } masquerade; }
}
EOF

# --- two VPN providers (test keys only) ---
provider() { # provider <ns> <server-addr/24> <client-addr> [psk-file]
	local ns=$1 srv=$2 client=$3 psk=${4:-}
	local spriv cpriv
	spriv=$(wg genkey) cpriv=$(wg genkey)
	echo "$spriv" >"$TMP/$ns.key"
	ip -n "$ns" link add wg0 type wireguard
	if [[ -n $psk ]]; then
		ip netns exec "$ns" wg set wg0 private-key "$TMP/$ns.key" listen-port 51820 peer "$(echo "$cpriv" | wg pubkey)" allowed-ips "$client/32" preshared-key "$psk"
	else
		ip netns exec "$ns" wg set wg0 private-key "$TMP/$ns.key" listen-port 51820 peer "$(echo "$cpriv" | wg pubkey)" allowed-ips "$client/32"
	fi
	ip -n "$ns" addr add "$srv" dev wg0
	ip -n "$ns" link set wg0 up
	ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
	ip netns exec "$ns" nft -f - <<-'EOF'
		table ip vpn_nat {
			chain post { type nat hook postrouting priority 100; oifname "pub0" masquerade; }
		}
	EOF
	SERVER_PUB=$(echo "$spriv" | wg pubkey) CLIENT_PRIV=$cpriv
}
provider "$V1" 10.2.0.1/24 10.2.0.2
cat >"$TMP/vpn1.conf" <<EOF
[Interface]
# Key for e2e
# NetShield = 1
# VPN Accelerator = on
PrivateKey = $CLIENT_PRIV
Address = 10.2.0.2/32
DNS = 192.0.2.53

[Peer]
# DE#1
PublicKey = $SERVER_PUB
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.14:51820
PersistentKeepalive = 15
EOF
wg genpsk >"$TMP/vpn2.psk"
provider "$V2" 10.66.0.1/24 10.66.0.2 "$TMP/vpn2.psk"
cat >"$TMP/vpn2.conf" <<EOF
[Interface]
Address = 10.66.0.2/32, fd7d:76ee:e68f:a993::2/128
PrivateKey = $CLIENT_PRIV
MTU = 1380

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $(cat "$TMP/vpn2.psk")
Endpoint = vpn2.example.net:51820
AllowedIPs = 0.0.0.0/0, ::/0
EOF
mkdir -p "$HOSTS_DIR"
printf '127.0.0.1 localhost\n198.51.100.18 vpn2.example.net\n' >"$HOSTS_DIR/hosts"

# --- fake CDN ---
mkdir -p "$TMP/certs"
"$SD" gencert "$TMP/certs" a.test '*.a.test' b.test '*.b.test' other.test '*.other.test'
touch "$TMP/cdn-dns.log" "$TMP/cdn-http.log"
in_cdn "$SD" fakedns -listen 192.0.2.53:53 -nl-src 192.0.2.254 -nl 192.0.2.10 -uk 192.0.2.10 -ttl 2 \
	-by-src "198.51.100.14=192.0.2.30;198.51.100.18=192.0.2.31" >>"$TMP/cdn-dns.log" 2>&1 &
PIDS+=($!)
in_cdn "$SD" cdn -addrs 192.0.2.10,192.0.2.30,192.0.2.31,192.0.2.40 -countries 192.0.2.10=GB,192.0.2.30=DE,192.0.2.31=FR \
	-geo 198.51.100.1=GB,198.51.100.14=DE,198.51.100.18=FR -certs "$TMP/certs" >>"$TMP/cdn-http.log" 2>&1 &
PIDS+=($!)
sleep 0.5

# --- the node ---
mkdir -p "$TMP/node/run" "$TMP/node/state" "$TMP/node/xdg" "$TMP/node/conf"
echo "{\"admin\": {\"listen\": \"unix/$TMP/node/run/caddy-admin.sock\"}}" >"$TMP/node/bootstrap.json"
XDG_DATA_HOME=$TMP/node/xdg XDG_CONFIG_HOME=$TMP/node/xdg in_edge "$BIN/ingressd-edge" run --config "$TMP/node/bootstrap.json" >"$TMP/node/caddy.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do [[ -S $TMP/node/run/caddy-admin.sock ]] && break; sleep 0.1; done
printf 'version: 1\nedge: { acme: { ca: internal } }\n' >"$TMP/node/conf/config.yaml"
he init >/dev/null
ROUTE_BEFORE=$(in_edge ip route show default)

# Exit names as the panel writes them (slugs): one too long for a verbatim
# interface name.
EXIT1=provider-one-germany
cat >"$TMP/node/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 198.51.100.1
  acme: { ca: internal }
tunnels:
  home: { site: router, vendor: unifi, listen_port: 51820, transit: 10.100.1.0/24 }
smartdns:
  enabled: true
  upstream: [192.0.2.53]
  exits:
    $EXIT1: { node: self, country: DE, vpn: "secret://vpn-one" }
    fr: { node: self, country: FR, vpn: "secret://vpn-two" }
  services:
    svca: { domains: [a.test], exit: $EXIT1 }
    svcb: { domains: [b.test], exit: fr }
EOF
he secret set vpn-one --from-file "$TMP/vpn1.conf"
he secret set vpn-two --from-file "$TMP/vpn2.conf"
expect "node applies two VPN exits" "Applied." he apply --author e2e -m "two VPN exits"
IF1=$(in_edge ip -br link show type wireguard | awk '{print $1}' | grep '^ix-x-prov' || true)
[[ ${#IF1} -le 15 && -n $IF1 ]] && pass "long exit name gets a valid interface ($IF1)" || fail "no interface for $EXIT1: $(in_edge ip -br link)"

he tunnel config home --format wg --endpoint 172.16.1.1 >"$TMP/site-home.conf"
addr=$(he tunnel config home --endpoint 172.16.1.1 | sed -n 's/^Address = //p')
ip -n "$SITE" link add wg0 type wireguard
in_site wg setconf wg0 "$TMP/site-home.conf"
ip -n "$SITE" addr add "$addr" dev wg0
ip -n "$SITE" link set wg0 up

he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
expect "node serve started" "listening" cat "$TMP/serve.log"

# --- kernel side: two tunnels, own tables, the main route untouched ---
expect "provider 1 handshake" "latest handshake" in_edge wg show "$IF1"
expect "provider 2 handshake (host name endpoint)" "latest handshake" in_edge wg show ix-x-fr
expect "provider 2 endpoint resolved from its host name" "198.51.100.18:51820" in_edge wg show ix-x-fr endpoints
expect "provider 1 keepalive from the file (15 s)" "15" in_edge wg show "$IF1" persistent-keepalive
expect "provider 2 keepalive defaulted to 25 s" "25" in_edge wg show ix-x-fr persistent-keepalive
expect "provider 2 preshared key applied" "(hidden)" in_edge wg show ix-x-fr
expect "provider 2 MTU from the file" "mtu 1380" in_edge ip link show ix-x-fr
if in_edge ip -6 addr show dev ix-x-fr | grep -q fd7d; then fail "IPv6 address applied to ix-x-fr"; else pass "no IPv6 address on the VPN interface"; fi
expect "two VPN tables (exits in name order)" "dev ix-x-fr" in_edge ip route show table 1900
expect "second VPN table" "dev $IF1" in_edge ip route show table 1901
expect "two fwmark rules" "lookup 1901" in_edge ip rule
[[ $(in_edge ip route show default) == "$ROUTE_BEFORE" ]] && pass "node default route unchanged ($ROUTE_BEFORE)" || fail "default route changed: $(in_edge ip route show default)"
if in_edge ip route show table main | grep -q "ix-x-"; then fail "VPN route in the main table: $(in_edge ip route show table main)"; else pass "no VPN routes in the main table"; fi
expect "node's own traffic uses its normal route" "dev pub0" in_edge ip route get 192.0.2.10
expect "node's own HTTPS leaves by its own IP" "src=198.51.100.1 " in_edge curl -sS --max-time 5 --cacert "$TMP/certs/ca.pem" --resolve www.other.test:443:192.0.2.10 https://www.other.test/
expect "node's own trace shows its own IP" "ip=198.51.100.1" in_edge curl -sS --max-time 5 $TRACE_URL
if in_edge cat /etc/resolv.conf 2>/dev/null | grep -q "192.0.2.53"; then fail "VPN DNS written to resolv.conf"; else pass "node resolver not changed by the VPN DNS line"; fi

# --- per-service egress ---
TV=(in_lan "$SD" query 10.100.1.1:53)
TVCURL=(in_lan curl -sS --max-time 10 --cacert "$TMP/certs/ca.pem")
: >"$TMP/cdn-dns.log"
expect "service A answered with the transit IP" "NOERROR 10.100.1.1" "${TV[@]}" www.a.test A
expect "service B answered with the transit IP" "NOERROR 10.100.1.1" "${TV[@]}" www.b.test A
expect "service A resolved by provider 1's DNS (inside tunnel 1)" "198.51.100.14 www.a.test." cat "$TMP/cdn-dns.log"
expect "service B resolved through tunnel 2 (no DNS line: upstream via the VPN)" "198.51.100.18 www.b.test." cat "$TMP/cdn-dns.log"
if grep -qE "^198.51.100.1 www\.(a|b)\.test" "$TMP/cdn-dns.log"; then fail "service name resolved from the node's own IP"; else pass "service names never resolved from the node's own IP"; fi
expect "service A egresses via provider 1" "edge=192.0.2.30 src=198.51.100.14 host=www.a.test" "${TVCURL[@]}" --resolve www.a.test:443:10.100.1.1 https://www.a.test/
expect "service B egresses via provider 2" "edge=192.0.2.31 src=198.51.100.18 host=www.b.test" "${TVCURL[@]}" --resolve www.b.test:443:10.100.1.1 https://www.b.test/
expect "non-service names go direct from the home" "src=198.51.100.10" "${TVCURL[@]}" --resolve www.other.test:443:192.0.2.10 https://www.other.test/

# --- health: egress IP and country per exit ---
jq() { python3 -c "import json,sys; s=json.load(sys.stdin); print($1)"; }
st() { he smartdns status --json | jq "$1"; }
EXITS="' '.join('%s:%s:%s:%s' % (e['name'], e['up'], e.get('egress',''), e['country']) for e in s['exits'])"
expect "exit 1 health: up, provider 1 egress IP, DE" "$EXIT1:True:198.51.100.14:DE" st "$EXITS"
expect "exit 2 health: up, provider 2 egress IP, FR" "fr:True:198.51.100.18:FR" st "$EXITS"
expect "exit 2 reports its resolved endpoint" "198.51.100.18:51820" st "[e.get('endpoint') for e in s['exits'] if e['name']=='fr']"

# --- provider 2 moves its server (DNS now points elsewhere, old address dead) ---
printf '127.0.0.1 localhost\n203.0.113.50 vpn2.example.net\n' >"$HOSTS_DIR/hosts"
ip netns exec "$V2" nft -f - <<'EOF'
table ip old_addr {
	chain in { type filter hook input priority 0; policy accept; ip daddr 198.51.100.18 udp dport 51820 drop; }
	# Dead both ways: otherwise a keepalive the server still sends from its
	# old address makes the node's peer roam back to it (WireGuard follows
	# the source of authenticated packets), a flake seen ~1 in 16 runs.
	chain out { type filter hook output priority 0; policy accept; ip saddr 198.51.100.18 udp sport 51820 drop; }
}
EOF
ok=0
for _ in $(seq 90); do
	if in_edge wg show ix-x-fr endpoints | grep -q "203.0.113.50:51820"; then ok=1; break; fi
	sleep 1
done
[[ $ok -eq 1 ]] && pass "endpoint follows the provider's DNS change" || fail "endpoint not refreshed: $(in_edge wg show ix-x-fr endpoints)"
expect "service B works again after the move" "src=198.51.100.18 host=www.b.test" "${TVCURL[@]}" --resolve www.b.test:443:10.100.1.1 https://www.b.test/moved
expect "exit 2 reports the new endpoint" "203.0.113.50:51820" st "[e.get('endpoint') for e in s['exits'] if e['name']=='fr']"
expect "service A unaffected" "src=198.51.100.14 host=www.a.test" "${TVCURL[@]}" --resolve www.a.test:443:10.100.1.1 https://www.a.test/still

# --- provider 1 down: service A fails closed, B keeps working, nothing leaks ---
: >"$TMP/cdn-http.log"
ip -n "$EDGE" link set "$IF1" down
reject "no egress for service A with tunnel 1 down" "${TVCURL[@]}" --max-time 15 --resolve www.a.test:443:10.100.1.1 https://www.a.test/
expect "service B still egresses via provider 2" "src=198.51.100.18" "${TVCURL[@]}" --resolve www.b.test:443:10.100.1.1 https://www.b.test/
if grep -q "host=www.a.test" "$TMP/cdn-http.log"; then fail "service A leaked: $(cat "$TMP/cdn-http.log")"; else pass "service A never left by another route"; fi
expect "forced apply restores tunnel 1" "Applied." he apply --force --author e2e -m "Restore"
expect "service A works again" "src=198.51.100.14" "${TVCURL[@]}" --resolve www.a.test:443:10.100.1.1 https://www.a.test/
[[ $(in_edge ip route show default) == "$ROUTE_BEFORE" ]] && pass "default route still unchanged at the end" || fail "default route changed: $(in_edge ip route show default)"

if [[ $FAIL -ne 0 ]]; then
	echo "--- serve log (tail) ---"; tail -60 "$TMP/serve.log"
	echo "--- cdn dns log (tail) ---"; tail -20 "$TMP/cdn-dns.log"
	echo "--- cdn http log ---"; tail -20 "$TMP/cdn-http.log"
	in_edge wg show 2>/dev/null || true
	in_edge ip rule 2>/dev/null || true
fi
exit "$FAIL"
