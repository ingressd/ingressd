#!/usr/bin/env bash
# e2e l4-forwarding: TCP/UDP forwarding from a client on the "internet"
# through the edge and a real WireGuard tunnel to a LAN host, configured only
# through config.yaml and the ingressd CLI. Runs twice: with a plain tunnel
# and with a remapped one (virtual_prefix), which uses fwmark routing.
#
# Checks: proxy mode (server sees the edge's transit IP), transparent mode
# (server sees the client's real IP; the site router emulates a UniFi policy
# route sending the game host's replies back through wg0), allowlist access
# (blocked, allowed after `ingressd l4 allow`, entries survive re-applies,
# expiry, revoke), PROXY protocol v2 via caddy-l4, the login-to-play portal
# host, and port-conflict validation.
set -euo pipefail
P=he-p4
source "$(dirname "$0")/lib.sh"

# LAN test servers: TCP/UDP echo on 9000 reporting the peer address, and a
# PROXY v2 reader on 9100 reporting the header's source and the peer.
cat >"$TMP/servers.py" <<'EOF'
import socket, socketserver, struct, threading

class TCPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024).strip()
        self.request.sendall(b"tcp %s %s\n" % (self.client_address[0].encode(), data))

class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(b"udp %s %s\n" % (self.client_address[0].encode(), data.strip()), self.client_address)

class PP2(socketserver.BaseRequestHandler):
    def handle(self):
        hdr = b""
        while len(hdr) < 16:
            hdr += self.request.recv(16 - len(hdr))
        if hdr[:12] != b"\r\n\r\n\x00\r\nQUIT\n":
            self.request.sendall(b"no proxy header\n")
            return
        n = struct.unpack("!H", hdr[14:16])[0]
        body = b""
        while len(body) < n:
            body += self.request.recv(n - len(body))
        src = socket.inet_ntoa(body[0:4]) if hdr[13] == 0x11 else "?"
        self.request.recv(1024)
        self.request.sendall(b"pp2 src=%s peer=%s\n" % (src.encode(), self.client_address[0].encode()))

socketserver.ThreadingTCPServer.allow_reuse_address = True
for srv in (socketserver.ThreadingTCPServer(("0.0.0.0", 9000), TCPEcho),
            socketserver.ThreadingUDPServer(("0.0.0.0", 9000), UDPEcho),
            socketserver.ThreadingTCPServer(("0.0.0.0", 9100), PP2)):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
threading.Event().wait()
EOF

# client.py <tcp|udp> <host> <port>: sends "hello", prints the reply.
cat >"$TMP/client.py" <<'EOF'
import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
s.settimeout(1.5)
s.connect((host, port))
s.send(b"hello\n")
print(s.recv(1024).decode().strip())
EOF

PUB=198.51.100.1
call() { in_client python3 "$TMP/client.py" "$@"; }

write_config() { # write_config <virtual_prefix line or "">
	mkdir -p "$TMP/conf"
	cat >"$TMP/conf/config.yaml" <<EOF
version: 1
edge:
  public_ipv4: 172.16.1.1
  admin: { hostname: edge.example.test }
  acme: { ca: internal }
tunnels:
  home:
    site: router
    vendor: unifi
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
$1
email: { provider: log, log: { path: $TMP/mail.log } }
policies:
  friends:
    action: allow
    include: [{ email_domain: [example.test] }]
l4:
  echo:
    listen: [7000/tcp, 7000/udp]
    target: { tunnel: home, address: 192.168.0.17, port: 9000 }
    mode: proxy
  echot:
    listen: [7001/tcp, 7001/udp]
    target: { tunnel: home, address: 192.168.0.17, port: 9000 }
    mode: transparent
    limits: { conn_per_ip: 50, new_conn_rate: 100/s }
  locked:
    listen: [7002/tcp, 7002/udp]
    target: { tunnel: home, address: 192.168.0.17, port: 9000 }
    access: allowlist
  mc:
    preset: minecraft_java
    listen: [7003/tcp]
    target: { tunnel: home, address: 192.168.0.17, port: 9100 }
  play:
    listen: [7004/udp]
    target: { tunnel: home, address: 192.168.0.17, port: 9000 }
    access: login_to_play
    login_to_play: { policy: friends, ttl: 1h, portal_host: play.example.test }
EOF
}

reset() {
	# As lib.sh cleanup: the in_* helpers background subshells, so kill what
	# runs inside the namespaces too, or it outlives build_topology.
	kill_ns_procs
	wait 2>/dev/null || true
	PIDS=()
	rm -rf "$TMP/conf" "$TMP/state" "$TMP/run" "$TMP/keys" "$TMP/xdg"
}

suite() { # suite <label> <virtual_prefix line or "">
	local L=$1
	echo "=== $L ==="
	reset
	build_topology
	in_lan python3 "$TMP/servers.py" >"$TMP/servers.log" 2>&1 &
	PIDS+=($!)
	start_edge_proxy
	write_config "$2"
	he init >/dev/null
	expect "$L: apply succeeds" "Applied." he apply --author e2e -m "L4 services"
	connect_site home
	in_site ping -c1 -W2 10.100.1.1 >/dev/null || true
	expect "$L: ip_forward enabled" "1" in_edge cat /proc/sys/net/ipv4/ip_forward

	# Proxy mode works with the default site config (transit-only AllowedIPs).
	expect "$L: proxy TCP, server sees edge transit IP" "tcp 10.100.1.1 hello" call tcp $PUB 7000
	expect "$L: proxy UDP, server sees edge transit IP" "udp 10.100.1.1 hello" call udp $PUB 7000

	# PROXY protocol v2 through caddy-l4: header carries the client IP.
	expect "$L: PROXY v2 header has client IP" "pp2 src=198.51.100.2 peer=10.100.1.1" call tcp $PUB 7003

	# Transparent mode: site accepts any source from the edge and routes the
	# game host's replies back through the tunnel (UniFi policy route).
	local edgepub
	edgepub=$(in_site wg show wg0 peers)
	in_site wg set wg0 peer "$edgepub" allowed-ips 0.0.0.0/0
	in_site ip rule add from 192.168.0.17 lookup 100 priority 100
	in_site ip route add default dev wg0 table 100
	expect "$L: transparent TCP, server sees client IP" "tcp 198.51.100.2 hello" call tcp $PUB 7001
	expect "$L: transparent UDP, server sees client IP" "udp 198.51.100.2 hello" call udp $PUB 7001
	expect "$L: proxy mode still works with policy route" "tcp 10.100.1.1 hello" call tcp $PUB 7000

	# Allowlist: blocked until allowed; entries survive re-applies; expiry.
	reject "$L: allowlist blocks unknown client (tcp)" call tcp $PUB 7002
	reject "$L: allowlist blocks unknown client (udp)" call udp $PUB 7002
	expect "$L: l4 allow" "Allowed 198.51.100.2 on locked (no expiry)" he l4 allow locked 198.51.100.2 --email e2e@example.test
	expect "$L: allowed client connects (tcp)" "tcp 10.100.1.1 hello" call tcp $PUB 7002
	expect "$L: allowed client connects (udp)" "udp 10.100.1.1 hello" call udp $PUB 7002
	expect "$L: l4 list shows entry" "e2e@example.test" he l4 list
	expect "$L: forced re-apply" "Applied." he apply --force --author e2e
	expect "$L: entry restored after re-apply" "tcp 10.100.1.1 hello" call tcp $PUB 7002
	expect "$L: l4 revoke" "Revoked" he l4 revoke locked 198.51.100.2
	reject "$L: revoked client blocked" call tcp $PUB 7002
	expect "$L: l4 allow with ttl" "Allowed 198.51.100.2 on locked (until" he l4 allow locked 198.51.100.2 --ttl 3s
	expect "$L: client allowed before expiry" "tcp 10.100.1.1 hello" call tcp $PUB 7002
	sleep 4
	reject "$L: client blocked after expiry" call tcp $PUB 7002
	if he l4 list | grep -q 198.51.100.2; then fail "$L: expired entry still listed"; else pass "$L: expired entry pruned"; fi
	reject "$L: allow on public service refused" he l4 allow echo 198.51.100.2
}

suite plain ""
suite remapped "    virtual_prefix: 10.201.0.0/24"
expect "remapped: fwmark routing in use" "meta mark set 0x000003e8" in_edge nft list chain ip ingressd_l4 route_mark

# Login-to-play: the portal host is served by the control plane and signs
# players in with the Access email-code flow (provider log here; managed
# nodes ask the panel), then allowlists their IP.
reject "login-to-play: unauthenticated client blocked" call udp $PUB 7004
he serve --watch-interval 1s >"$TMP/serve.log" 2>&1 &
PIDS+=($!)
PC=(in_client curl -sk --max-time 5 --resolve play.example.test:443:$PUB -c "$TMP/play-jar" -b "$TMP/play-jar")
expect "login-to-play: portal lists service" 'href="/join/play"' "${PC[@]}" https://play.example.test/
expect "login-to-play: join page asks for an email" 'value="email"' "${PC[@]}" https://play.example.test/join/play
play_form() { "${PC[@]}" -X POST https://play.example.test/join/play -H "Origin: https://play.example.test" \
	--data-urlencode "step=$1" --data-urlencode "email=$2" --data-urlencode "code=${3:-}"; }
expect "login-to-play: code requested" "is on its way to" play_form email gamer@example.test
PLAYCODE=""
for _ in $(seq 40); do
	PLAYCODE=$(awk '$0 == "To: gamer@example.test" { w = 1 } w && / is: [0-9]+$/ { c = $NF; w = 0 } END { print c }' "$TMP/mail.log" 2>/dev/null)
	[[ -n $PLAYCODE ]] && break
	sleep 0.25
done
expect "login-to-play: wrong code rejected" "invalid or has expired" play_form code gamer@example.test 000000
expect "login-to-play: signed in and allowlisted" "You're in" play_form code gamer@example.test "$PLAYCODE"
expect "login-to-play: player connects" "udp 10.100.1.1 hello" call udp $PUB 7004
expect "login-to-play: entry listed with the email" "gamer@example.test" he l4 list
expect "login-to-play: cookie skips the code" "You're in" "${PC[@]}" https://play.example.test/join/play
expect "snippet prints site routing" "AllowedIPs = 0.0.0.0/0" he l4 snippet echot

# Validation: game ports must not collide with the edge's own ports.
sed 's|listen: \[7000/tcp, 7000/udp\]|listen: [443/tcp, 51820/udp]|' "$TMP/conf/config.yaml" >"$TMP/bad.yaml"
expect "port conflict with HTTPS rejected" "port 443/tcp is already used by HTTPS" he validate -f "$TMP/bad.yaml"
expect "port conflict with WireGuard rejected" 'port 51820/udp is already used by tunnel "home"' he validate -f "$TMP/bad.yaml"

finish
