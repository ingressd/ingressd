#!/usr/bin/env bash
# e2e origin-tls: Origin CA, origin TLS modes and authenticated origin
# pulls. The LAN host runs HTTPS origins with Origin CA certificates (one
# generated on the edge, one from a CSR), a self-signed certificate, and an
# origin that requires the edge's client certificate.
set -euo pipefail
P=he-p7
source "$(dirname "$0")/lib.sh"
command -v openssl >/dev/null || { echo "missing openssl" >&2; exit 1; }

build_topology
start_edge_proxy

# lan_https <port> <cert> <key> <body> [client-ca]: HTTPS origin on the LAN
# host; with client-ca it requires a client certificate signed by it.
cat >"$TMP/https.py" <<'EOF'
import http.server, ssl, sys
port, cert, key, body = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4].encode() + b"\n"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
if len(sys.argv) > 5:
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(sys.argv[5])
srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
lan_https() {
	in_lan python3 "$TMP/https.py" "$@" >>"$TMP/https.log" 2>&1 &
	PIDS+=($!)
}

mkdir -p "$TMP/conf"
cat >"$TMP/conf/config.yaml" <<'EOF'
version: 1
edge:
  name: e2e
  public_ipv4: 172.16.1.1
  acme: { ca: internal }
certificates:
  origin_ca: { enabled: true, common_name: "E2E Origin CA" }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
apps:
  strict:
    hosts: [strict.example.test]
    origin: https://192.168.0.17:8443
    tunnel: home
    tls: { origin: strict }
  named:
    hosts: [named.example.test]
    origin: https://192.168.0.17:8443
    tunnel: home
    tls: { origin: strict, server_name: origin.internal }
  full:
    hosts: [full.example.test]
    origin: https://192.168.0.17:9443
    tunnel: home
    tls: { origin: full }
  selfstrict:
    hosts: [selfstrict.example.test]
    origin: https://192.168.0.17:9443
    tunnel: home
    tls: { origin: strict, verify_with: origin_ca }
  mtls:
    hosts: [mtls.example.test]
    origin: https://192.168.0.17:10443
    tunnel: home
    tls: { origin: strict, mtls: true }
  csr:
    hosts: [csr.example.test]
    origin: https://192.168.0.17:11443
    tunnel: home
    tls: { origin: strict }
EOF

he init >/dev/null

# Origin CA certificate generated on the edge (key handed out, not kept).
expect "issue origin certificate" "Issued" he cert origin issue --san 192.168.0.17 --san origin.internal --out "$TMP/origin" --pfx-password s3cret
expect "PFX export opens with its password" "BEGIN PRIVATE KEY" openssl pkcs12 -in "$TMP/origin/origin.pfx" -passin pass:s3cret -nocerts -nodes
reject "PFX rejects a wrong password" openssl pkcs12 -in "$TMP/origin/origin.pfx" -passin pass:wrong -noout
expect "PFX holds key and full chain" "3" bash -c "openssl pkcs12 -in '$TMP/origin/origin.pfx' -passin pass:s3cret -nokeys 2>/dev/null | grep -c 'BEGIN CERTIFICATE'"
if grep -rq "BEGIN PRIVATE KEY" "$TMP/conf"; then fail "private key stored in config dir"; else pass "issued key not stored in config dir"; fi
expect "inventory is committed" "pki-inventory.yaml" git -C "$TMP/conf" show --stat HEAD

# CSR round trip: the key stays on the "origin".
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$TMP/csr.key" -out "$TMP/csr.pem" \
	-subj /CN=csr.internal -addext "subjectAltName=DNS:csr.internal,IP:192.168.0.17" 2>/dev/null
expect "sign CSR" "Issued" he cert origin sign-csr "$TMP/csr.pem" --out "$TMP/csr"
expect "CSR certificate chains to the Origin CA" "OK" openssl verify -CAfile "$TMP/csr/origin-ca.pem" "$TMP/csr/origin.crt"
[[ ! -e $TMP/csr/origin.key ]] && pass "no key written for CSR" || fail "key written for CSR"
expect "CSR cert carries the CSR key" "$(openssl pkey -in "$TMP/csr.key" -pubout | sed -n 2p)" bash -c "openssl x509 -in '$TMP/csr/origin.crt' -noout -pubkey"

# Self-signed origin certificate.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -keyout "$TMP/self.key" -out "$TMP/self.crt" \
	-subj /CN=192.168.0.17 -addext "subjectAltName=IP:192.168.0.17" 2>/dev/null

lan_https 8443 "$TMP/origin/origin.crt" "$TMP/origin/origin.key" "hello strict"
lan_https 9443 "$TMP/self.crt" "$TMP/self.key" "hello self-signed"
lan_https 10443 "$TMP/origin/origin.crt" "$TMP/origin/origin.key" "hello mtls" "$TMP/origin/edge-client-ca.pem"
lan_https 11443 "$TMP/csr/origin.crt" "$TMP/csr.key" "hello csr"

expect "apply succeeds" "Applied." he apply --author e2e -m "Origin TLS"
connect_site home
in_site ping -c1 -W2 10.100.1.1 >/dev/null || true

CURL=(in_client curl -sS --max-time 3 -k)
for h in strict named full selfstrict mtls csr; do CURL+=(--resolve "$h.example.test:443:198.51.100.1"); done
code() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$1"; }

expect "strict verifies an Origin CA certificate" "hello strict" "${CURL[@]}" https://strict.example.test/
expect "strict with server_name override" "hello strict" "${CURL[@]}" https://named.example.test/
expect "full accepts a self-signed certificate" "hello self-signed" "${CURL[@]}" https://full.example.test/
expect "strict rejects a self-signed certificate" "502" code https://selfstrict.example.test/
expect "strict accepts a certificate signed from a CSR" "hello csr" "${CURL[@]}" https://csr.example.test/
expect "mtls: edge presents its client certificate" "hello mtls" "${CURL[@]}" https://mtls.example.test/
reject "mtls: direct request without client certificate rejected" in_lan curl -sk --max-time 3 https://192.168.0.17:10443/
reject "mtls: origin certificate is not accepted as a client certificate" \
	in_lan curl -sk --max-time 3 --cert "$TMP/origin/origin.crt" --key "$TMP/origin/origin.key" https://192.168.0.17:10443/
CLIENT_CRT=$(ls "$TMP"/state/pki/edge-client-*.crt | head -1)
expect "mtls: the edge client certificate is what the origin accepts" "hello mtls" \
	in_lan curl -sk --max-time 3 --cert "$CLIENT_CRT" --key "${CLIENT_CRT%.crt}.key" https://192.168.0.17:10443/
expect "diff is empty after apply" "No changes." he diff
expect "inventory lists both certificates" "csr:ecdsa-p256" he cert origin list
expect "edge certificate inventory" "strict.example.test" he cert list
expect "nginx snippet with mtls" "ssl_verify_client on;" he cert origin snippet nginx --mtls

# Revocation: --rotate replaces the origin issuer, so after apply the edge no
# longer trusts anything the old issuer signed.
SERIAL=$(he cert origin list | awk '/origin.internal/ {print $1}')
expect "revoke without rotate warns" "still trusts" he cert origin revoke "$SERIAL"
expect "revoked status listed" "revoked" he cert origin list
SERIAL2=$(he cert origin list | awk '/csr.internal/ {print $1}')
expect "revoke --rotate lists certificates to re-issue" "$SERIAL2" he cert origin revoke "$SERIAL2" --rotate
expect "apply after rotation" "Applied." he apply --author e2e -m "Rotate origin issuer"
expect "rotated issuer: old certificate rejected" "502" code https://strict.example.test/
expect "rotated issuer: full mode unaffected" "hello self-signed" "${CURL[@]}" https://full.example.test/

finish
