#!/usr/bin/env bash
# Installs ingressd on a fresh Debian/Ubuntu VM from locally built binaries.
#   sudo ./deploy/install.sh [bin-dir]      (default: ./bin)
# Idempotent: re-running upgrades binaries and units without touching config.
set -euo pipefail

BIN=${1:-bin}
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for b in ingressd ingressd-edge; do
	[[ -x $BIN/$b ]] || { echo "missing $BIN/$b (run make build)" >&2; exit 1; }
done
HERE=$(cd "$(dirname "$0")" && pwd)

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard-tools nftables git ca-certificates >/dev/null
modprobe wireguard

echo "==> user and directories"
id ingressd >/dev/null 2>&1 || useradd --system --home /var/lib/ingressd --shell /usr/sbin/nologin ingressd
install -d -m 0750 /etc/ingressd
install -d -m 0700 /etc/ingressd-keys
# The edge (user ingressd) traverses the state dir via its group: it reads
# snapshots, GeoIP databases and its mTLS client cert, and writes only the
# directories it owns below.
install -d -m 0750 -o root -g ingressd /var/lib/ingressd
install -d -m 0750 -o ingressd -g ingressd /var/lib/ingressd/caddy /var/lib/ingressd/cache /var/lib/ingressd/waf /etc/ingressd-edge
install -m 0644 "$HERE/caddy-bootstrap.json" /etc/ingressd-edge/bootstrap.json

echo "==> binaries"
install -m 0755 "$BIN/ingressd" "$BIN/ingressd-edge" /usr/local/bin/

echo "==> systemd"
install -m 0644 "$HERE/systemd/ingressd.service" "$HERE/systemd/ingressd-edge.service" /etc/systemd/system/
# /run/ingressd (root:ingressd 1770) is created at boot by tmpfiles.d; this
# creates it now, or fixes an older edge-owned one.
install -m 0644 "$HERE/systemd/ingressd.tmpfiles" /etc/tmpfiles.d/ingressd.conf
systemd-tmpfiles --create /etc/tmpfiles.d/ingressd.conf
systemctl daemon-reload

if [[ ! -f /etc/ingressd/config.yaml ]]; then
	ingressd init
	cat <<EOF

ingressd is installed but not started.
  1. Edit /etc/ingressd/config.yaml (public IP, hostname, ACME email, tunnels, apps).
  2. Back up /etc/ingressd-keys/age.key somewhere safe.
  3. systemctl enable --now ingressd-edge ingressd
  4. ingressd tunnel config home     # import on your router
  5. ingressd doctor
EOF
else
	systemctl try-restart ingressd-edge ingressd
	echo "Upgraded. Running services were restarted."
fi
