#!/bin/sh
# Installs (or upgrades) an ingressd node and enrols it with a panel.
#
#   curl -fsSL <panel>/install/node.sh | sudo sh -s -- --panel URL --token T [--hostname H]
#
# Options:
#   --panel URL        panel URL (default: the panel that served this script)
#   --token T          one-time enrolment token from the panel (first install)
#   --hostname H       this node's public DNS name, if it has one
#   --public-ip IP     this node's public IPv4 (default: detected)
#   --artifacts URL    download binaries from URL instead of <panel>/downloads
#                      (https only; SHA256SUMS and its signature are verified)
#   --bin-dir DIR      install local binaries from DIR (ingressd[_linux_ARCH],
#                      ingressd-edge[_linux_ARCH]; SHA256SUMS and
#                      SHA256SUMS.minisig checked if present)
#   --no-firewall-guard  do not arm the 5-minute firewall dead-man switch
#
# Safe to re-run: it upgrades binaries and units, keeps config, secrets and
# the enrolment. A node installed under the old name is migrated in place:
# config, keys, state and enrolment move to the ingressd paths and the old
# units are removed, without re-enrolment. SSH stays reachable: the managed
# firewall always allows the SSH port, and until the node has connected to
# the panel a dead-man timer deletes ingressd's nftables table after 5 minutes.
set -eu

# A panel serving this script replaces __PANEL_URL__ with its own URL.
DEFAULT_PANEL="__PANEL_URL__"
case "$DEFAULT_PANEL" in __*) DEFAULT_PANEL="" ;; esac
PANEL="$DEFAULT_PANEL" TOKEN="" HOSTNAME_ARG="" PUBLIC_IP="" ARTIFACTS="" BIN_DIR="" GUARD=1
while [ $# -gt 0 ]; do
	case "$1" in
	--panel) PANEL=$2; shift 2 ;;
	--token) TOKEN=$2; shift 2 ;;
	--hostname) HOSTNAME_ARG=$2; shift 2 ;;
	--public-ip) PUBLIC_IP=$2; shift 2 ;;
	--artifacts) ARTIFACTS=$2; shift 2 ;;
	--bin-dir) BIN_DIR=$2; shift 2 ;;
	--no-firewall-guard) GUARD=0; shift ;;
	-h | --help) sed -n '2,/^set -eu/p' "$0" 2>/dev/null || true; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo sh -s -- ...)"
STATE=/var/lib/ingressd
LEGACY=0
[ -d /var/lib/homeedge ] && [ ! -L /var/lib/homeedge ] && LEGACY=1 # legacy homeedge name, remove after 2027-01
[ -f /etc/systemd/system/homeedge.service ] && LEGACY=1 # legacy homeedge name, remove after 2027-01
ENROLLED=0
[ -f "$STATE/node.json" ] && ENROLLED=1
[ -f /var/lib/homeedge/node.json ] && ENROLLED=1 # legacy homeedge name, remove after 2027-01
if [ $ENROLLED -eq 0 ]; then
	[ -n "$PANEL" ] || die "--panel is required"
	[ -n "$TOKEN" ] || die "--token is required"
fi
PANEL=${PANEL%/}
# Binaries and the enrolment token never travel over plain http.
require_https() { # require_https <option> <url>
	case "$2" in
	https://*) ;;
	*) die "$1 must be an https:// URL (got '$2')" ;;
	esac
}
[ -z "$PANEL" ] || require_https --panel "$PANEL"
[ -z "$ARTIFACTS" ] || require_https --artifacts "$ARTIFACTS"

# --- Platform -----------------------------------------------------------------
[ -r /etc/os-release ] || die "cannot detect the OS (/etc/os-release missing)"
# shellcheck source=/dev/null
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
*" debian "* | *" ubuntu "*) ;;
*) die "unsupported OS '${ID:-unknown}': this installer supports Debian and Ubuntu" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

say "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard-tools nftables git ca-certificates curl iproute2 >/dev/null
# In a container modprobe always fails; what matters is whether the kernel
# (the host's, there) can make a WireGuard interface.
if ! modprobe wireguard 2>/dev/null; then
	if ip link add ix-wgprobe type wireguard 2>/dev/null; then
		ip link del ix-wgprobe
	else
		echo "warning: WireGuard is not available (kernel too old, or a container whose host has not loaded the wireguard module)" >&2
	fi
fi

# --- Binaries -------------------------------------------------------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

sha256_check() { # sha256_check <dir> <file-name-in-SHA256SUMS> <local-file>
	want=$(awk -v f="$2" '{n=$2; sub(/^\*/, "", n)} n==f {print $1}' "$1/SHA256SUMS")
	[ -n "$want" ] || die "$2 is not listed in SHA256SUMS"
	got=$(sha256sum "$3" | awk '{print $1}')
	[ "$want" = "$got" ] || die "checksum mismatch for $2 (want $want, got $got)"
}

# The release signing key (pkg/release.ReleasePublicKey; a Go test keeps the
# two equal). INGRESSD_RELEASE_PUBLIC_KEY overrides it for self-signed
# releases, as for the binaries themselves.
RELEASE_KEY=${INGRESSD_RELEASE_PUBLIC_KEY:-RWTCi6nxdL6unHcK5KWP/DTr/NFJSt1EEN48LJTlNVJHGkPs9/Ax00gl}

# verify_sums <dir>: checks <dir>/SHA256SUMS against SHA256SUMS.minisig, with
# the first available of: the minisign CLI; the ingressd already installed
# here (trusted from an earlier install); the ingressd just downloaded, after
# its checksum matched. The last one is circular: a download source that can
# replace both the binary and SHA256SUMS also controls the verifier, so on a
# first install without minisign the https channel (and the panel serving
# this script) remain the root of trust. It still catches a mirror serving
# files that were not signed with the release key.
verify_sums() {
	if command -v minisign >/dev/null 2>&1; then
		minisign -Vq -P "$RELEASE_KEY" -m "$1/SHA256SUMS" -x "$1/SHA256SUMS.minisig" ||
			die "SHA256SUMS signature verification failed"
		say "SHA256SUMS signature verified (minisign)"
	elif [ -x /usr/local/bin/ingressd ] && /usr/local/bin/ingressd verify-sums --help >/dev/null 2>&1; then
		INGRESSD_RELEASE_PUBLIC_KEY="$RELEASE_KEY" /usr/local/bin/ingressd verify-sums "$1/SHA256SUMS" "$1/SHA256SUMS.minisig" >/dev/null ||
			die "SHA256SUMS signature verification failed"
		say "SHA256SUMS signature verified (installed ingressd)"
	else
		INGRESSD_RELEASE_PUBLIC_KEY="$RELEASE_KEY" "$WORK/ingressd" verify-sums "$1/SHA256SUMS" "$1/SHA256SUMS.minisig" >/dev/null ||
			die "SHA256SUMS signature verification failed"
		say "SHA256SUMS signature verified by the downloaded ingressd (install minisign for an independent check)"
	fi
}

if [ -n "$BIN_DIR" ]; then
	say "binaries from $BIN_DIR"
	for b in ingressd ingressd-edge; do
		src=""
		for cand in "$BIN_DIR/${b}_linux_$ARCH" "$BIN_DIR/$b-linux-$ARCH" "$BIN_DIR/$b"; do
			[ -f "$cand" ] && { src=$cand; break; }
		done
		[ -n "$src" ] || die "missing $b in $BIN_DIR"
		if [ -f "$BIN_DIR/SHA256SUMS" ]; then
			sha256_check "$BIN_DIR" "$(basename "$src")" "$src"
		else
			echo "warning: no SHA256SUMS in $BIN_DIR; installing $src unverified" >&2
		fi
		cp "$src" "$WORK/$b"
	done
	SIGNED=""
	[ -f "$BIN_DIR/SHA256SUMS.minisig" ] && SIGNED=$BIN_DIR
else
	BASE=${ARTIFACTS:-$PANEL/downloads}
	BASE=${BASE%/}
	[ -n "$BASE" ] || die "--artifacts or --panel is required to download binaries"
	say "binaries from $BASE"
	for f in SHA256SUMS SHA256SUMS.minisig; do
		curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$f" "$BASE/$f" || die "cannot download $BASE/$f"
	done
	for b in ingressd ingressd-edge; do
		f=${b}_linux_$ARCH # release asset names (scripts/build-release.sh)
		curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$f" "$BASE/$f" || die "cannot download $BASE/$f"
		sha256_check "$WORK" "$f" "$WORK/$f"
		mv "$WORK/$f" "$WORK/$b"
	done
	SIGNED=$WORK
fi
chmod 0755 "$WORK/ingressd" "$WORK/ingressd-edge"
"$WORK/ingressd" version >/dev/null || die "the downloaded ingressd binary does not run on this machine"
[ -z "$SIGNED" ] || verify_sums "$SIGNED"

# --- Migration from the old name ------------------------------------------------
# A node installed under the old name keeps everything: its services stop, the
# directories move to the new paths (the old paths stay as symlinks so config
# written by an older panel keeps working), the system user is renamed (same
# uid, so file ownership is unchanged) and the old units and binaries go. The
# new services then start with the same enrolment. The old firewall table is
# dropped by the new control plane's first apply; until then the dead-man
# switch below covers both tables.
if [ $LEGACY -eq 1 ]; then
	say "migrating the homeedge install to ingressd" # legacy homeedge name, remove after 2027-01
	systemctl stop homeedge-firewall-guard.timer homeedge.service homeedge-edge.service 2>/dev/null || true # legacy homeedge name, remove after 2027-01
	systemctl disable homeedge.service homeedge-edge.service >/dev/null 2>&1 || true # legacy homeedge name, remove after 2027-01
	for pair in /etc/homeedge:/etc/ingressd /etc/homeedge-keys:/etc/ingressd-keys /etc/homeedge-edge:/etc/ingressd-edge /var/lib/homeedge:/var/lib/ingressd /var/lib/homeedge-edge:/var/lib/ingressd-edge; do # legacy homeedge name, remove after 2027-01
		old=${pair%%:*} new=${pair#*:}
		[ -d "$old" ] && [ ! -L "$old" ] || continue
		if [ -e "$new" ]; then
			echo "warning: both $old and $new exist; keeping $new, leaving $old" >&2
			continue
		fi
		mv "$old" "$new" && ln -s "$new" "$old"
	done
	# The autosaved Caddy config names old sockets and paths; the control
	# plane applies the current config right after start.
	rm -f /var/lib/ingressd-edge/caddy/autosave.json
	if id homeedge >/dev/null 2>&1 && ! id ingressd >/dev/null 2>&1; then # legacy homeedge name, remove after 2027-01
		usermod -l ingressd -d /var/lib/ingressd homeedge # legacy homeedge name, remove after 2027-01
		groupmod -n ingressd homeedge 2>/dev/null || true # legacy homeedge name, remove after 2027-01
	fi
	for u in homeedge homeedge-edge; do # legacy homeedge name, remove after 2027-01
		if [ -d "/etc/systemd/system/$u.service.d" ] && [ ! -e "/etc/systemd/system/ingressd${u#homeedge}.service.d" ]; then # legacy homeedge name, remove after 2027-01
			mv "/etc/systemd/system/$u.service.d" "/etc/systemd/system/ingressd${u#homeedge}.service.d" # legacy homeedge name, remove after 2027-01 (drop-ins; old env var names are still read)
		fi
		rm -f "/etc/systemd/system/$u.service" "/etc/systemd/system/multi-user.target.wants/$u.service"
	done
	rm -rf /run/homeedge # legacy homeedge name, remove after 2027-01
	rm -f /usr/local/bin/homeedge-edge # legacy homeedge name, remove after 2027-01
	systemctl daemon-reload
fi

# --- Users, directories, units (as deploy/install.sh) -------------------------
say "user and directories"
id ingressd >/dev/null 2>&1 || useradd --system --home /var/lib/ingressd --shell /usr/sbin/nologin ingressd
install -d -m 0750 /etc/ingressd
install -d -m 0700 /etc/ingressd-keys
install -d -m 0750 -o root -g ingressd /var/lib/ingressd
install -d -m 0750 -o ingressd -g ingressd /var/lib/ingressd/caddy /var/lib/ingressd/cache /var/lib/ingressd/waf /etc/ingressd-edge
printf '{"admin": {"listen": "unix//run/ingressd/caddy-admin.sock"}}\n' >/etc/ingressd-edge/bootstrap.json
chmod 0644 /etc/ingressd-edge/bootstrap.json

say "binaries"
install -m 0755 "$WORK/ingressd" "$WORK/ingressd-edge" /usr/local/bin/
if [ $LEGACY -eq 1 ] || [ -f /usr/local/bin/homeedge ]; then # legacy homeedge name, remove after 2027-01
	# The old CLI name keeps working for scripts, with a hint.
	printf '#!/bin/sh\n# %s\necho "note: homeedge was renamed to ingressd; run: ingressd $*" >&2\nexec /usr/local/bin/ingressd "$@"\n' "legacy homeedge name, remove after 2027-01" >/usr/local/bin/homeedge # legacy homeedge name, remove after 2027-01
	chmod 0755 /usr/local/bin/homeedge # legacy homeedge name, remove after 2027-01
fi

say "systemd units"
cat >/etc/systemd/system/ingressd-edge.service <<'EOF'
[Unit]
Description=ingressd edge proxy (Caddy)
Documentation=https://github.com/ingressd/ingressd
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=ingressd
Group=ingressd
ExecStart=/usr/local/bin/ingressd-edge run --environ --resume --config /etc/ingressd-edge/bootstrap.json
ExecReload=/usr/local/bin/ingressd-edge reload --config /etc/ingressd-edge/bootstrap.json --force
Environment=XDG_DATA_HOME=/var/lib/ingressd-edge XDG_CONFIG_HOME=/var/lib/ingressd-edge
# /run/ingressd comes from /etc/tmpfiles.d/ingressd.conf (root:ingressd 1770).
StateDirectory=ingressd-edge
TimeoutStopSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/ingressd/caddy /var/lib/ingressd/cache /var/lib/ingressd/waf /var/lib/ingressd-edge /run/ingressd
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/ingressd.service <<'EOF'
[Unit]
Description=ingressd node (control plane and managed-mode agent)
Documentation=https://github.com/ingressd/ingressd
After=network-online.target ingressd-edge.service
Wants=network-online.target
Requires=ingressd-edge.service

[Service]
Type=simple
# Root is needed to manage WireGuard interfaces, routes and nftables; the
# sandbox limits the rest (reasons per line: deploy/systemd/ingressd.service).
ExecStart=/usr/local/bin/ingressd serve
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/ingressd -/etc/ingressd-keys /var/lib/ingressd /run/ingressd /usr/local/bin
ProtectHome=true
PrivateTmp=true
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL

[Install]
WantedBy=multi-user.target
EOF
# Sockets shared with the edge: root's, sticky, group-writable (see
# deploy/systemd/ingressd.tmpfiles); also fixes an older edge-owned dir.
printf 'd /run/ingressd 1770 root ingressd -\n' >/etc/tmpfiles.d/ingressd.conf
systemd-tmpfiles --create /etc/tmpfiles.d/ingressd.conf
# A non-default release key (a staging or self-signed panel) must also reach
# the agent, or its own updates would be checked against the built-in key.
# The literal is split so a panel that rewrites the key in this script
# leaves the comparison alone.
if [ "$RELEASE_KEY" != "RWTCi6nxdL6unHcK5KWP/DTr/NFJSt1EEN48""LJTlNVJHGkPs9/Ax00gl" ]; then
	mkdir -p /etc/systemd/system/ingressd.service.d
	printf '[Service]\nEnvironment=INGRESSD_RELEASE_PUBLIC_KEY=%s\n' "$RELEASE_KEY" >/etc/systemd/system/ingressd.service.d/release-key.conf
else
	rm -f /etc/systemd/system/ingressd.service.d/release-key.conf
fi
systemctl daemon-reload

# --- Firewall dead-man switch ----------------------------------------------------
# ingressd's nftables table is deleted after 5 minutes unless the node has
# connected to the panel by then (a broken firewall can never lock you out).
GUARD_UNIT=ingressd-firewall-guard
if [ $GUARD -eq 1 ] && command -v systemd-run >/dev/null; then
	systemctl stop "$GUARD_UNIT.timer" 2>/dev/null || true
	systemctl reset-failed "$GUARD_UNIT.service" "$GUARD_UNIT.timer" 2>/dev/null || true
	# After a migration the old table may still be loaded: drop both.
	systemd-run --quiet --unit "$GUARD_UNIT" --on-active=5min /bin/sh -c \
		'/usr/sbin/nft delete table inet ingressd; /usr/sbin/nft delete table inet homeedge 2>/dev/null; true' && # legacy homeedge name, remove after 2027-01
		say "firewall dead-man switch armed (5 minutes)"
fi

# --- Enrolment ---------------------------------------------------------------------
SSH_PORT=$(ss -Htlnp 2>/dev/null | awk '/"sshd"/ {n=split($4, a, ":"); print a[n]; exit}')
if [ $ENROLLED -eq 1 ]; then
	say "already enrolled; keeping the enrolment (ingressd node detach to re-enrol)"
	[ -z "$TOKEN" ] || echo "note: --token ignored on an enrolled node" >&2
else
	say "enrolling with $PANEL"
	# The token goes in on stdin (printf is a shell builtin), never in argv.
	set -- --panel "$PANEL" --token-file -
	[ -n "$HOSTNAME_ARG" ] && set -- "$@" --hostname "$HOSTNAME_ARG"
	[ -n "$PUBLIC_IP" ] && set -- "$@" --public-ip "$PUBLIC_IP"
	[ -n "$SSH_PORT" ] && set -- "$@" --ssh-port "$SSH_PORT"
	printf '%s\n' "$TOKEN" | /usr/local/bin/ingressd node enroll "$@"
fi

say "services"
systemctl enable ingressd-edge ingressd >/dev/null 2>&1
systemctl restart ingressd-edge ingressd

# Cancel the dead-man switch once the node is connected to the panel.
if [ $GUARD -eq 1 ] && systemctl is-active --quiet "$GUARD_UNIT.timer" 2>/dev/null; then
	i=0
	while [ $i -lt 90 ]; do
		if /usr/local/bin/ingressd node status 2>/dev/null | grep -q "connected since"; then
			systemctl stop "$GUARD_UNIT.timer" 2>/dev/null || true
			say "connected to the panel; firewall dead-man switch cancelled"
			break
		fi
		i=$((i + 1))
		sleep 2
	done
	if [ $i -ge 90 ]; then
		echo "warning: the node has not connected to the panel yet; the firewall dead-man switch stays armed" >&2
		echo "         (check: ingressd node status; journalctl -u ingressd)" >&2
	fi
fi

cat <<EOF

ingressd node installed.
  Status:   ingressd node status
  Logs:     journalctl -u ingressd -f
  Back up /etc/ingressd-keys/age.key somewhere safe: it decrypts this node's secrets.
EOF
