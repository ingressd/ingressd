#!/bin/sh
# Installs ingressd-connector and links this home to an ingressd node.
#
#   curl -fsSL https://<panel>/install/connector.sh | sh -s -- <join-string>
#   curl -fsSL https://<panel>/install/connector.sh | sudo sh -s -- <join-string>
#
# What it does, by platform:
#   Linux + systemd (root)  binary in /usr/local/bin, state in
#                           /var/lib/ingressd-connector, systemd unit
#   Linux + Docker          container with host networking (also: --docker)
#   macOS (root)            binary in /usr/local/bin, launchd daemon
#   otherwise               binary in ~/.local/bin, prints how to run it
#
# Binaries come from --artifacts <url> (an https release: ingressd-connector_<os>_<arch>
# plus SHA256SUMS and its signature SHA256SUMS.minisig, verified) or --bin-dir
# <dir> (local build; SHA256SUMS and its signature are verified when present). Safe to re-run: an enrolled connector is upgraded
# in place and not re-enrolled (unless --reenroll); the join string is then
# optional. A connector installed under the old name is migrated in place
# (state, service and Docker volume), keeping its enrolment.
#
# Options:
#   --join STRING     the join string (same as the positional argument)
#   --artifacts URL   release download base URL (default $INGRESSD_ARTIFACTS,
#                     else the serving panel's /downloads, else the latest
#                     GitHub release)
#   --bin-dir DIR     use binaries from DIR instead of downloading
#   --docker          install as a Docker container
#   --image IMAGE     container image (default ghcr.io/ingressd/ingressd-connector:latest)
#   --mode MODE       tun or netstack (default: tun as root on Linux, else netstack)
#   --edge-addr IP    dial this address instead of resolving the edge hostname
#   --no-discovery    never scan the LAN for services
#   --no-masquerade   tun mode on the LAN's router itself: forward without masquerading
#   --no-service      install and enrol, but do not install/start a service
#   --reenroll        enrol again even if this host is already enrolled
#   --prefix DIR      binary directory (default /usr/local/bin, or ~/.local/bin)
#   --state FILE      state file (default per platform)
set -eu

# A panel serving this script replaces __PANEL_URL__ with its own URL; its
# /downloads then hosts the binaries.
PANEL_URL="__PANEL_URL__"
case "$PANEL_URL" in __*) PANEL_URL="" ;; esac
REPO_RELEASES=https://github.com/ingressd/ingressd/releases/latest/download
INGRESSD_ARTIFACTS=${INGRESSD_ARTIFACTS:-${HOMEEDGE_ARTIFACTS:-}} # legacy homeedge name, remove after 2027-01
ARTIFACTS=${INGRESSD_ARTIFACTS:-${PANEL_URL:+$PANEL_URL/downloads}}
ARTIFACTS=${ARTIFACTS:-$REPO_RELEASES}
BIN_DIR=""
DOCKER=0
IMAGE=${INGRESSD_CONNECTOR_IMAGE:-${HOMEEDGE_CONNECTOR_IMAGE:-ghcr.io/ingressd/ingressd-connector:latest}} # legacy homeedge name, remove after 2027-01
MODE=""
EDGE_ADDR=""
NO_DISCOVERY=0
NO_MASQ=0
NO_SERVICE=0
REENROLL=0
PREFIX=""
STATE=""
JOIN=""

say() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need_arg() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
	case $1 in
	--join) need_arg "$@"; JOIN=$2; shift 2 ;;
	--artifacts) need_arg "$@"; ARTIFACTS=$2; shift 2 ;;
	--bin-dir) need_arg "$@"; BIN_DIR=$2; shift 2 ;;
	--docker) DOCKER=1; shift ;;
	--image) need_arg "$@"; IMAGE=$2; shift 2 ;;
	--mode) need_arg "$@"; MODE=$2; shift 2 ;;
	--edge-addr) need_arg "$@"; EDGE_ADDR=$2; shift 2 ;;
	--no-discovery) NO_DISCOVERY=1; shift ;;
	--no-masquerade) NO_MASQ=1; shift ;;
	--no-service) NO_SERVICE=1; shift ;;
	--reenroll) REENROLL=1; shift ;;
	--prefix) need_arg "$@"; PREFIX=$2; shift 2 ;;
	--state) need_arg "$@"; STATE=$2; shift 2 ;;
	-h | --help) sed -n '2,/^set -eu/p' "$0" 2>/dev/null || echo "see https://github.com/ingressd/ingressd"; exit 0 ;;
	--) shift; break ;;
	-*) die "unknown option $1" ;;
	*) [ -z "$JOIN" ] || die "unexpected argument $1"; JOIN=$1; shift ;;
	esac
done
if [ $# -gt 0 ] && [ -z "$JOIN" ]; then JOIN=$1; fi
case $MODE in "" | tun | netstack) ;; *) die "--mode must be tun or netstack" ;; esac

# ---------------------------------------------------------------- platform
OS=$(uname -s)
case $OS in
Linux) OS=linux ;;
Darwin) OS=darwin ;;
*) die "unsupported OS $OS (on Windows download ingressd-connector_windows_amd64.exe and run: ingressd-connector enroll <join-string>; ingressd-connector install-service)" ;;
esac
case $(uname -m) in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv7* | armv6*) ARCH=arm ;;
*) die "unsupported CPU $(uname -m)" ;;
esac
ROOT=0
[ "$(id -u)" -eq 0 ] && ROOT=1
SYSTEMD=0
[ "$OS" = linux ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && SYSTEMD=1
HAVE_DOCKER=0
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && HAVE_DOCKER=1

if [ "$DOCKER" -eq 0 ] && [ "$OS" = linux ] && [ "$SYSTEMD" -eq 0 ] && [ "$HAVE_DOCKER" -eq 1 ] && [ -z "$BIN_DIR" ]; then
	say "no systemd found; using Docker"
	DOCKER=1
fi

# ---------------------------------------------------------------- docker
if [ "$DOCKER" -eq 1 ]; then
	[ "$HAVE_DOCKER" -eq 1 ] || die "--docker given but docker is not available"
	VOL=ingressd-connector
	# A container installed under the old name keeps its volume (the name is
	# only a label; it is mounted at the new path).
	if ! docker volume inspect "$VOL" >/dev/null 2>&1 && docker volume inspect homeedge-connector >/dev/null 2>&1; then # legacy homeedge name, remove after 2027-01
		VOL=homeedge-connector # legacy homeedge name, remove after 2027-01
		say "migrating: reusing volume $VOL"
	fi
	docker rm -f homeedge-connector >/dev/null 2>&1 || true # legacy homeedge name, remove after 2027-01
	docker volume create "$VOL" >/dev/null
	if [ "$REENROLL" -eq 0 ] && docker run --rm -v "$VOL:/var/lib/ingressd-connector" "$IMAGE" status >/dev/null 2>&1; then
		say "already enrolled (volume $VOL); upgrading the container"
	else
		[ -n "$JOIN" ] || die "a join string is required to enrol (copy it from the panel)"
		set -- enroll "$JOIN" --mode netstack
		[ -n "$EDGE_ADDR" ] && set -- "$@" --edge-addr "$EDGE_ADDR"
		[ "$NO_DISCOVERY" -eq 1 ] && set -- "$@" --no-discovery
		[ "$NO_MASQ" -eq 1 ] && set -- "$@" --masquerade=false
		say "enrolling"
		docker pull -q "$IMAGE" >/dev/null || warn "could not pull $IMAGE; using the local image"
		docker run --rm -v "$VOL:/var/lib/ingressd-connector" "$IMAGE" "$@"
	fi
	docker rm -f ingressd-connector >/dev/null 2>&1 || true
	# Host networking lets discovery see the LAN and keeps UDP simple.
	docker run -d --name ingressd-connector --restart unless-stopped --network host \
		-v "$VOL:/var/lib/ingressd-connector" "$IMAGE" run >/dev/null
	say "running: docker logs -f ingressd-connector"
	exit 0
fi

# ---------------------------------------------------------------- binary
if [ -z "$PREFIX" ]; then
	if [ "$ROOT" -eq 1 ]; then PREFIX=/usr/local/bin; else PREFIX=$HOME/.local/bin; fi
fi
ASSET=ingressd-connector_${OS}_$ARCH

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

fetch() { # fetch <url> <file>; https only
	case $1 in https://*) ;; *) die "refusing to download $1: only https:// URLs are allowed" ;; esac
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		# GNU wget can refuse a redirect to http; BusyBox wget cannot, but
		# the signature check below still covers what it fetched.
		if wget --help 2>&1 | grep -q -- --https-only; then
			wget -q --https-only -O "$2" "$1"
		else
			wget -q -O "$2" "$1"
		fi
	else
		die "need curl or wget"
	fi
}

# verify <file> <asset-name> <sums-file>
verify() {
	want=$(awk -v f="$2" '$2 == f || $2 == "*"f {print $1}' "$3")
	[ -n "$want" ] || die "$2 is not listed in SHA256SUMS"
	got=$(sha256 "$1")
	[ "$got" = "$want" ] || die "checksum mismatch for $2 (got $got, want $want)"
	say "verified $2 ($got)"
}

# The release signing key (pkg/release.ReleasePublicKey; a Go test keeps the
# two equal). INGRESSD_RELEASE_PUBLIC_KEY overrides it for self-signed
# releases, as for the binaries themselves.
RELEASE_KEY=${INGRESSD_RELEASE_PUBLIC_KEY:-RWTCi6nxdL6unHcK5KWP/DTr/NFJSt1EEN48LJTlNVJHGkPs9/Ax00gl}

# verify_sig <sums-file> <sig-file> <new-binary>: checks the SHA256SUMS
# signature with the first available of: the minisign CLI; the connector
# already installed here (trusted from an earlier install); the binary just
# downloaded, after its checksum matched. The last one is circular: a
# source that can replace both the binary and SHA256SUMS also controls the
# verifier, so on a first install without minisign the https channel (and
# the panel serving this script) remain the root of trust.
verify_sig() {
	if command -v minisign >/dev/null 2>&1; then
		minisign -Vq -P "$RELEASE_KEY" -m "$1" -x "$2" || die "SHA256SUMS signature verification failed"
		say "SHA256SUMS signature verified (minisign)"
	elif [ -x "$EXE" ] && "$EXE" verify-sums --help >/dev/null 2>&1; then
		INGRESSD_RELEASE_PUBLIC_KEY="$RELEASE_KEY" "$EXE" verify-sums "$1" "$2" >/dev/null || die "SHA256SUMS signature verification failed"
		say "SHA256SUMS signature verified (installed ingressd-connector)"
	else
		"$3" version >/dev/null 2>&1 || die "the downloaded binary does not run on this host"
		INGRESSD_RELEASE_PUBLIC_KEY="$RELEASE_KEY" "$3" verify-sums "$1" "$2" >/dev/null || die "SHA256SUMS signature verification failed"
		say "SHA256SUMS signature verified by the downloaded binary (install minisign for an independent check)"
	fi
}

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT INT TERM
NEW=$TMPD/ingressd-connector
EXE=$PREFIX/ingressd-connector
SUMS="" SIG=""

if [ -n "$BIN_DIR" ]; then
	if [ -f "$BIN_DIR/$ASSET" ]; then SRC=$BIN_DIR/$ASSET; NAME=$ASSET; else SRC=$BIN_DIR/ingressd-connector; NAME=ingressd-connector; fi
	[ -f "$SRC" ] || die "no $ASSET or ingressd-connector in $BIN_DIR"
	cp "$SRC" "$NEW"
	if [ -f "$BIN_DIR/SHA256SUMS" ]; then
		verify "$NEW" "$NAME" "$BIN_DIR/SHA256SUMS"
		[ -f "$BIN_DIR/SHA256SUMS.minisig" ] && SUMS=$BIN_DIR/SHA256SUMS SIG=$BIN_DIR/SHA256SUMS.minisig
	else
		warn "no SHA256SUMS in $BIN_DIR; not verified"
	fi
else
	say "downloading $ASSET from $ARTIFACTS"
	SUMS=$TMPD/SHA256SUMS SIG=$TMPD/SHA256SUMS.minisig
	fetch "$ARTIFACTS/SHA256SUMS" "$SUMS" || die "cannot download $ARTIFACTS/SHA256SUMS"
	fetch "$ARTIFACTS/SHA256SUMS.minisig" "$SIG" || die "cannot download $ARTIFACTS/SHA256SUMS.minisig"
	fetch "$ARTIFACTS/$ASSET" "$NEW" || die "cannot download $ARTIFACTS/$ASSET"
	verify "$NEW" "$ASSET" "$SUMS"
fi
chmod 0755 "$NEW"
[ -z "$SIG" ] || verify_sig "$SUMS" "$SIG" "$NEW"
"$NEW" version >/dev/null 2>&1 || die "the downloaded binary does not run on this host"

# ---------------------------------------------------------------- migration
# A connector installed under the old name: stop its service, move its state
# directory to the new path (the new binary would also do that itself) and
# replace the old binary with a hint that runs the new one. The enrolment is
# kept; install-service below replaces the old unit / launchd job.
OLDEXE=$PREFIX/homeedge-connector # legacy homeedge name, remove after 2027-01
if [ -e "$OLDEXE" ] && [ ! -L "$OLDEXE" ] && ! grep -q "legacy homeedge name" "$OLDEXE" 2>/dev/null; then # legacy homeedge name, remove after 2027-01
	say "migrating the homeedge-connector install to ingressd-connector" # legacy homeedge name, remove after 2027-01
	if [ "$SYSTEMD" -eq 1 ] && [ "$ROOT" -eq 1 ]; then
		systemctl disable --now homeedge-connector >/dev/null 2>&1 || true # legacy homeedge name, remove after 2027-01
		rm -f /etc/systemd/system/homeedge-connector.service # legacy homeedge name, remove after 2027-01
		systemctl daemon-reload
	elif [ "$OS" = darwin ] && [ "$ROOT" -eq 1 ]; then
		launchctl unload -w /Library/LaunchDaemons/com.homeedge.connector.plist 2>/dev/null || true # legacy homeedge name, remove after 2027-01
		rm -f /Library/LaunchDaemons/com.homeedge.connector.plist # legacy homeedge name, remove after 2027-01
	fi
	if [ -z "$STATE" ]; then
		if [ "$ROOT" -eq 1 ] && [ "$OS" = linux ]; then
			OLDST=/var/lib/homeedge-connector NEWST=/var/lib/ingressd-connector # legacy homeedge name, remove after 2027-01
		elif [ "$ROOT" -eq 1 ]; then
			OLDST="/Library/Application Support/homeedge-connector" NEWST="/Library/Application Support/ingressd-connector" # legacy homeedge name, remove after 2027-01
		elif [ "$OS" = darwin ]; then
			OLDST="$HOME/Library/Application Support/homeedge-connector" NEWST="$HOME/Library/Application Support/ingressd-connector" # legacy homeedge name, remove after 2027-01
		else
			OLDST="${XDG_CONFIG_HOME:-$HOME/.config}/homeedge-connector" NEWST="${XDG_CONFIG_HOME:-$HOME/.config}/ingressd-connector" # legacy homeedge name, remove after 2027-01
		fi
		if [ -d "$OLDST" ] && [ ! -e "$NEWST/connector.json" ]; then
			if [ -d "$NEWST" ]; then rmdir "$NEWST" 2>/dev/null || true; fi
			mv "$OLDST" "$NEWST" && say "moved $OLDST to $NEWST"
		fi
	fi
	MIGRATED=1
fi

mkdir -p "$PREFIX"
UPGRADE=0
[ "${MIGRATED:-0}" -eq 1 ] && UPGRADE=1
if [ -x "$EXE" ] && cmp -s "$NEW" "$EXE"; then
	say "$EXE is up to date ($("$EXE" version))"
else
	[ -e "$EXE" ] && UPGRADE=1
	# Install via rename so a running service keeps its old inode.
	cp "$NEW" "$EXE.new" && chmod 0755 "$EXE.new" && mv -f "$EXE.new" "$EXE"
	say "installed $EXE ($("$EXE" version))"
fi
if [ "${MIGRATED:-0}" -eq 1 ]; then
	# The old name keeps working for scripts, with a hint.
	printf '#!/bin/sh\n# %s\necho "note: homeedge-connector was renamed to ingressd-connector" >&2\nexec "%s" "$@"\n' "legacy homeedge name, remove after 2027-01" "$EXE" >"$OLDEXE" # legacy homeedge name, remove after 2027-01
	chmod 0755 "$OLDEXE"
fi

# ---------------------------------------------------------------- enrol
# "$@" holds the global flags for every connector command from here on.
set --
[ -n "$STATE" ] && set -- --state "$STATE"
ENROLLED=0
if "$EXE" "$@" status >/dev/null 2>&1 && [ "$REENROLL" -eq 0 ]; then
	say "already enrolled; keeping the existing enrolment (use --reenroll to replace it)"
else
	[ -n "$JOIN" ] || die "a join string is required to enrol (copy it from the panel)"
	# "-": the join string (it carries the enrolment token) goes over stdin,
	# not argv, so other local users cannot read it from the process list.
	set -- "$@" enroll -
	[ -n "$MODE" ] && set -- "$@" --mode "$MODE"
	[ -n "$EDGE_ADDR" ] && set -- "$@" --edge-addr "$EDGE_ADDR"
	[ "$NO_DISCOVERY" -eq 1 ] && set -- "$@" --no-discovery
	[ "$NO_MASQ" -eq 1 ] && set -- "$@" --masquerade=false
	say "enrolling"
	printf '%s\n' "$JOIN" | "$EXE" "$@"
	ENROLLED=1
	set --
	[ -n "$STATE" ] && set -- --state "$STATE"
fi

# ---------------------------------------------------------------- service
if [ "$NO_SERVICE" -eq 1 ]; then
	say "done (no service installed). Start it with: $EXE $* run"
	exit 0
fi
if [ "$ROOT" -eq 1 ] && { [ "$SYSTEMD" -eq 1 ] || [ "$OS" = darwin ]; }; then
	"$EXE" "$@" install-service
	# A non-default release key (a staging or self-signed panel) must reach the
	# service too, or self-updates are checked against the built-in key. The
	# literal is split so a panel rewriting the key here leaves it alone.
	if [ "$SYSTEMD" -eq 1 ]; then
		if [ "$RELEASE_KEY" != "RWTCi6nxdL6unHcK5KWP/DTr/NFJSt1EEN48""LJTlNVJHGkPs9/Ax00gl" ]; then
			mkdir -p /etc/systemd/system/ingressd-connector.service.d
			printf '[Service]\nEnvironment=INGRESSD_RELEASE_PUBLIC_KEY=%s\n' "$RELEASE_KEY" >/etc/systemd/system/ingressd-connector.service.d/release-key.conf
		else
			rm -f /etc/systemd/system/ingressd-connector.service.d/release-key.conf
		fi
		systemctl daemon-reload
	fi
	if [ "$UPGRADE" -eq 1 ] || [ "$ENROLLED" -eq 1 ]; then
		if [ "$SYSTEMD" -eq 1 ]; then
			systemctl restart ingressd-connector
		else
			launchctl kickstart -k system/com.ingressd.connector 2>/dev/null || true
		fi
		say "service restarted"
	fi
	say "done. Check it with: ingressd-connector status"
	exit 0
fi
if [ "$ROOT" -eq 0 ]; then
	warn "not root: no system service installed (re-run with sudo to install one)"
else
	warn "no systemd: no service installed"
fi
case :$PATH: in *:"$PREFIX":*) ;; *) warn "$PREFIX is not in PATH" ;; esac
say "start it with: $EXE $* run"
