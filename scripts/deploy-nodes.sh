#!/usr/bin/env bash
# Rolls a release out to an inventory of nodes over SSH, one node at a time,
# stopping at the first failure. Used by .github/workflows/deploy.yml; see
# docs/RELEASING.md §8.
#
#   DEPLOY_HOSTS="..." scripts/deploy-nodes.sh --release-dir DIR --version vX.Y.Z \
#       [--ssh-key FILE] [--known-hosts FILE] [--only name,name] [--dry-run]
#
# Host keys must already be known: from --known-hosts, else the user's own
# known_hosts. RELEASE_DIR needs SHA256SUMS and SHA256SUMS.minisig.
#
# DEPLOY_HOSTS has one node per line: "<name> <user@host> [ssh-port]"; blank
# lines and "#" comments are ignored. The SSH user needs passwordless sudo.
#
# On each node: the binaries for its architecture (uname -m) are copied to a
# temporary directory, SHA256SUMS' signature is verified by the ingressd
# installed there and the binaries are checked against it, swapped atomically into
# /usr/local/bin (the previous ones kept as *.old), the systemd units are
# restarted, and the node must pass `ingressd doctor` within the health
# timeout; otherwise the old binaries are restored and restarted and the
# rollout stops. This mirrors `ingressd upgrade`, which needs a signed public
# release.
set -euo pipefail

RELEASE_DIR="" VERSION="" SSH_KEY="" KNOWN_HOSTS="" ONLY="" DRY_RUN=0
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-90}
while [[ $# -gt 0 ]]; do
	case $1 in
	--release-dir) RELEASE_DIR=$2; shift 2 ;;
	--version) VERSION=$2; shift 2 ;;
	--ssh-key) SSH_KEY=$2; shift 2 ;;
	--known-hosts) KNOWN_HOSTS=$2; shift 2 ;;
	--only) ONLY=$2; shift 2 ;;
	--dry-run) DRY_RUN=1; shift ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
done
[[ -n $RELEASE_DIR && -n $VERSION ]] || { echo "usage: $0 --release-dir DIR --version vX.Y.Z [...]" >&2; exit 2; }
[[ -n ${DEPLOY_HOSTS:-} ]] || { echo "DEPLOY_HOSTS is empty: nothing to deploy" >&2; exit 2; }
for f in SHA256SUMS SHA256SUMS.minisig; do
	[[ -f $RELEASE_DIR/$f ]] || { echo "$RELEASE_DIR/$f missing" >&2; exit 1; }
done

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o StrictHostKeyChecking=yes)
[[ -n $SSH_KEY ]] && SSH_OPTS+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
[[ -n $KNOWN_HOSTS ]] && SSH_OPTS+=(-o UserKnownHostsFile="$KNOWN_HOSTS")

# The remote half, run as root with: <dir> <version> <arch> <timeout>.
# shellcheck disable=SC2016
REMOTE='
set -euo pipefail
dir=$1 version=$2 arch=$3 timeout=$4
cd "$dir"
# Created by root with O_EXCL (a fixed /tmp name could be pre-planted).
doctor_out=$(mktemp)
trap "rm -f \"\$doctor_out\"" EXIT
grep -E "  (ingressd|ingressd-edge)_linux_${arch}\$" SHA256SUMS | sha256sum -c -
# The installed binary holds the release key; one too old to verify leaves
# the new binary to check itself, as on a first install.
verifier=/usr/local/bin/ingressd
if ! "$verifier" verify-sums --help >/dev/null 2>&1; then
	echo "installed ingressd cannot verify signatures; using the new binary" >&2
	verifier=./ingressd_linux_${arch}
	chmod 0755 "$verifier"
fi
"$verifier" verify-sums SHA256SUMS SHA256SUMS.minisig
for b in ingressd ingressd-edge; do
	[[ -e /usr/local/bin/$b ]] && cp -p "/usr/local/bin/$b" "/usr/local/bin/$b.old"
	install -m 0755 "${b}_linux_${arch}" "/usr/local/bin/$b.new"
	mv -f "/usr/local/bin/$b.new" "/usr/local/bin/$b"
done
healthy() {
	systemctl is-active --quiet ingressd-edge.service ingressd.service && ingressd doctor >"$doctor_out" 2>&1
}
restart() { systemctl restart ingressd-edge.service && systemctl restart ingressd.service; }
restart || true
for _ in $(seq "$timeout"); do
	if healthy; then
		echo "healthy: $(ingressd version)"
		rm -rf "$dir"
		exit 0
	fi
	sleep 1
done
echo "unhealthy after ${timeout}s; rolling back" >&2
tail -20 "$doctor_out" >&2 || true
for b in ingressd ingressd-edge; do
	[[ -e /usr/local/bin/$b.old ]] && mv -f "/usr/local/bin/$b.old" "/usr/local/bin/$b"
done
restart || true
rm -rf "$dir"
exit 1
'

deployed=0
# The inventory is read on fd 3: ssh would swallow it on stdin.
while read -r name target port _ <&3; do
	[[ -z ${name:-} || $name == \#* ]] && continue
	if [[ -n $ONLY && ",$ONLY," != *",$name,"* ]]; then
		continue
	fi
	[[ -n ${target:-} ]] || { echo "inventory line for $name has no user@host" >&2; exit 1; }
	ssh_=(ssh "${SSH_OPTS[@]}" -p "${port:-22}" "$target")
	scp_=(scp "${SSH_OPTS[@]}" -P "${port:-22}" -q)
	echo "::group::$name ($target)"
	if [[ $DRY_RUN -eq 1 ]]; then
		echo "dry run: would deploy $VERSION to $name ($target, port ${port:-22})"
		echo "::endgroup::"
		deployed=$((deployed + 1))
		continue
	fi
	case $("${ssh_[@]}" uname -m) in
	x86_64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "::error::$name: unsupported architecture"; exit 1 ;;
	esac
	for b in ingressd ingressd-edge; do
		[[ -f $RELEASE_DIR/${b}_linux_$arch ]] || { echo "::error::release has no ${b}_linux_$arch"; exit 1; }
	done
	rdir=$("${ssh_[@]}" mktemp -d /tmp/ingressd-deploy.XXXXXX)
	"${scp_[@]}" "$RELEASE_DIR/ingressd_linux_$arch" "$RELEASE_DIR/ingressd-edge_linux_$arch" "$RELEASE_DIR/SHA256SUMS" "$RELEASE_DIR/SHA256SUMS.minisig" "$target:$rdir/"
	if ! "${ssh_[@]}" sudo bash -s -- "$rdir" "$VERSION" "$arch" "$HEALTH_TIMEOUT" <<<"$REMOTE"; then
		echo "::error::$name: deployment failed and was rolled back; stopping the rollout"
		echo "::endgroup::"
		exit 1
	fi
	echo "::endgroup::"
	deployed=$((deployed + 1))
done 3<<<"$DEPLOY_HOSTS"

[[ $deployed -gt 0 ]] || { echo "::error::no inventory entries matched"; exit 1; }
echo "Deployed $VERSION to $deployed node(s)."
