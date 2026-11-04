#!/usr/bin/env bash
# Builds every release binary into a directory with release.json and
# SHA256SUMS.
#   scripts/build-release.sh [out-dir]          (default: dist)
# Used by `make release-local` and .github/workflows/release.yml, so a local
# build and a tagged release produce the same file names:
#   ingressd_<os>_<arch>, ingressd-edge_<os>_<arch>   (node, Linux only)
#   ingressd-connector_<os>_<arch>[.exe]                (home side)
#   install-connector.sh, install-node.sh
#   release.json   release manifest (pkg/release): version, channel,
#                  min_supported, security, notes_url and the sha256 of
#                  every file
#   SHA256SUMS     checksums of every file, release.json included
# The names match pkg/release.AssetName, so `ingressd upgrade` and
# panel-driven updates accept a release once release.json and SHA256SUMS
# are signed (*.minisig, see release.yml and docs/RELEASING.md).
#
# VERSION is the semantic version stamped into the binaries. It defaults to
# `git describe --tags`: exactly vX.Y.Z on a release tag, a dev version
# such as v1.2.3-4-gabc1234 between tags (panels show those as "unknown",
# never as outdated). release.json is only written for release versions
# (vX.Y.Z or vX.Y.Z-pre).
# Environment: VERSION, COMMIT (default from git), GO, NODE_TARGETS,
# CONNECTOR_TARGETS (space-separated os/arch lists), and for release.json
# MIN_SUPPORTED, SECURITY=1, NOTES_URL, CHANNEL, RELEASE_KEY (sign with this
# unencrypted minisign key; CI signs with the minisign CLI instead).
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=${1:-dist}
GO=${GO:-go}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
COMMIT=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}
NODE_TARGETS=${NODE_TARGETS:-"linux/amd64 linux/arm64"}
CONNECTOR_TARGETS=${CONNECTOR_TARGETS:-"linux/amd64 linux/arm64 linux/arm darwin/arm64 darwin/amd64 windows/amd64"}
PKG=github.com/ingressd/ingressd
LDFLAGS="-s -w -X $PKG/internal/version.Version=$VERSION -X $PKG/internal/version.Commit=$COMMIT"
export CGO_ENABLED=0 GOARM=7

rm -rf "$OUT"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

for t in $NODE_TARGETS; do
	os=${t%/*} arch=${t#*/}
	echo "==> ingressd, ingressd-edge $os/$arch"
	GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags "$LDFLAGS" -o "$OUT/ingressd_${os}_$arch" ./cmd/ingressd
	(cd edge && GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags "-s -w" -o "$OUT/ingressd-edge_${os}_$arch" ./cmd/ingressd-edge)
done
for t in $CONNECTOR_TARGETS; do
	os=${t%/*} arch=${t#*/} ext=""
	[[ $os == windows ]] && ext=.exe
	echo "==> ingressd-connector $os/$arch"
	GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags "$LDFLAGS" -o "$OUT/ingressd-connector_${os}_$arch$ext" ./cmd/ingressd-connector
done
cp deploy/install-connector.sh deploy/install-node.sh "$OUT/"

semver='^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.]+)?$'
if [[ $VERSION =~ $semver && $VERSION != *-g* && $VERSION != *dirty* ]]; then
	args=(--dir "$OUT" --version "$VERSION" --channel "${CHANNEL:-stable}")
	[[ -n ${MIN_SUPPORTED:-} ]] && args+=(--min-supported "$MIN_SUPPORTED")
	[[ ${SECURITY:-} == 1 || ${SECURITY:-} == true ]] && args+=(--security)
	[[ -n ${NOTES_URL:-} ]] && args+=(--notes-url "$NOTES_URL")
	[[ -n ${RELEASE_KEY:-} ]] && args+=(--key "$RELEASE_KEY")
	echo "==> release.json"
	"$GO" run ./scripts/releasetool manifest "${args[@]}" # also writes SHA256SUMS
else
	echo "==> $VERSION is not a release version: no release.json"
	(cd "$OUT" && sha256sum -- * >"$OUT/.SHA256SUMS" && mv "$OUT/.SHA256SUMS" "$OUT/SHA256SUMS")
fi
echo "==> $OUT ($VERSION)"
cat "$OUT/SHA256SUMS"
