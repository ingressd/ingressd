#!/usr/bin/env bash
# Pre-push check scoped to what changed (make check) or everything
# (make check-all): gofmt, go vet and go test for the affected packages of
# both modules (the changed ones plus their reverse dependencies), then the
# affected netns e2e suites (scripts/e2e.sh, root).
#
#   scripts/check.sh [--all] [--base REF] [--no-e2e] [--race]
#
# The change set is the diff to the merge base with REF (default
# origin/main) plus uncommitted and untracked
# files; see scripts/affected.sh. --race needs cgo (CGO_ENABLED=1, a C
# compiler).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
GO=${GO:-go}
AFF=(scripts/affected.sh)
E2E=1
RACE=()
while [[ $# -gt 0 ]]; do
	case $1 in
	--all) AFF+=(--all); shift ;;
	--base) AFF+=(--base "$2"); shift 2 ;;
	--no-e2e) E2E=0; shift ;;
	--race) RACE=(-race); export CGO_ENABLED=1; shift ;;
	-h | --help) sed -n '2,12p' "$0"; exit 0 ;;
	*) echo "check.sh: unknown argument $1" >&2; exit 2 ;;
	esac
done

step() { printf '\n== %s\n' "$*"; }
T0=$SECONDS
rc=0

for mod in . edge; do
	mapfile -t pkgs < <("${AFF[@]}" packages "$mod")
	label=$([[ $mod == . ]] && echo "control plane module" || echo "edge module")
	if [[ ${#pkgs[@]} -eq 0 ]]; then
		step "$label: no affected packages"
		continue
	fi
	step "$label: ${#pkgs[@]} package(s)$([[ ${pkgs[0]} == ./... ]] && echo " (all)")"
	t=$SECONDS
	(
		cd "$mod"
		if [[ ${pkgs[0]} == ./... ]]; then dirs=(.); else mapfile -t dirs < <($GO list -f '{{.Dir}}' "${pkgs[@]}"); fi
		unformatted=$(gofmt -l "${dirs[@]}" 2>/dev/null || true)
		if [[ -n $unformatted ]]; then echo "gofmt needed:"; echo "$unformatted"; exit 1; fi
		$GO vet "${pkgs[@]}"
		$GO test "${RACE[@]}" "${pkgs[@]}"
	) || rc=1
	echo "($label: $((SECONDS - t))s)"
done

if [[ $E2E == 1 ]]; then
	if [[ $(uname -s) != Linux ]]; then
		step "e2e: skipped (needs Linux)"
	else
		mapfile -t suites < <("${AFF[@]}" suites)
		if [[ ${#suites[@]} -eq 0 ]]; then
			step "e2e: no affected suites"
		else
			step "e2e: ${suites[*]}"
			scripts/e2e.sh "${suites[@]}" || rc=1
		fi
	fi
fi

printf '\ncheck: %s in %ss\n' "$([[ $rc == 0 ]] && echo ok || echo FAILED)" "$((SECONDS - T0))"
exit $rc
