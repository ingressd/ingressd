#!/usr/bin/env bash
# What a change affects: the netns e2e suites (via test/netns/affected.map)
# and the Go packages whose tests must run (the changed packages plus every
# package that depends on them, in the same module).
#
#   scripts/affected.sh [--base REF] [--all] files
#   scripts/affected.sh [--base REF] [--all] suites [--json]
#   scripts/affected.sh [--base REF] [--all] packages [MODULE_DIR]
#   scripts/affected.sh list-suites [--json]
#
# The change set is `git diff` from the merge base of REF and HEAD, plus
# uncommitted and untracked files. REF defaults to $AFFECTED_BASE, else
# origin/main. --all (or
# AFFECTED_ALL=1) pretends everything changed. `packages` prints import paths
# for `go test` (cd MODULE_DIR first: "." or "edge"), or "./..." when the
# whole module is affected, or nothing. AFFECTED_FILES="a b ..." replaces
# the git change set (to try a mapping: AFFECTED_FILES=internal/l4/x.go).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
MAP=test/netns/affected.map
# AFFECTED_GIT_DIR: for checkouts whose .git points elsewhere (e.g. a Windows
# worktree read from WSL). Only used for these read-only git commands.
gitq() {
	if [[ -n ${AFFECTED_GIT_DIR:-} ]]; then GIT_DIR=$AFFECTED_GIT_DIR GIT_WORK_TREE=$ROOT git "$@"; else git "$@"; fi
}

BASE=${AFFECTED_BASE:-}
ALL=${AFFECTED_ALL:-0}
while [[ $# -gt 0 ]]; do
	case $1 in
	--base) BASE=$2; shift 2 ;;
	--base=*) BASE=${1#*=}; shift ;;
	--all) ALL=1; shift ;;
	*) break ;;
	esac
done
CMD=${1:-suites}
shift || true

all_suites() {
	local f n
	for f in test/netns/*-e2e.sh; do
		[[ -f $f ]] || continue
		n=${f##*/}
		n=${n%-e2e.sh}
		echo "${n%.sh}"
	done | sort -V
}

json() { # lines on stdin -> compact JSON array of strings
	local first=1 l
	printf '['
	while IFS= read -r l; do
		[[ -n $l ]] || continue
		[[ $first == 1 ]] || printf ','
		first=0
		printf '"%s"' "$l"
	done
	printf ']\n'
}

changed_files() {
	if [[ -n ${AFFECTED_FILES:-} ]]; then
		tr ' ' '\n' <<<"$AFFECTED_FILES" | grep -v '^$' | sort -u
		return
	fi
	if [[ -z $BASE ]]; then
		BASE=origin/main
	fi
	local mb
	mb=$(gitq merge-base "$BASE" HEAD 2>/dev/null) || {
		echo "affected.sh: no merge base with $BASE (fetch it, or pass --base); assuming everything changed" >&2
		echo "__ALL__"
		return
	}
	{
		gitq diff --name-only "$mb"
		gitq ls-files --others --exclude-standard
	} | sort -u
}

# suites_for <file>: the suites of the first matching map line ("all"/"none").
suites_for() {
	local f=$1 glob rest
	while read -r glob rest; do
		[[ -z $glob || $glob == \#* ]] && continue
		# shellcheck disable=SC2053 # $glob is a pattern on purpose
		if [[ $f == $glob ]]; then
			echo "$rest"
			return
		fi
	done <"$MAP"
	echo all
}

affected_suites() {
	[[ $ALL == 1 ]] && { all_suites; return; }
	local f s out=()
	while IFS= read -r f; do
		[[ -n $f ]] || continue
		[[ $f == __ALL__ ]] && { all_suites; return; }
		s=$(suites_for "$f")
		case $s in
		all)
			[[ -n ${AFFECTED_DEBUG:-} ]] && echo "affected.sh: $f -> all" >&2
			all_suites
			return
			;;
		none) ;;
		*) for x in $s; do out+=("$x"); done ;;
		esac
		[[ -n ${AFFECTED_DEBUG:-} ]] && echo "affected.sh: $f -> $s" >&2
	done < <(changed_files)
	local known
	known=$(all_suites)
	for x in "${out[@]}"; do
		if grep -qx -- "$x" <<<"$known"; then echo "$x"; else echo "affected.sh: $MAP names unknown suite $x" >&2; fi
	done | sort -uV
}

# affected_packages <module dir>: see the header.
affected_packages() {
	local mod=${1:-.} prefix=""
	[[ $mod == . ]] || prefix=${mod%/}/
	(
		[[ $ALL == 1 ]] && { echo ./...; exit 0; }
		files=$(changed_files)
		[[ $files == *__ALL__* ]] && { echo ./...; exit 0; }
		dirs=()
		while IFS= read -r f; do
			[[ -n $f ]] || continue
			if [[ -n $prefix ]]; then
				[[ $f == "$prefix"* ]] || continue
				f=${f#"$prefix"}
			else
				# Another module (edge/go.mod) is not part of this one.
				[[ $f == edge/* ]] && continue
			fi
			case $f in
			go.mod | go.sum) echo ./...; exit 0 ;;
			*.md | docs/* | *.sh | .github/*) continue ;;
			esac
			[[ $f == */* ]] && dirs+=("${f%/*}") || dirs+=(".")
		done <<<"$files"
		[[ ${#dirs[@]} -gt 0 ]] || exit 0
		cd "$mod"
		# Every package: <import path> <dir> <deps> <test imports> (lists
		# comma-separated, "-" when empty).
		go list -f '{{.ImportPath}} {{.Dir}} -{{range .Deps}},{{.}}{{end}} -{{range .TestImports}},{{.}}{{end}}{{range .XTestImports}},{{.}}{{end}}' ./... |
			awk -v root="$PWD" -v dirs="$(printf '%s
' "${dirs[@]}" | sort -u | tr '
' ' ')" '
			BEGIN { n = split(dirs, d, " "); for (i = 1; i <= n; i++) want[d[i]] = 1 }
			{
				ip = $1; dir = $2; sub("^" root "/?", "", dir); if (dir == "") dir = "."
				pkgdir[ip] = dir; deps[ip] = $3; tdeps[ip] = $4; order[++np] = ip
			}
			function hits(list, set,    m, j, l) {
				m = split(list, l, ",")
				for (j = 2; j <= m; j++) if (l[j] in set) return 1
				return 0
			}
			END {
				# A changed file marks its package, or (testdata, embedded
				# assets) the nearest enclosing package directory.
				for (w in want) {
					p = w
					while (1) {
						found = 0
						for (ip in pkgdir) if (pkgdir[ip] == p) { changed[ip] = 1; found = 1 }
						if (found || p == ".") break
						if (index(p, "/") == 0) p = "."; else sub("/[^/]*$", "", p)
					}
				}
				# Packages whose code depends on a changed one...
				for (i = 1; i <= np; i++) { ip = order[i]; if ((ip in changed) || hits(deps[ip], changed)) aff[ip] = 1 }
				# ...and packages whose tests import any of those.
				for (i = 1; i <= np; i++) { ip = order[i]; if ((ip in aff) || hits(tdeps[ip], aff)) print ip }
			}' | grep -v '^$' | sort -u || true
	)
}

case $CMD in
files) changed_files ;;
list-suites) if [[ ${1:-} == --json ]]; then all_suites | json; else all_suites; fi ;;
suites) if [[ ${1:-} == --json ]]; then affected_suites | json; else affected_suites; fi ;;
packages) affected_packages "${1:-.}" ;;
*) sed -n '2,17p' "$0" >&2; exit 2 ;;
esac
