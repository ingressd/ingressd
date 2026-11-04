#!/usr/bin/env bash
# CI planner (the `changes` job): decides what a run checks and writes it to
# $GITHUB_OUTPUT (or stdout). Pull requests get the affected subset
# (scripts/affected.sh against the PR base); pushes, the nightly schedule
# and manual runs get everything.
#
# Outputs:
#   full        true when everything runs
#   go          root module affected (unit tests, build, connector builds)
#   go_pkgs     packages for `go test` in the root module ("./..." = all)
#   edge        edge module affected
#   edge_pkgs   packages for `go test` in edge/
#   deps        go.mod/go.sum changed (vuln, docker)
#   docker      Dockerfiles or what the images contain changed
#   suites      JSON array of netns e2e suites ([] = none)
#   e2e         suites is not empty
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
OUT=${GITHUB_OUTPUT:-/dev/stdout}

full=false
args=()
if [[ ${CI_FULL:-} == true || ${GITHUB_EVENT_NAME:-} != pull_request ]]; then
	full=true
	args=(--all)
else
	args=(--base "origin/${GITHUB_BASE_REF:?}")
fi

files=$(scripts/affected.sh "${args[@]}" files)
has() { grep -Eq "$1" <<<"$files"; }

go_pkgs=$(scripts/affected.sh "${args[@]}" packages . | tr '\n' ' ' | sed 's/ $//')
edge_pkgs=$(scripts/affected.sh "${args[@]}" packages edge | tr '\n' ' ' | sed 's/ $//')
suites=$(scripts/affected.sh "${args[@]}" suites --json)

deps=false docker=false
if [[ $full == true ]] || has '(^|/)go\.(mod|sum)$'; then deps=true; fi
if [[ $full == true || $deps == true ]] || has '^(Dockerfile|\.dockerignore|deploy/docker/)'; then docker=true; fi

{
	echo "full=$full"
	echo "go=$([[ -n $go_pkgs ]] && echo true || echo false)"
	echo "go_pkgs=$go_pkgs"
	echo "edge=$([[ -n $edge_pkgs ]] && echo true || echo false)"
	echo "edge_pkgs=$edge_pkgs"
	echo "deps=$deps"
	echo "docker=$docker"
	echo "suites=$suites"
	echo "e2e=$([[ $suites != "[]" ]] && echo true || echo false)"
} | tee -a "$OUT"
if [[ $OUT != /dev/stdout && -n ${GITHUB_STEP_SUMMARY:-} ]]; then
	{
		echo "### What this run checks"
		echo "- full: $full, deps changed: $deps, docker: $docker"
		echo "- root module packages: ${go_pkgs:-none}"
		echo "- edge module packages: ${edge_pkgs:-none}"
		echo "- e2e suites: $suites"
	} >>"$GITHUB_STEP_SUMMARY"
fi
