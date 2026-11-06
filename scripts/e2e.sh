#!/usr/bin/env bash
# Fast netns end-to-end runner: builds the binaries once (incrementally, Go
# build cache), then runs the selected suites in parallel and prints a
# summary. Needs Linux and root for the suites (it re-runs them through
# sudo when started as a normal user; the build runs as you).
#
#   scripts/e2e.sh                       # every suite
#   scripts/e2e.sh l4-forwarding managed-node      # by name (or path)
#   scripts/e2e.sh --changed [REF]       # suites affected by the diff to REF
#   scripts/e2e.sh -j 4 --no-build ...
#
# Options / environment:
#   -j N, E2E_JOBS=N     parallel suites (default: nproc)
#   E2E_SERIAL=1         one suite at a time, under flock $E2E_LOCK
#                        (default /tmp/ingressd-e2e.lock)
#   --no-build, E2E_NO_BUILD=1   use the binaries already in $BIN
#   E2E_TIMEOUT=SECS     per-suite timeout (default 600)
#   E2E_OUT=DIR          logs (default a new /tmp/ingressd-e2e.XXXXXX)
#   E2E_TMP=DIR          suite temp dirs (default tmp below that directory);
#                        every user must be able to enter it (connector-transports runs
#                        the connector as nobody on files below it)
#   BIN=DIR              binaries (default ./bin)
#   E2E_REPEAT=N         run the selection N times (flake hunting)
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit
export BIN=${BIN:-$ROOT/bin}

JOBS=${E2E_JOBS:-$(nproc)}
BUILD=1
[[ ${E2E_NO_BUILD:-0} == 1 ]] && BUILD=0
SEL=()
CHANGED=""
while [[ $# -gt 0 ]]; do
	case $1 in
	-j) JOBS=$2; shift 2 ;;
	-j*) JOBS=${1#-j}; shift ;;
	--no-build) BUILD=0; shift ;;
	--changed)
		CHANGED=--changed
		if [[ ${2:-} != "" && ${2:-} != -* && ! -f test/netns/$2-e2e.sh && ! -f test/netns/$2.sh ]]; then CHANGED_BASE=$2; shift; fi
		shift ;;
	-h | --help) sed -n '2,21p' "$0"; exit 0 ;;
	*) SEL+=("$1"); shift ;;
	esac
done
[[ ${E2E_SERIAL:-0} == 1 ]] && JOBS=1

suite_path() { # name or path -> path
	local s=$1
	[[ -f $s ]] && { echo "$s"; return; }
	s=${s%.sh}; s=${s%-e2e}
	for f in "test/netns/$s-e2e.sh" "test/netns/$s.sh"; do [[ -f $f ]] && { echo "$f"; return; }; done
	echo "e2e.sh: unknown suite $1" >&2
	return 1
}

# --- Selection -----------------------------------------------------------------
if [[ -n $CHANGED ]]; then
	mapfile -t SEL < <(scripts/affected.sh ${CHANGED_BASE:+--base "$CHANGED_BASE"} suites)
	if [[ ${#SEL[@]} -eq 0 ]]; then echo "e2e: no suite affected by the change"; exit 0; fi
elif [[ ${#SEL[@]} -eq 0 ]]; then
	mapfile -t SEL < <(scripts/affected.sh list-suites)
fi
TESTS=()
for s in "${SEL[@]}"; do p=$(suite_path "$s") || exit 2; TESTS+=("$p"); done

# --- Build (as the invoking user) ------------------------------------------------
if [[ $BUILD == 1 ]]; then
	t0=$SECONDS
	export CGO_ENABLED=0
	mkdir -p "$BIN"
	# Built concurrently; go reuses the build cache, so an unchanged tree
	# only relinks. Test helpers (fakepanel, sdtool, fakeidp and the
	# idptest build of ingressd for access-idp) are tiny.
	(go build -o "$BIN/" ./cmd/... && go build -o "$BIN/fakepanel" ./test/fakepanel/cmd/fakepanel &&
		go build -o "$BIN/ingressd-sdtool" ./test/netns/sdtool && go build -o "$BIN/realmtool" ./test/netns/realmtool && go build -o "$BIN/fakeidp" ./test/fakeidp/cmd/fakeidp &&
		go build -tags idptest -o "$BIN/ingressd-idptest" ./cmd/ingressd) >"${TMPDIR:-/tmp}/e2e-build-$$.log" 2>&1 &
	b1=$!
	(cd edge && go build -o "$BIN/ingressd-edge" ./cmd/ingressd-edge) >"${TMPDIR:-/tmp}/e2e-build-edge-$$.log" 2>&1 &
	b2=$!
	ok=1
	wait $b1 || ok=0
	wait $b2 || ok=0
	cat "${TMPDIR:-/tmp}/e2e-build-$$.log" "${TMPDIR:-/tmp}/e2e-build-edge-$$.log"
	rm -f "${TMPDIR:-/tmp}/e2e-build-$$.log" "${TMPDIR:-/tmp}/e2e-build-edge-$$.log"
	[[ $ok == 1 ]] || { echo "e2e: build failed" >&2; exit 1; }
	echo "build: $((SECONDS - t0))s"
fi

# --- Root for the suites -------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
	exec sudo --preserve-env=BIN,E2E_TIMEOUT,E2E_OUT,E2E_TMP,E2E_SERIAL,E2E_LOCK,E2E_REPEAT,TMPDIR \
		"$0" --no-build -j "$JOBS" "${TESTS[@]}"
fi

if [[ ${E2E_SERIAL:-0} == 1 && -z ${E2E_LOCKED:-} ]]; then
	export E2E_LOCKED=1
	exec flock "${E2E_LOCK:-/tmp/ingressd-e2e.lock}" "$0" --no-build -j 1 "${TESTS[@]}"
fi

# --- Run ------------------------------------------------------------------------------
RUN=$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')
BASE=$(mktemp -d /tmp/ingressd-e2e.XXXXXX) || exit
chmod 755 "$BASE"
OUT=${E2E_OUT:-$BASE}
mkdir -p "$OUT"
# Suite temp dirs live apart from the logs: $E2E_OUT may sit in a directory
# other users cannot enter (CI: $RUNNER_TEMP below /home/runner, mode 750),
# and suites drop privileges on files below their $TMP (connector-transports: nobody).
TMPBASE=${E2E_TMP:-$BASE/tmp}
mkdir -p "$TMPBASE"
chmod 755 "$TMPBASE"
TIMEOUT=${E2E_TIMEOUT:-600}
REPEAT=${E2E_REPEAT:-1}

# The queue: suite paths, longest first (from the last run's timings) so the
# slow ones do not start last.
TIMES=$BIN/.e2e-times
QUEUE=()
for ((r = 1; r <= REPEAT; r++)); do QUEUE+=("${TESTS[@]}"); done
if [[ -f $TIMES ]]; then
	mapfile -t QUEUE < <(for t in "${QUEUE[@]}"; do
		n=$(basename "$t" .sh)
		echo "$(awk -v n="$n" '$1 == n { s = $2 } END { print s + 0 }' "$TIMES") $t"
	done | sort -k1,1nr -s | cut -d' ' -f2-)
fi

# reap <id>: kills and deletes whatever the suite with run ID <id> left
# behind (its namespaces contain "-<id>-"), even after SIGKILL.
reap() {
	local id=$1 ns pids
	for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep -- "-$id-"); do
		pids=$(ip netns pids "$ns" 2>/dev/null)
		# shellcheck disable=SC2086
		[[ -n $pids ]] && kill -KILL $pids 2>/dev/null
		ip netns del "$ns" 2>/dev/null
		rm -rf "/etc/netns/$ns"
		echo "reaped $ns" >>"$OUT/reaped.log"
	done
}

declare -A PID2IDX
START=()
NAMES=() RC=() SECS=() PASSN=() FAILN=() LOGS=()
running=0 done_n=0 total=${#QUEUE[@]} failed=0
tty=0
[[ -t 1 ]] && tty=1

start_suite() { # start_suite <index>
	local i=$1 t=${QUEUE[$1]} n id
	n=$(basename "$t" .sh); n=${n%-e2e}
	id=$RUN$(printf '%02d' "$i")
	local log=$OUT/$n.log
	[[ $REPEAT -gt 1 ]] && log=$OUT/$n.$i.log
	NAMES[i]=$n LOGS[i]=$log
	mkdir -m 755 "$TMPBASE/$id"
	(
		unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY
		export E2E_RUN=$id TMPDIR=$TMPBASE/$id
		timeout -k 15 "$TIMEOUT" bash "$t" >"$log" 2>&1
		rc=$?
		reap "$id"
		rm -rf "${TMPBASE:?}/$id"
		exit $rc
	) &
	PID2IDX[$!]=$i
	START[i]=$(date +%s)
	running=$((running + 1))
}

progress() {
	local names="" i
	for i in "${PID2IDX[@]}"; do names+=" ${NAMES[i]}"; done
	local line
	line=$(printf '[%d/%d done, %d running, %d failed]%s' "$done_n" "$total" "$running" "$failed" "$names")
	if [[ $tty == 1 ]]; then printf '\r\033[K%s' "${line:0:$(( $(tput cols 2>/dev/null || echo 120) - 1 ))}"; fi
}

finish_suite() { # finish_suite <pid> <rc>
	local pid=$1 rc=$2 i=${PID2IDX[$1]}
	unset "PID2IDX[$pid]"
	running=$((running - 1))
	done_n=$((done_n + 1))
	RC[i]=$rc
	SECS[i]=$(($(date +%s) - START[i]))
	PASSN[i]=$(grep -c '^PASS' "${LOGS[i]}")
	FAILN[i]=$(grep -c '^FAIL' "${LOGS[i]}")
	local status=ok
	if [[ $rc -ne 0 || ${FAILN[i]} -ne 0 ]]; then status=FAIL; failed=$((failed + 1)); fi
	[[ $rc == 124 || $rc == 137 ]] && status=TIMEOUT
	[[ $tty == 1 ]] && printf '\r\033[K'
	printf '%-7s %-20s %3ds  pass=%-3d fail=%d\n' "$status" "${NAMES[i]}" "${SECS[i]}" "${PASSN[i]}" "${FAILN[i]}"
	if [[ $status != ok ]]; then
		grep '^FAIL' "${LOGS[i]}" | head -5 | cut -c1-200 | sed 's/^/        /'
		echo "        log: ${LOGS[i]}"
	fi
}

on_signal() {
	echo; echo "e2e: interrupted, stopping suites" >&2
	for pid in "${!PID2IDX[@]}"; do pkill -TERM -P "$pid" 2>/dev/null; kill -TERM "$pid" 2>/dev/null; done
	wait
	for ((i = 0; i < total; i++)); do reap "$RUN$(printf '%02d' "$i")"; done
	exit 130
}
trap on_signal INT TERM

echo "e2e: ${total} suite run(s), ${JOBS} in parallel, logs in $OUT"
T0=$(date +%s)
next=0
while [[ $next -lt $total || $running -gt 0 ]]; do
	while [[ $running -lt $JOBS && $next -lt $total ]]; do start_suite $next; next=$((next + 1)); done
	progress
	wait -n -p DONE_PID
	rc=$?
	[[ -n ${DONE_PID:-} && -n ${PID2IDX[$DONE_PID]:-} ]] && finish_suite "$DONE_PID" "$rc"
done
WALL=$(($(date +%s) - T0))
[[ -z ${E2E_TMP:-} ]] && rmdir "$TMPBASE" 2>/dev/null
rmdir "$BASE" 2>/dev/null

# --- Summary ------------------------------------------------------------------------
{
	echo
	printf '%-22s %-7s %6s %5s %5s\n' SUITE RESULT SECS PASS FAIL
	for ((i = 0; i < total; i++)); do
		r=ok
		[[ ${RC[i]} -ne 0 || ${FAILN[i]} -ne 0 ]] && r=FAIL
		[[ ${RC[i]} == 124 || ${RC[i]} == 137 ]] && r=TIMEOUT
		printf '%-22s %-7s %6d %5d %5d\n' "${NAMES[i]}" "$r" "${SECS[i]}" "${PASSN[i]}" "${FAILN[i]}"
	done | sort
} | tee "$OUT/summary.txt"
tp=0 tf=0
for ((i = 0; i < total; i++)); do tp=$((tp + PASSN[i])) tf=$((tf + FAILN[i])); done
echo "e2e: $((total - failed))/$total suites ok, $tp checks passed, $tf failed, ${WALL}s wall" | tee -a "$OUT/summary.txt"
[[ -s $OUT/reaped.log ]] && echo "e2e: reaped leftovers (suite cleanup missed them): $(wc -l <"$OUT/reaped.log")"

# Remember durations for the next run's ordering.
mkdir -p "$(dirname "$TIMES")"
{
	for ((i = 0; i < total; i++)); do echo "$(basename "${QUEUE[i]}" .sh) ${SECS[i]}"; done
	[[ -f $TIMES ]] && cat "$TIMES"
} | awk '!seen[$1]++' >"$TIMES.new" && mv "$TIMES.new" "$TIMES"

[[ $failed -eq 0 ]]
