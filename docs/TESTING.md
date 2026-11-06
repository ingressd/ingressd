# Testing

What runs where, how to run it fast, and how to add a network-namespace
(netns) end-to-end suite.

## Commands

| Command | What it does | Typical time (dev box, warm cache) |
|---|---|---|
| `make check` | gofmt + `go vet` + `go test` for the packages the change affects (both modules), then the affected netns suites | 10 s (docs-only: nothing) to ~75 s |
| `make check-all` | the same for everything | ~100 s (unit tests 33 s + e2e 67 s) |
| `make e2e` | every netns suite in parallel (builds first) | **~75 s** (was ~10 min serial) |
| `make e2e E2E_TESTS="l4-forwarding managed-node"` | the named suites | the slowest one |
| `make e2e-changed [BASE=ref]` | only the suites the change affects | |
| `make affected [BASE=ref]` | prints the affected suites and packages | 1–5 s |
| `make test` | `go test ./...` in both modules | |

"The change" is the diff from the merge base with `origin/main` (or
`BASE=<ref>`) plus uncommitted and untracked files.

The scripts behind the targets can be run directly (no make in WSL):
`scripts/e2e.sh`, `scripts/check.sh [--all] [--base REF] [--no-e2e]`,
`scripts/affected.sh suites|packages|files`.

### scripts/e2e.sh

```sh
scripts/e2e.sh                     # all suites
scripts/e2e.sh l4-forwarding managed-node    # by name (test/netns/<name>-e2e.sh) or path
scripts/e2e.sh --changed [REF]     # affected suites only
scripts/e2e.sh -j 4 --no-build ... # 4 at a time, binaries already in bin/
E2E_SERIAL=1 scripts/e2e.sh        # one at a time (under flock /tmp/ingressd-e2e.lock)
E2E_REPEAT=5 scripts/e2e.sh connector-join   # flake hunting: 5 concurrent runs
```

1. Builds `bin/ingressd`, `ingressd-connector`, `ingressd-edge`,
   `fakepanel`, `ingressd-sdtool`, `fakeidp` (fake Discord/Google/Microsoft/
   Steam) and `ingressd-idptest` (ingressd built with `-tags idptest`, the only
   build that honours `INGRESSD_IDP_TEST_BASE`; used by access-idp) (the root
   module and the edge module build concurrently; the Go build cache means an unchanged tree builds in ~1 s).
2. Runs the suites as root (re-execs through `sudo` if needed) in a worker
   pool of `nproc` (`-j`/`E2E_JOBS`), longest first (timings from the last
   run in `/tmp/ingressd-e2e/times`), with a one-line live progress display.
3. Logs per suite in `/tmp/ingressd-e2e/<run>/<suite>.log` (`E2E_OUT`),
   failures printed inline, a summary table at the end, exit status 1 if any
   suite failed or timed out (`E2E_TIMEOUT`, default 600 s per suite).
4. Each suite gets a unique run ID (`E2E_RUN`) and its own `TMPDIR` (below
   `/tmp/ingressd-e2e/<run>/tmp`, `E2E_TMP`, never below `E2E_OUT`: connector-transports
   runs the connector as `nobody`, so every directory above it must be
   enterable by other users; lib.sh falls back to `/tmp` if not); after
   it exits the runner deletes any namespace still carrying that ID and
   kills what runs in it, even if the suite was killed with SIGKILL.

No global lock is needed any more: suites from different runs, checkouts
and agents can run at the same time (old-style runs of an unconverted
branch still use fixed names, so keep those under `flock /tmp/he-e2e.lock`).

### On Windows (WSL)

Go and the suites run in WSL (`docs/CONTRIBUTING.md`). Root is needed for
the netns suites:

```sh
wsl -d Ubuntu -u root -- bash -c 'export PATH=/home/<you>/.local/go/bin:$PATH; cd /mnt/c/.../ingressd && scripts/e2e.sh'
```

A `git worktree` created by Windows git has a `.git` file pointing at a
`C:/...` path that WSL's git cannot follow. `scripts/affected.sh` then
assumes everything changed; set `AFFECTED_GIT_DIR=/mnt/c/.../.git/worktrees/<name>`
to give it the right git directory (it uses it only for read-only `git
diff`/`merge-base`/`ls-files`). **Never export `GIT_DIR`/`GIT_WORK_TREE`
around the suites**: `ingressd init` runs `git init`, and with those set it
writes into the repository they name (lib.sh and e2e.sh unset them as a
safeguard).

## What runs when (CI, `.github/workflows/ci.yml`)

| Lane | Trigger | Runs |
|---|---|---|
| PR | `pull_request` | `plan` decides (`scripts/ci-plan.sh`): `go vet` + `go test -race` of the affected packages per module, lint (both modules, new issues only), `build` once (binaries as artifact `e2e-bin`, edge module check, example validation), connector cross-builds if the root module is affected, the affected netns suites as a matrix, `vuln` only if go.mod/go.sum changed, images only if Dockerfiles or dependencies changed. Docs-only PRs run only `plan` and `workflows + shell scripts`. |
| Full | push to `release`, manual | everything, every suite, then (release) the release |

Pull requests use no secrets and never save caches. Container images are built only by the release ([RELEASING.md](RELEASING.md)).

Each Go job has its own build/module cache (`.github/actions/go-cache`),
saved on pushes and restored by PRs from the base branch. (setup-go's
built-in cache shared one key between all jobs and kept whichever job
finished first, so the edge build was rarely cached: `end-to-end build`
took 4.5 min.)

**Required checks** (branch protection on `main`): only

- `checks (all)`: every non-e2e job (plan, control plane + connector,
  edge, build, lint, vuln, workflows + shell scripts, connector builds,
  images)
- `e2e (all suites)`: the build and every e2e matrix job

A job the plan skipped counts as passed; a failed or cancelled one fails
the aggregate. The names stay the same whatever the plan selects, so
branch protection never needs updating when suites are added.

## Unit tests

`go test ./...` (root) and `cd edge && go test ./...`. CI adds `-race`
(needs cgo). `make check` tests the packages that changed plus every
package that imports them (directly or not) and every package whose tests
import one of those (`scripts/affected.sh packages . | edge`). A change to
`go.mod`/`go.sum` tests the whole module.

## The netns suites

`test/netns/*-e2e.sh`, one per feature (the file name says what it covers): real WireGuard, nftables and
the real binaries in network namespaces on one Linux host (root). ~600
checks; the slowest suites (connector-join, connector-transports/6) take
~60–70 s each because they wait for real timers (handshakes, health
checks, failback holds), which is why they run in parallel.

### Writing a suite (parallel-safe conventions)

```bash
#!/usr/bin/env bash
# What this suite proves, the topology.
set -euo pipefail
P=he-xy                               # short, unique per suite
source "$(dirname "$0")/lib.sh"       # P becomes he-xy-<run id>; TMP, cleanup traps

build_topology                        # client, edge, site, lan (see lib.sh)
EXTRA=$P-extra
ns_add "$EXTRA"                       # extra namespaces: always via ns_add
veth "$EDGE" wan1 172.16.2.1/30 "$EXTRA" wan0 172.16.2.2/30
in_lan python3 -m http.server 8080 >/dev/null 2>&1 &
PIDS+=($!)
expect "app reachable" "hello" in_client curl -s http://...
finish
```

Rules (lib.sh enforces or relies on them):

1. **Names**: every namespace is `$P-<role>`; never hard-code a name. P
   carries the run ID after `source lib.sh`. `ns_add` refuses other names.
2. **Nothing in the root namespace**: start processes with `in_*`/`ip
   netns exec`, create links with `ip link add … netns …` (as `veth` does)
   so their names never exist in the root namespace, and keep nft tables,
   ip rules, routes, sysctls and listening ports inside the suite's
   namespaces. Interface names need only be unique per namespace (≤ 15
   characters).
3. **Files** under `$TMP` (a `mktemp -d` below `$TMPDIR`), never fixed
   `/tmp/...` paths. `/etc/netns/$NS/{hosts,resolv.conf}` is fine for the
   suite's own namespaces (removed by cleanup). Private mount namespaces
   (`unshare --mount` inside a suite namespace) are
   fine: their processes live in the suite's netns and are killed with it.
4. **Cleanup** is automatic: on exit and on INT/TERM/HUP (timeouts) lib.sh
   runs `on_cleanup` hooks, kills every process in the run's namespaces
   (TERM, then KILL after 2 s; also setsid'd daemons), deletes the
   namespaces, their `/etc/netns` entries and `$TMP`. Do not install your
   own `trap … EXIT`; use `on_cleanup '<command>'`.
5. **Waits**: poll for state (`expect` retries ~10 s; write a `wait_for`
   with a longer deadline when needed) instead of fixed `sleep`s, and do not
   depend on wall-clock timing tighter than a few seconds: suites run 16 at
   a time.
6. Report with `pass`/`fail` (lines starting `PASS `/`FAIL ` are counted)
   and end with `finish` (or `exit "$FAIL"`).

Converting an old suite: drop any `ip netns del/add` loop for
`ns_add "${NAMESPACES[@]}"`, drop `trap … EXIT` (move its body to
`on_cleanup`), replace fixed `/tmp` paths with `$TMP`. Then run it several
times concurrently: `E2E_REPEAT=8 scripts/e2e.sh <suite>`.

### Mapping paths to suites

`test/netns/affected.map` decides which suites a change runs (local
`make check` and CI PRs alike):

```
# <glob>                 <suite>... | all | none   (first match wins)
internal/smartdns/*      connector-smartdns
docs/*                   none
```

- `*` matches across `/`, so `internal/l4/*` covers the subtree.
- **Unmapped paths run every suite**: the default is conservative. Only
  add a line for a path once you know which suites exercise it.
- A new suite needs no entry to run (unmapped paths and shared code already
  select all suites); add `test/netns/<suite>-e2e.sh  <suite>` so editing
  the script runs only it, and add the suite to the lines of the feature
  packages it covers.
- Try a mapping without committing: `AFFECTED_FILES="internal/l4/x.go"
  scripts/affected.sh suites`.

## Timings

Measured on a development machine (WSL2, 32 cores; checkout on `/mnt/c`):

| | Before | After |
|---|---|---|
| Full local e2e (16 suites, ~600 checks), build cached | 574 s (serial, under the global lock; build ~30 s) | **70–78 s** |
| Typical selective check (smartdns change: vet+test 2 packages, 2 suites) | (full run) | **~70 s** |
| Docs-only change | (full run) | 0 s e2e |
| Flake check: 3 rounds × 16 suites × 3 copies (48 concurrent) | – | 144/144 passed |
| CI, full push (wall) | ~6.8 min (critical path: `go test -race ./...` 6.6 min, `end-to-end build` 4.5 min) | expected ≲ 4 min with warm per-job caches (not yet measured on GitHub) |
| CI, PR touching one feature package | same as push | plan + affected packages + affected suites only |

