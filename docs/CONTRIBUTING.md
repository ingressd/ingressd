# Contributing

How the code fits together, where new features plug in, and how to build and test. Read [DESIGN.md](DESIGN.md) for the design, [rev1/ARCHITECTURE.md](rev1/ARCHITECTURE.md) for the node ↔ panel contracts and [TESTING.md](TESTING.md) for the test lanes. Report security issues privately as described in [SECURITY.md](../SECURITY.md), not in public issues.

## Architecture in one paragraph

`config.yaml` (+ `secrets.age`) is the only source of truth; on a managed node the panel writes it from signed snapshots (`internal/nodeagent`) and local edits are ignored. `ingressd apply` runs **load → validate → ensure keys → render → diff → apply → git commit**. There is no local admin UI or REST API (removed in rev1): standalone nodes are managed with the CLI, managed nodes by the hosted panel. `internal/render` is pure: it turns a config into a `render.Plan` (Caddy JSON, an nftables script, kernel network state). `internal/apply` pushes a plan to the kernel (netlink/wgctrl), nftables (`nft -f`, atomic) and Caddy (admin API on a unix socket), rolling back to the last good plan on failure. `ingressd serve` re-applies at startup and on config changes, and runs the **control server** (`internal/controlsrv`): one HTTP server on `<run-dir>/control.sock` that Caddy forwards the control hostnames to, dispatching by Host.

## Package map

| Package | Role |
|---|---|
| `pkg/config` | Types, parsing (strict), defaults (`load.go`), validation (`validate.go`) |
| `internal/secrets` | age-encrypted secrets; `secret://name` resolution; `Redact` |
| `internal/gitstore` | git history of the config dir |
| `internal/render` | config → `Plan`. One file per concern: `caddy.go`, `nft.go`, `network.go`, `control.go` |
| `internal/apply` | Plan → system; rollback; diff |
| `internal/pki` | Origin CA: root + origin/edge-client issuers, issuing, CSR signing, PFX, snippets, inventory; `Ensure` runs in the apply pipeline |
| `internal/tunnel` | WireGuard keys, site configs, tunnel status |
| `internal/controlsrv` | Host-routed control HTTP server, `ClientIP` |
| `internal/pipeline` | The apply pipeline shared by the CLI, serve and the node agent (validate → render → diff → apply → commit), serialized per process |
| `internal/nodeagent` | Managed mode (rev1): enrolment (`node.json`), the WebSocket control channel to the panel, signed snapshots applied through the pipeline, status/usage/live logs/diagnostics, node-answered requests, exit routing hooks (`hooks.go`), detach |
| `internal/edgecert` | Edge certificates in Caddy storage (`ingressd cert list`, managed-mode cert status) and the internal CA root |
| `pkg/nodeproto` | Panel ↔ node protocol types (shared with the panel; additive changes only) |
| `test/fakepanel` | Minimal panel (enrol + control channel + `/test/` API) for unit and netns tests of managed mode |
| `cmd/ingressd` | CLI; one `cmd_*.go` per command group; `control.go` registers control-host handlers |
| `edge/` | Separate Go module: custom Caddy build + ingressd Caddy modules (`edge/modules/*`) |

## Extension points (keep edits to shared files small)

Several features are developed in parallel. To keep merges easy, put new logic in **new files/packages** and touch shared files only with small hooks:

- **Config:** replace the section's `yaml.Node` placeholder in `types.go` with a typed struct (define the struct in a new file `pkg/config/<feature>.go`). Add defaults to `applyDefaults` and validation as a `validate<Feature>(v)` method in your new file, called from `Validate()` (one line).
- **Caddy rendering:** write `internal/render/<feature>.go`. Hook it in with one line where it belongs: `appHandlers` (per-app middleware, in this order: control → auth → security → cache → proxy), `reverseProxy` (upstream/transport changes), `renderTLS`, or `renderCaddy` (new top-level apps such as `layer4`).
- **nftables:** add a `render<Feature>NFT(cfg) string` function and append its output in `renderNFT`. Use your own table (e.g. `table ip ingressd_l4`) and add the matching `add table …; delete table …` pair at the top so applies stay atomic.
- **Control hosts:** add your hostname to `render.ControlHosts` and your handler in `cmd/ingressd/control.go`.
- **CLI:** new `cmd/ingressd/cmd_<feature>.go`; register it in `newRootCmd` (one line).
- **Caddy modules:** new package under `edge/modules/<name>`, imported in `edge/cmd/ingressd-edge/main.go`, added to `scripts/check-edge-modules.sh`. Module IDs use the `ingressd_` or `edge_` prefix as in DESIGN.md.
- **Shared runtime state for Caddy modules:** pass it in the rendered Caddy JSON (module config), not via files.
- **Managed mode:** panel messages are handled in `internal/nodeagent/agent.go` (`dispatch`); new protocol fields go into `pkg/nodeproto` additively. The node exit and mesh (`smartdns`, `mesh`) report through the small interfaces in `internal/nodeagent/hooks.go`, registered with `nodeagent.SetSmartDNS(v)`; connectors' Smart DNS state arrives in their health reports (`internal/connector/store.go`).
- **Machine endpoints:** `/.ingressd/` (connector enrolment/poll/report/discovery, WireGuard-over-WebSocket) are served on `edge.admin.hostname` and, once a node has enrolled, on its own hostname or bare public IP (`render.Options.MachineHost`; a bare IP gets a certificate from Caddy's internal CA, which the connector join string pins).

## Conventions

- Match the surrounding code: comment density, naming, error wrapping (`fmt.Errorf("...: %w", err)`), table-driven tests.
- Validation errors use YAML paths (`apps.web.waf.mode: ...`).
- Never print secrets: pass diff/log output through `secrets.Store.Redact`.
- Update `examples/config.yaml` for new config, and golden files with `go test ./internal/render -update` (review the diff).
- New features add a netns end-to-end test `test/netns/<feature>-e2e.sh` using `test/netns/lib.sh` and its parallel-safe conventions (unique `P=he-xy`, extra namespaces via `ns_add`, files under `$TMP`, nothing in the root namespace; see `docs/TESTING.md`), and a line in `test/netns/affected.map`. Run suites with `scripts/e2e.sh` (parallel) and changes with `make check`. Managed-mode tests use `bin/fakepanel` (`go build -o bin/fakepanel ./test/fakepanel/cmd/fakepanel`).
- Comments explain *why*, not *what*: no comment where the code already says it, no commented-out code, no change logs or TODO notes in comments.

## Commit messages

- Start with a short summary line in the imperative (`smartdns: refresh edge checks on reconfigure`), prefixed with the area where it helps.
- Follow with a blank line and one bullet per change, each a single sentence.
- End with a `Signed-off-by` line (see below) and no other trailers: no `Co-Authored-By` lines for AI tools.

```text
smartdns: refresh edge checks on reconfigure

- Reload the configured checks whenever a new config is applied.
- Drop cached results for domains that no longer have a check.

Signed-off-by: Your Name <you@example.com>
```

## Building and testing on Windows (WSL)

The edge build and the netns tests are Linux-only. On Windows, with Go installed inside WSL (for example in `~/.local/go/bin`). Passing commands from PowerShell to WSL mangles quotes, so put commands in a script file and run it:

```powershell
wsl -d Ubuntu -- bash /mnt/c/path/to/script.sh                 # as the normal user (builds, unit tests)
wsl -d Ubuntu -u root -- bash /mnt/c/path/to/test/netns/tunnel-http-e2e.sh   # netns tests need root
```

Inside the script: `export PATH=$HOME/.local/go/bin:$PATH` and `cd` to the repo's `/mnt/c/...` path (or your worktree's). Typical script:

```bash
export PATH="$HOME/.local/go/bin:$PATH" CGO_ENABLED=0
cd /mnt/c/.../your-checkout
go vet ./... && go test ./... && go build -o bin/ingressd ./cmd/ingressd
(cd edge && go test ./... && go build -o ../bin/ingressd-edge ./cmd/ingressd-edge)
```

If `make` is not installed in WSL, run the equivalent `go` commands. The edge binary takes a few minutes to build the first time.

On Linux CI/servers, the Makefile targets work as usual (`make build test e2e`).

## Licensing of contributions

ingressd is licensed under the [Apache License 2.0](../LICENSE). Contributions are accepted under the same licence (inbound = outbound, as in section 5 of the licence); there is no separate CLA.

Sign off every commit to certify the [Developer Certificate of Origin](https://developercertificate.org/), i.e. that you wrote the change or otherwise have the right to submit it under the project's licence:

```bash
git commit -s    # adds "Signed-off-by: Your Name <you@example.com>"
```

Code adapted from other projects must keep its original copyright and licence notice in the file header, use a licence compatible with Apache-2.0 (no GPL/AGPL/LGPL), and be listed in [NOTICE](../NOTICE).
