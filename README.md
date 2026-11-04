# ingressd

A self-hosted edge for the home lab: WireGuard tunnels from a public cloud VM back to your network (UDM Pro or anything else), a reverse proxy with automatic Let's Encrypt, access policies with email OTP, WAF and bot filtering, load-balanced origin pools, TCP/UDP forwarding for game servers, and an Always Online fallback. All configuration lives in one readable, git-versioned `config.yaml`.

**Status: pre-release.** ingressd is under active development and not production ready: configuration, protocols and on-disk formats may still change between releases.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): design and configuration reference
- [docs/rev1/ARCHITECTURE.md](docs/rev1/ARCHITECTURE.md): node ↔ panel architecture and contracts
- [docs/RELEASING.md](docs/RELEASING.md): how releases are built, signed and verified, and how to sign your own
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) and [docs/TESTING.md](docs/TESTING.md): code layout, building and testing
- [SECURITY.md](SECURITY.md): reporting vulnerabilities

## Two ways to run a node

- **Standalone**: the node agent, the `ingressd` CLI and `config.yaml`. There is no local web UI (removed in rev1): edit the config and run `ingressd apply`, or let `ingressd serve` pick changes up. A config exported from the panel can be imported with `ingressd import config.yaml`.
- **Managed**: the node enrols with the hosted ingressd panel and receives signed config snapshots over an outbound WebSocket; it keeps serving its last config while the panel is unreachable. Install and enrol in one line:

  ```bash
  curl -fsSL <panel>/install/node.sh | sudo sh -s -- --panel <panel-url> --token <token> [--hostname node.example.com]
  ```

  or, on an installed node, `ingressd node enroll --panel URL --token T`. `ingressd node status` shows the connection; `ingressd node detach` returns the node to standalone (config and secrets are kept).

## Layout

| Path | What |
|---|---|
| `cmd/ingressd` | Node agent and CLI (`serve`, `apply`, `node`, `import`, …) |
| `cmd/ingressd-connector` | Site connector |
| `internal/nodeagent` | Managed mode: enrolment, control channel, snapshots, status, usage, live logs, diagnostics |
| `pkg/config` | `config.yaml` types, parsing and semantic validation (shared with the panel) |
| `pkg/nodeproto` | Panel ↔ node protocol (shared with the panel) |
| `edge/` | Separate Go module: custom Caddy build (`ingressd-edge`) and ingressd Caddy modules |
| `deploy/` | `install.sh` (standalone, local binaries), `install-node.sh` (managed, one line) |
| `examples/config.yaml` | Full example config, validated in tests |
| `test/netns/` | Linux network-namespace integration tests |
| `test/fakepanel/` | A minimal panel for testing managed mode |

## Build

Requires Go 1.27+ on Linux (the edge build and netns tests are Linux-only; the control plane and connector build anywhere).

```bash
make tidy                 # first run: resolves and pins all dependencies
make build                # bin/ingressd, bin/ingressd-connector, bin/ingressd-edge
make test
make check-edge-modules   # confirms every required Caddy plugin is compiled in
make validate-example
```

## Licence

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). The hosted panel is a separate, proprietary product.
