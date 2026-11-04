# Spike 01 — Caddy plugin build

## Question
Do Caddy and every plugin the plan relies on compile into one binary, and which versions do we pin?

## Plugins
| Plugin | Purpose | Expected module ID |
|---|---|---|
| `github.com/corazawaf/coraza-caddy/v2` | WAF (OWASP CRS) | `http.handlers.waf` |
| `github.com/mholt/caddy-ratelimit` | Rate limiting | `http.handlers.rate_limit` |
| `github.com/mholt/caddy-l4` | TCP/UDP, PROXY protocol, SNI | `layer4` |
| `github.com/caddyserver/cache-handler` | Cache, stale-if-error | `http.handlers.cache` |
| `github.com/caddy-dns/cloudflare` | ACME DNS-01 | `dns.providers.cloudflare` |
| `github.com/porech/caddy-maxmind-geolocation` | Country matching | `http.matchers.maxmind_geolocation` |
| `github.com/hslatman/caddy-crowdsec-bouncer` | IP reputation | `crowdsec`, `http.handlers.crowdsec` |
| `edge/modules/edgehello` | Proves our own module pipeline | `http.handlers.ingressd_hello` |

## Procedure
```bash
cd edge && go mod tidy && cd ..
make build-edge
make check-edge-modules
make test-edge
ls -lh bin/ingressd-edge
```
If `go mod tidy` fails on a version conflict, record which plugins conflict, then try pinning the older one with `go get <module>@<version>`.

## Record (2026-11-02, Go 1.27.3, linux/amd64 under WSL2)
- Go version required (from `edge/go.mod` after tidy): **1.26.1** (raised automatically from 1.25 by the plugins' requirements)
- Caddy version resolved: **v2.11.7**
- Plugin versions:
  ```
  github.com/caddy-dns/cloudflare v0.2.4
  github.com/caddyserver/cache-handler v0.17.0
  github.com/corazawaf/coraza-caddy/v2 v2.6.2   (coraza v3.8.1, CRS v4.25.0)
  github.com/hslatman/caddy-crowdsec-bouncer v0.15.0
  github.com/mholt/caddy-l4 v0.1.2
  github.com/mholt/caddy-ratelimit v0.1.0
  github.com/porech/caddy-maxmind-geolocation v1.0.3
  ```
- Conflicts: **none**. `go mod tidy` resolved everything at the latest versions.
- Binary size: **63 MB** (`-trimpath -s -w`, CGO off)
- Module IDs that differed from the table above: none (`scripts/check-edge-modules.sh` passes)
- `edgehello` caddytest passes, so the custom-module pipeline works end to end.

## Result
✅ All plugins build together. Versions are pinned in `edge/go.mod` / `edge/go.sum`. The binary is large mostly because of the CrowdSec and Souin storage dependencies; revisit if size matters (e.g. drop unused Souin storage backends).
