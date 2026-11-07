# coraza-coreruleset (local copy)

Stands in for `github.com/corazawaf/coraza-coreruleset/v4` through the `replace`
in `edge/go.mod`, so `coraza-caddy` can use CRS 4.25.2 LTS, which upstream has
not packaged. The package API and include paths are unchanged.

| Path | Source |
|---|---|
| `coreruleset.go`, `LICENSE`, `rules/@coraza.conf-recommended` | `coraza-coreruleset` v4.25.0, unmodified |
| `rules/@owasp_crs/`, `rules/@crs-setup.conf.example`, `rules/LICENSE` | OWASP CRS v4.25.2, unmodified |

CRS source: tag `v4.25.2` of https://github.com/coreruleset/coreruleset (commit
`b9818c3718bc75b99403aed6c4b23773004c5412`), release asset
`coreruleset-4.25.2-minimal.tar.gz`, SHA-256
`a2d4b2a5bb4f397f7e40d4e22d0346350706a5f17c1cfefc09e8b9740e00d87e`.
The two `*.conf.example` exclusion templates in `rules/` are left out, as upstream does.

Both projects are licensed under Apache-2.0; see `LICENSE` and `rules/LICENSE`.

Remove this directory and the `replace` once `coraza-coreruleset` ships a
release at or above this CRS version.
