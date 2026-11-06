# Releasing

How ingressd releases are versioned, built, signed and verified, and how to build and sign your own. Repository settings and key handling for maintainers are in [CI-SECURITY.md](CI-SECURITY.md); test lanes in [TESTING.md](TESTING.md).

---

## 1. Versions

- The `VERSION` file on `main` holds the version the **next** release will have (`X.Y.Z`). It is bumped right after each release.
- Releases are tagged `vX.Y.Z` by CI from `VERSION`; tags are never created by hand. The workflow refuses to build if that tag already points at another commit.
- The version is stamped into every binary (`ingressd version`, the version a node reports to the panel, the connector's health report).
- Local builds report `git describe` versions such as `v1.2.3-4-gabc1234` (or `dev`); panels show those as "unknown", never as outdated.

Commit message trailers since the previous release set manifest fields:

| Trailer | Effect |
|---|---|
| `Security: yes` | Marks the release as a security release. |
| `Min-Supported: v1.2.0` | Oldest supported version: older installations are flagged "unsupported" and nodes never install anything below it (the highest value wins). Raise it to the first fixed version once a security release has soaked, so a rollback stays possible until then. |

## 2. Pipeline

A release is cut by fast-forwarding the `release` branch to a commit already on `main`. CI ([`ci.yml`](../.github/workflows/ci.yml)) runs the full suite on that push; when it is green it calls [`release.yml`](../.github/workflows/release.yml) ("Run workflow" on `release` rebuilds). Each job gets only what it needs:

| Job | Permissions / secrets | What it does |
|---|---|---|
| `build` | `contents: read`, no secrets, no build cache | `scripts/build-release.sh dist` builds every asset and `release.json`; also builds `releasetool`. Uploads both as one tarball and outputs its SHA-256. |
| `build provenance` | `id-token`, `attestations` | Checks the tarball digest and creates [GitHub build provenance attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) for the binaries. Skipped while the repository is private (GitHub only stores attestations for public repositories on the free plan). |
| `sign` | environment `release-signing` (`MINISIGN_SECRET_KEY`), no token permissions | Checks the tarball digest, signs `release.json` and `SHA256SUMS` with minisign (a pinned upstream build checked against its SHA-256, not a distribution package), and verifies `release.json` against the key built into the code (`releasetool verify`). Runs no Go toolchain and no checkout. |
| `publish` | `contents: write` | Tags `vX.Y.Z` and publishes the GitHub release with all assets and signatures. |
| `publish to the panel` | environment `release-publish` (`PANEL_HOST_*`) | Hands the release to the hosted panel's download mirror (nodes and connectors try the mirror first, then GitHub). |
| `image <name>` | `packages: write`, `id-token` | Builds and pushes the container images (no build cache) with SBOM and max-mode provenance, then signs them with cosign (keyless). |

Release binaries are built with `-trimpath`, `CGO_ENABLED=0` and the newest stable Go.

## 3. Release assets

`scripts/build-release.sh` (also `make release-local`) produces:

- node: `ingressd_linux_{amd64,arm64}`, `ingressd-edge_linux_{amd64,arm64}`
- connector: `ingressd-connector_{linux_amd64,linux_arm64,linux_arm,darwin_arm64,darwin_amd64,windows_amd64.exe}`
- `install-connector.sh`, `install-node.sh`
- `release.json`, the manifest (`pkg/release`, written by `scripts/releasetool manifest`): `{version, published_at, channel, min_supported, security, notes_url, assets: {name: sha256}}`
- `SHA256SUMS` of every file, `release.json` included
- `release.json.minisig`, `SHA256SUMS.minisig` (added by the `sign` job; trusted comment `ingressd vX.Y.Z`)

Asset names match `pkg/release.AssetName`.

Container images: `ghcr.io/ingressd/ingressd-connector` (amd64, arm64, arm/v7) and `ghcr.io/ingressd/ingressd-node` (amd64, arm64), tagged `X.Y.Z` and `X.Y`. The repository variables `REGISTRY` and `IMAGE_NAMESPACE` (and secrets `REGISTRY_USERNAME`/`REGISTRY_PASSWORD`) select another registry. Images set `INGRESSD_INSTALL=docker`, so they never update themselves in place.

## 4. Release signing key

Releases are signed with [minisign](https://jedisct1.github.io/minisign/). The trusted public key is compiled into every node and connector:

- `pkg/release.ReleasePublicKey`, key ID `9CAEBE74F1A98BC2`:
  `RWTCi6nxdL6unHcK5KWP/DTr/NFJSt1EEN48LJTlNVJHGkPs9/Ax00gl`
- Builds that predate the signing key trust `pkg/release.PlaceholderPublicKey` (no private key exists). They verify nothing: nodes refuse remote updates and connectors ignore update notices, so they need one manual update (re-run the installer).
- `INGRESSD_RELEASE_PUBLIC_KEY` (environment of the node or connector service) overrides the built-in key, for self-built releases and tests.

Key generation, storage and rotation are covered in [CI-SECURITY.md §3](CI-SECURITY.md#3-release-signing-key).

## 5. Verifying a release

```sh
# Signature over the checksums, then the files you downloaded
minisign -Vm SHA256SUMS -P RWTCi6nxdL6unHcK5KWP/DTr/NFJSt1EEN48LJTlNVJHGkPs9/Ax00gl
sha256sum -c --ignore-missing SHA256SUMS

# Build provenance (GitHub CLI; releases published while the repository is public)
gh attestation verify ingressd_linux_amd64 --repo ingressd/ingressd

# Container image signature
cosign verify ghcr.io/ingressd/ingressd-node:X.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/ingressd/ingressd/\.github/workflows/release\.yml@refs/heads/release$'
```

`go run ./scripts/releasetool verify --dir <dir>` checks `release.json.minisig` and every asset hash in a downloaded release directory (`--pub file` for another key).

## 6. How nodes and connectors update

The panel learns of a release and sends the signed `release.json` verbatim; nodes and connectors verify it themselves with their built-in key, so the panel cannot make them install anything the release key did not sign.

- **Node** (`upgrade_request` → `upgrade_progress` events → one `upgrade_result{ok, from, to, rolled_back, reason}`): the agent refuses unsigned or tampered manifests, versions below the highest `min_supported` it has seen in any signed manifest, the version it already runs, downgrades unless forced, forced downgrades to a non-stable release, container installs, and concurrent updates. It downloads `ingressd` and `ingressd-edge` from the given sources in order (the panel's mirror, then GitHub), checks each against the manifest's SHA-256, runs `<new ingressd> version`, and starts `ingressd upgrade-helper` (under systemd in its own transient unit, so restarting `ingressd.service` does not kill it). The helper keeps the current binaries as `*.old`, swaps, restarts `ingressd-edge.service` and `ingressd.service`, and waits for the new version to reconnect with health not `down` (default 2 minutes, `INGRESSD_UPGRADE_HEALTH_TIMEOUT`); otherwise it restores the old binaries and reports a rollback. Log: `<state-dir>/upgrade/helper.log`. Without systemd the helper restarts `ingressd serve` itself (`INGRESSD_UPGRADE_RESTART=exec` forces that).
- **Connector**: the node hands a `connector_update` notice to the connector on its next poll. The connector verifies the manifest with its own key; installed as a service (systemd, launchd, Windows service) it downloads its binary through the node (which fetches, checks and caches it once) or straight from the sources, and `ingressd-connector upgrade-helper` swaps the binary, restarts the service and rolls back unless the new version gets a tunnel up and a poll answered in time. Docker and manual installs only report the command to run.
- **By hand**: `ingressd upgrade` installs a signed release, verifying `SHA256SUMS.minisig`.

## 7. Building and signing your own release

```sh
# 1. A key of your own (or: minisign -G -W -p my-release.pub -s my-release.key)
go run ./scripts/releasetool keygen --pub my-release.pub --key my-release.key

# 2. Build and sign dist/ (VERSION must be vX.Y.Z or vX.Y.Z-pre for release.json)
VERSION=v1.2.3 RELEASE_KEY=my-release.key ./scripts/build-release.sh dist

# 3. Check it
go run ./scripts/releasetool verify --pub my-release.pub --dir dist
```

Then either set `ReleasePublicKey` in `pkg/release/key.go` to the base64 line of `my-release.pub` (the line after "untrusted comment") in your build, or keep the official build and set `INGRESSD_RELEASE_PUBLIC_KEY=<that line>` in the environment of the node and connector services (for example a systemd drop-in). An installation trusts exactly one key at a time: with your key configured it no longer accepts official releases, and vice versa.

## 8. Deploying to your own nodes (`deploy.yml`)

[`deploy.yml`](../.github/workflows/deploy.yml) rolls a **published** release out to systemd-installed nodes over SSH (Actions → deploy → Run workflow: environment, release tag, optional node subset, dry run). Managed nodes normally update through the panel instead; this is for fleets you operate yourself.

- The job runs in the chosen GitHub environment (`staging` or `production`) and gets that environment's secrets; give `production` required reviewers.
- It does nothing unless the environment has `DEPLOY_SSH_KEY` and `DEPLOY_HOSTS`; it then **requires** `DEPLOY_KNOWN_HOSTS` (host keys are never trusted on first use).
- Production refuses pre-releases. Assets are checked against `SHA256SUMS`, and each node verifies `SHA256SUMS.minisig` with the release key in its installed `ingressd`.
- `scripts/deploy-nodes.sh` goes **one node at a time**: detect the architecture, copy `ingressd` and `ingressd-edge`, verify the signature and checksums on the node, swap them into `/usr/local/bin` (keeping `*.old`), restart `ingressd-edge` then `ingressd`, and wait up to 90 s for both units and `ingressd doctor`. On failure it restores the old binaries and **stops the rollout**.

Adding a node:

1. Create a deploy user with passwordless sudo for the rollout. **This is full root on the node**: the rollout sends its script to `sudo bash -s`, so the sudoers line below lets the user run anything as root, and the deploy SSH key must be protected like a root key.
   ```sh
   sudo useradd --create-home --shell /bin/bash ingressd-deploy
   sudo install -d -m 700 -o ingressd-deploy -g ingressd-deploy ~ingressd-deploy/.ssh
   echo 'ssh-ed25519 AAAA… ingressd-deploy@github' | sudo tee ~ingressd-deploy/.ssh/authorized_keys
   echo 'ingressd-deploy ALL=(root) NOPASSWD: /usr/bin/bash -s -- *' | sudo tee /etc/sudoers.d/ingressd-deploy
   ```
   (To limit the key itself, put a forced command in `authorized_keys` that accepts only the rollout's commands.)
2. Append its host key to `DEPLOY_KNOWN_HOSTS`: `ssh-keyscan -t ed25519 <host>` (check the fingerprint on the node's console).
3. Add a line to the `DEPLOY_HOSTS` environment secret (secrets cannot be read back: keep the canonical list elsewhere and paste the whole list):
   ```
   # name      user@host                       [port]
   edge-lon-1  ingressd-deploy@203.0.113.10
   edge-ams-1  ingressd-deploy@edge-ams-1.example.net  2222
   ```
4. Dry run, then deploy the current release to just that node (`only: edge-ams-1`).

Use one SSH key pair per environment (`ssh-keygen -t ed25519 -C ingressd-deploy-staging -f deploy_staging -N ''`): the private key goes into `DEPLOY_SSH_KEY`, the public key into the nodes' `authorized_keys`. That key can run root commands on every node of its environment.
