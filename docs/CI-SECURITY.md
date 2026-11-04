# CI and release security (maintainers)

Settings the workflows rely on but cannot apply themselves, and how the release key is handled. Nothing here is secret. The pipeline itself is described in [RELEASING.md](RELEASING.md).

What the workflows already do: every action is pinned to a full commit SHA (Dependabot proposes updates weekly); every workflow starts from `permissions: {}` and each job asks only for what it needs; pull requests run with no secrets, never save caches and never use `pull_request_target`; checkouts that do not push use `persist-credentials: false`; release builds use no cache; signing and panel publishing run in protected environments; binaries get build provenance, images get SBOM, provenance and cosign signatures.

---

## 1. Repository settings (Settings → …)

Apply these once on the public repository, in this order.

1. **Actions → General**
   - Actions permissions: "Allow ingressd, and select non-ingressd, actions and reusable workflows", with "Allow actions created by GitHub" ticked and this allow list:
     `docker/*, golangci/golangci-lint-action@*, sigstore/cosign-installer@*`
     Tick "Require actions to be pinned to a full-length commit SHA" if offered.
   - Fork pull request workflows: "Require approval for all external contributors".
   - Workflow permissions: **"Read repository contents and packages permissions"**; untick "Allow GitHub Actions to create and approve pull requests".
2. **Environments**
   - `release-signing`: Required reviewers = the maintainers who may release ("Prevent self-review" once there are several); Deployment branches and tags = **Selected branches: `release`** only. Secret: `MINISIGN_SECRET_KEY`.
   - `release-publish`: same reviewers and branch rule. Secrets: `PANEL_HOST_SSH_KEY`, `PANEL_HOST`, `PANEL_HOST_KNOWN_HOSTS`.
   - `production` (for `deploy.yml`): required reviewers; deployment tags `v*` only. Secrets: `DEPLOY_SSH_KEY`, `DEPLOY_HOSTS`, `DEPLOY_KNOWN_HOSTS` (mandatory). Optionally `staging` with the same secrets for staging nodes, no reviewers.
3. **Secrets and variables → Actions**: after creating the environment secrets above, **delete the repository-level copies** of `MINISIGN_SECRET_KEY`, `PANEL_HOST_SSH_KEY`, `PANEL_HOST`, `PANEL_HOST_KNOWN_HOSTS` and any `DEPLOY_*`. Only `REGISTRY_USERNAME`/`REGISTRY_PASSWORD` (optional, for a registry other than ghcr.io) stay at repository level. `ci.yml` passes only those two to `release.yml`; environment secrets reach the `sign` and `panel` jobs directly. Until moved, releases fail at the signing step.
4. **Rules → Rulesets**
   - Branch ruleset `main`: restrict deletions, block force pushes, require linear history, require a pull request (1 approval once there is a second maintainer, dismiss stale approvals, require review from code owners if you add a CODEOWNERS file), require status checks `checks (all)` and `e2e (all suites)` with "up to date" required, require signed commits if all maintainers sign.
   - Branch ruleset `release`: restrict deletions, block force pushes, restrict updates to maintainers (bypass list: repository admins), require the same status checks. The branch only ever fast-forwards to commits on `main`.
   - Tag ruleset `v*`: restrict creations, updates and deletions; bypass only for the GitHub Actions app (the release workflow creates tags) and repository admins.
5. **Code security**
   - Private vulnerability reporting: **on** (see [SECURITY.md](../SECURITY.md)).
   - Dependency graph, Dependabot alerts and Dependabot security updates: on (version updates come from `.github/dependabot.yml`).
   - Secret scanning and **push protection**: on.
   - Code scanning: CodeQL default setup for Go and GitHub Actions.
6. **Packages**: the ghcr.io packages `ingressd-node` and `ingressd-connector` are public and linked to this repository; only the repository's workflows have write access.

## 2. Reviewing changes to CI

- Treat changes under `.github/`, `scripts/build-release.sh`, `scripts/releasetool` and `pkg/release` as security-sensitive; consider a CODEOWNERS entry requiring a maintainer's review.
- New actions: pin to a full SHA with a `# vX.Y.Z` comment, check the action's source and permissions, and add the owner to the allow list.
- Never add `pull_request_target`, `workflow_run` on untrusted input, or secrets to pull-request jobs. Never pass untrusted text (PR titles, branch names) directly into `run:`; use `env:`.

## 3. Release signing key

The release key signs `release.json` and `SHA256SUMS`; every node and connector trusts the public key compiled into it (`pkg/release.ReleasePublicKey`). Whoever holds the private key can ship code to every installation, so:

**Before the first public release**, generate a fresh key on an offline machine instead of reusing any key that existed while the repository was private:

1. `minisign -G -W -p ingressd-release.pub -s ingressd-release.key` (`-W`: no password, because CI cannot type one; `go run ./scripts/releasetool keygen` writes the same format).
2. Store the `.key` file offline (encrypted backup in two places, for example a hardware-encrypted drive and a password manager).
3. Put the whole `.key` content into the `MINISIGN_SECRET_KEY` secret of the `release-signing` environment.
4. Set `ReleasePublicKey` in `pkg/release/key.go` to the base64 line of the `.pub` file and update the key ID in its comment and in [RELEASING.md](RELEASING.md). Release.

**Rotation** (scheduled, or immediately if the key may be exposed): installations only trust the key built into them, so

1. generate the new key offline as above;
2. ship one release signed with the **old** key whose code contains the **new** public key;
3. once installations have updated, replace `MINISIGN_SECRET_KEY` with the new key and delete the old one from the environment;
4. if the old key was compromised, publish an advisory: installations still on older versions must be updated by hand (reinstall), since they will accept anything the old key signs.

**Prefer offline signing** where practical. Today the `sign` job signs in CI, and keeping the key in an environment secret behind required reviewers and a branch restriction is the minimum. Moving the key offline needs a small workflow change: let CI publish a **draft** release with the unsigned assets; a maintainer downloads them, checks them against the `build` job digest and the provenance attestations, signs `release.json` and `SHA256SUMS` on the offline machine (`minisign -S -s ingressd-release.key -m release.json -t "ingressd vX.Y.Z"`, same for `SHA256SUMS`), checks with `releasetool verify`, uploads the two `.minisig` files and publishes the draft (the `publish` job already completes existing drafts). Then delete `MINISIGN_SECRET_KEY` from GitHub.
