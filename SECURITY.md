# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through GitHub: on this repository, go to **Security → Advisories → Report a vulnerability** ([GitHub's guide](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)). Include:

- the affected component (node agent, edge, connector, installer, release tooling) and version (`ingressd version`, `ingressd-connector version`);
- steps to reproduce or a proof of concept, and the impact you expect;
- whether the issue is already public or known to others.

We aim to acknowledge reports within a few working days, keep you updated while we work on a fix, and credit you in the advisory unless you prefer otherwise. Please give us a reasonable time to release a fix before disclosing details.

## Supported versions

ingressd is pre-release software. Security fixes are made on `main` and shipped in the **latest release** only; older releases are not patched. Releases that fix a vulnerability are marked as security releases in their signed manifest, and managed nodes are told to update.

## Scope

In scope: everything in this repository, including the node agent and CLI, the custom Caddy build and modules (`edge/`), the connector, installers under `deploy/`, container images built from this repository, the panel ↔ node protocol implementation (`pkg/nodeproto`, `internal/nodeagent`), and release signing and verification (`pkg/release`, `scripts/`).

The hosted ingressd panel is a separate, proprietary service and is **out of scope** for this repository, but reports about it are welcome through the same channel and will be passed on to the panel's maintainers. Please do not run disruptive tests (denial of service, spam, social engineering, accessing other users' data) against the hosted panel or anyone's nodes.
