# OpenClaw 2026.4.8 trust-boundary advisory batch (GHSA-7437-7hg8-frrw et al.)

**Signal:** GitHub Security Advisories updated **2026-04-28** and surfaced in the REST fallback on **2026-04-29**. OpenClaw 2026.4.8 fixed several local-assistant trust-boundary issues around plugin scopes, package integrity, exec environment filtering, pairing approval, and cross-channel media trust.

## What it is
The batch includes:

- `GHSA-7437-7hg8-frrw` / `CVE-2026-42427`: missing `HGRCPATH`, `CARGO_BUILD_RUSTC_WRAPPER`, `RUSTC_WRAPPER`, and `MAKEFLAGS` exec environment denylist entries could enable build-tool environment injection.
- `GHSA-3vvq-q2qc-7rmp` / `CVE-2026-42428`: ClawHub package downloads were not enforced with archive or per-file integrity verification.
- `GHSA-67mf-f936-ppxf` / `CVE-2026-42426`: `node.pair.approve` lived under `operator.write` instead of narrower pairing/admin scope.
- `GHSA-qqq7-4hxc-x63c` / `CVE-2026-42424`: shared reply `MEDIA:` paths could be treated as trusted across channels and trigger local file reads.
- `GHSA-4f8g-77mw-3rxc` / `CVE-2026-42429`: plugin HTTP `auth: gateway` could widen identity-bearing `operator.read` requests into runtime `operator.write`.

Affected package: npm `openclaw` `< 2026.4.8`. Fixed version: `2026.4.8`.

References: <https://github.com/advisories/GHSA-7437-7hg8-frrw>, <https://github.com/advisories/GHSA-3vvq-q2qc-7rmp>, <https://github.com/advisories/GHSA-67mf-f936-ppxf>, <https://github.com/advisories/GHSA-qqq7-4hxc-x63c>, <https://github.com/advisories/GHSA-4f8g-77mw-3rxc>

## Triage
1. Inventory OpenClaw installations below `2026.4.8`, especially systems that install ClawHub packages, pair nodes, use multiple chat channels, or expose trusted plugin HTTP routes.
2. Review recent package installs for missing integrity metadata and unexpected plugin contents.
3. Inspect exec environments for untrusted build-tool variables inherited from user workspaces.
4. Review paired-node approvals and cross-channel media references around sensitive local paths.

## Mitigation
- Upgrade OpenClaw to `2026.4.8` or later.
- Require package integrity metadata before plugin installation; avoid installing unsigned/unpinned plugin archives.
- Strip build-tool environment variables before host exec, not only shell metacharacters.
- Keep pairing approval on a distinct high-trust/admin path.
- Treat generated media handles as channel-scoped capabilities, never portable local-file paths.

## Detection ideas
- Search logs for ClawHub installs without recorded hashes or manifests.
- Hunt for unexpected `HGRCPATH`, `RUSTC_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER`, or `MAKEFLAGS` in exec contexts.
- Review plugin HTTP requests where an upstream read identity caused write-capable runtime behavior.

## Durable lesson
Local assistants have many “nearby” trust boundaries: workspace env, plugin packages, paired devices, chat channels, and generated media. Each needs explicit capability scoping and final enforcement at the point of use.
