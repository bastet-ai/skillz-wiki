# OpenClaw exec, filesystem, and browser boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced OpenClaw advisories updated on **2026-05-06** covering host exec environment inheritance, SSH sandbox tar uploads, localhost CDP host canonicalization, and a duplicate Teams sender-allowlist advisory.

## Advisories covered

- **Host exec environment sanitization gaps** — [GHSA-cg7q-fg22-4g98](https://github.com/advisories/GHSA-cg7q-fg22-4g98): host command execution could retain package-manager, registry, Docker, compiler, or TLS override variables that change what a supposedly controlled command downloads, builds, trusts, or contacts. Duplicate advisory: [GHSA-5mh4-3rv3-fpcf](https://github.com/advisories/GHSA-5mh4-3rv3-fpcf).
- **SSH sandbox tar upload symlink following** — [GHSA-fv94-qvg8-xqpw](https://github.com/advisories/GHSA-fv94-qvg8-xqpw): remote sandbox upload/extraction could follow symlinks and write outside the intended destination. Duplicate advisory: [GHSA-5799-3xg7-rfrv](https://github.com/advisories/GHSA-5799-3xg7-rfrv).
- **Trailing-dot localhost CDP bypass** — [GHSA-fh32-73r9-rgh5](https://github.com/advisories/GHSA-fh32-73r9-rgh5): browser/CDP loopback checks that did not canonicalize `localhost.` could misclassify a remote-control target. Duplicate advisory: [GHSA-f5fm-9jmp-c88r](https://github.com/advisories/GHSA-f5fm-9jmp-c88r).
- **Teams Graph API thread-history sender-allowlist bypass** — [GHSA-chfm-xgc4-47rj / CVE-2026-41365](https://github.com/advisories/GHSA-chfm-xgc4-47rj): Graph-fetched Microsoft Teams thread history could bypass sender allowlists in OpenClaw `<=2026.3.28`; patch to `>=2026.3.31`. Duplicate advisory: [GHSA-8pf2-vj79-4wxg](https://github.com/advisories/GHSA-8pf2-vj79-4wxg).

## Why this is durable

Automation platforms cross trust boundaries constantly: shell environment, archive transfer, remote browser control, and channel identity. The recurring failure is treating a helper boundary as isolated while inheriting ambient host trust, filesystem state, DNS/canonicalization quirks, or upstream message identity.

## Immediate triage

1. Upgrade OpenClaw deployments to a build containing the relevant fixes (`>=2026.3.31` for the Teams Graph API sender-allowlist issue), and deduplicate duplicate GHSA IDs in tracking systems.
2. Audit host exec wrappers for inherited `NPM_CONFIG_*`, `PIP_*`, `UV_*`, registry, compiler, linker, Docker, proxy, CA bundle, and TLS verification variables.
3. Review SSH sandbox upload paths for symlinks, hardlinks, archive extraction, and post-upload writes outside the destination root.
4. Test browser/CDP allowlists with `localhost.`, mixed case, IPv6 loopback, IPv4-mapped loopback, DNS search suffix behavior, and redirects.
5. Re-check channel connectors that import history through external APIs: the author identity used for policy must be the API-provided immutable sender, not display text or thread context.

## Durable controls

- Treat host exec as a clean-room boundary: construct an allowlisted environment instead of subtracting known-dangerous variables.
- Extract or upload into newly created private directories; use openat-style path resolution and reject symlink traversal before writes or metadata changes.
- Canonicalize hosts through the same parser/resolver used by the browser transport, then enforce loopback/remote policy on the canonical endpoint.
- Keep duplicate advisory IDs mapped to the same internal control record so alerting remains high-signal without losing provenance.
