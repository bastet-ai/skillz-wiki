# Malicious crates removed from crates.io (GHSA)

**Signal:** GitHub Security Advisories reported two crates removed from crates.io for malicious code in the **2026-05-04** scan.

## Advisories

- **`mysten-metrics` malicious crate** — removed from crates.io for malicious code. Reference: <https://github.com/advisories/GHSA-g38r-8gmr-ghrf>.
- **`sui-execution-cut` malicious crate** — removed from crates.io for malicious code. Reference: <https://github.com/advisories/GHSA-qprh-m6p3-hwxc>.

## Immediate triage

1. Search all Rust workspaces, lockfiles, vendored sources, internal mirrors, CI caches, and container layers for `mysten-metrics` or `sui-execution-cut`.
2. If either package was installed, treat the build host and resulting artifacts as potentially compromised: preserve evidence, rebuild from clean infrastructure, and rotate secrets exposed to cargo, CI, signing, registry, cloud, and deployment environments.
3. Check whether similarly named Sui/Mysten dependencies were introduced around the same commits or by the same developer/token.

## Hunt ideas

- `rg -n 'mysten-metrics|sui-execution-cut' Cargo.toml Cargo.lock vendor/ .github/ Dockerfile*`
- Review cargo home caches, sparse registry cache, and CI artifact caches for the package names.
- Inspect build logs for unexpected network calls, post-build scripts, credential discovery, or binary drops.
- Compare dependency-diff timestamps with token usage, registry publishes, and deployment events.

## Durable controls

- Require lockfile review for new direct and transitive dependencies with typosquat/namespace-lookalike checks.
- Prefer isolated, ephemeral builders with no long-lived production credentials.
- Mirror approved crates into an internal registry after scanning and provenance checks.
- Alert on yanked/removed/malicious package advisories as incident triggers, not routine patch tickets.

## Operator lesson

A malicious dependency is already code execution in the build boundary. The fix is not just removing the line from `Cargo.toml`; it is proving the builder and artifacts are clean.
