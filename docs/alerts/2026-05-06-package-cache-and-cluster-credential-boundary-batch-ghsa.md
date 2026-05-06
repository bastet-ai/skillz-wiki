# Package-cache and cluster credential boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-06.

This batch is durable because the advisories share one operational lesson: helper APIs and cluster security controls often run with more filesystem, API, and log visibility than their callers realize. Untrusted version strings, bootstrap defaults, password hashes, and process-command telemetry must be treated as privileged boundaries, not convenience plumbing.

## Advisories covered

- **Vite+ package-manager cache path traversal** — [GHSA-33r3-4whc-44c2](https://github.com/advisories/GHSA-33r3-4whc-44c2) / CVE-2026-41211: `vite-plus` `downloadPackageManager()` accepted an untrusted `version` string, used it as a filesystem path component under `VP_HOME/package_manager/<pm>/`, and could remove, replace, and populate directories outside the intended cache root. Affected npm package: `vite-plus <= 0.1.16`; fixed in `0.1.17`.
- **NeuVector default admin password** — [GHSA-8pxw-9c75-6w56](https://github.com/advisories/GHSA-8pxw-9c75-6w56) / CVE-2025-8077: NeuVector `5.0.0` through `< 5.4.6` could fall back to a fixed built-in `admin` password when bootstrap-secret retrieval failed, allowing any workload with network access to obtain an admin token.
- **NeuVector unsalted password/API-key hashes** — [GHSA-8ff6-pc43-jwv3](https://github.com/advisories/GHSA-8ff6-pc43-jwv3) / CVE-2025-53884: NeuVector stored user passwords and API keys with simple unsalted hashes; fixed versions regenerate salted PBKDF2 hashes after users log in and API keys are used.
- **NeuVector process-command secret leakage** — [GHSA-w54x-xfxg-4gxq](https://github.com/advisories/GHSA-w54x-xfxg-4gxq) / CVE-2025-54467: NeuVector security events could expose sensitive process arguments when terminated commands carried password-like values that were not covered by redaction patterns. Fixed in `5.4.6`.

## Operator triage

1. Hunt for `vite-plus` usage in build tooling, CI images, local developer machines, and agent workspaces. Upgrade to `vite-plus >= 0.1.17` and inspect `VP_HOME` plus sibling directories for unexpected package-manager cache writes or executable shims.
2. Treat any exposed Vite+ package-manager helper that accepts version/package-manager values from untrusted input as a filesystem-write primitive until proven otherwise.
3. Inventory NeuVector deployments and upgrade to `5.4.6` or later. Do not rely on network position inside the cluster as a compensating control for the built-in admin account.
4. Rotate the NeuVector `admin` password and all NeuVector API keys after upgrade. Force fresh login/API-key use so fixed versions regenerate salted hashes.
5. Review NeuVector security events, SIEM exports, and log pipelines for process commands containing `password`, `passwd`, `token`, trust-store passwords, API keys, or custom application secret names. Rotate any secret that may have appeared in logs.
6. Verify `neuvector-bootstrap-secret` exists where expected, contains `bootstrapPassword`, and failure to read it is surfaced as a deployment failure rather than silently falling back.

## Durable controls

- Never use a raw version, package name, runtime, or toolchain string as a filesystem path component. Parse to the expected grammar first, reject separators and traversal tokens, then resolve and compare against the intended root before delete/rename/write steps.
- Cache helpers should write into newly created, mode-restricted temporary directories and perform an atomic move only after validating the resolved destination remains inside the cache root.
- Bootstrap credentials must be unique per deployment and fail closed. A missing or unreadable secret should block startup, not activate a documented default.
- Password and API-key storage needs per-secret salts, memory/CPU-hard hashing where possible, and automatic rehash on first successful use after upgrades.
- Security telemetry should redact before persistence and export, with default patterns plus organization-specific secret names. Treat process command lines as hostile-to-secrets; prefer file descriptors, mounted secrets, or environment injection with redaction controls over CLI flags.
- Cluster security tools deserve the same hardening as identity providers: patch quickly, isolate control-plane access, monitor admin-token issuance, and keep audit logs immutable but scrubbed.
