# Fleet, Strapi, and CI execution-boundary batch

Source: GitHub Security Advisories updated 2026-05-14.

This batch links three common failure modes: management servers that trust caller-controlled network or package metadata, CMS query layers that expose relation filters as an authorization bypass surface, and CI workflows that let untrusted pull-request content run with trusted repository credentials. Treat each as a boundary problem, not just a patch note.

## Advisories covered

- **Fleet IP spoofing rate-limit bypass** — [GHSA-mxmp-wr3w-rvqx](https://github.com/advisories/GHSA-mxmp-wr3w-rvqx): Fleet rate limiting could be bypassed by spoofing client IP information. Affected `github.com/fleetdm/fleet < 4.80.1`; upgrade to `4.80.1` or later. This reinforces the earlier Fleet forwarding-header boundary lesson: only trusted proxy hops should decide the effective client address.
- **Fleet software package OS command injection** — [GHSA-9vcr-g537-3w5v](https://github.com/advisories/GHSA-9vcr-g537-3w5v): Fleet package-management paths allowed OS command injection through software-package handling. Affected `github.com/fleetdm/fleet/v4 < 4.81.1`; upgrade to `4.81.1` or later.
- **Fleet gRPC request crash** — [GHSA-x67p-9m2r-fxqv](https://github.com/advisories/GHSA-x67p-9m2r-fxqv): certain gRPC requests could unexpectedly terminate the Fleet server. Affected `github.com/fleetdm/fleet/v4 < 4.81.0`; upgrade to `4.81.0` or later.
- **Strapi relational filtering data leak** — [GHSA-rjg2-95x7-8qmx](https://github.com/advisories/GHSA-rjg2-95x7-8qmx): lack of query sanitization around relational filtering could leak sensitive data. Affected `@strapi/strapi >=4.0.0 <5.37.0`; upgrade to `5.37.0` or later.
- **CoreShop `pull_request_target` RCE** — [GHSA-q58j-g3f4-h26h](https://github.com/advisories/GHSA-q58j-g3f4-h26h): the release workflow used `pull_request_target` unsafely, allowing remote code execution in a privileged CI context for `coreshop/core-shop 5.0.0`. No patched package version was listed at publication time; review workflow state and repository credentials directly.

## Operator triage

1. Patch Fleet first on internet-facing or MDM/management-plane deployments: `>=4.81.1` covers the package command-injection fix and also includes the prior `4.81.0` gRPC crash fix; keep `>=4.80.1` as the minimum floor for the rate-limit issue.
2. Search Fleet logs for unusual package metadata, installer/script names, command separators, failed gRPC parsing, process restarts, and rate-limit evasion from rotating or spoofed client addresses.
3. Patch Strapi to `>=5.37.0`; then inventory content types and API routes where relation filters touch private fields, ownership relations, draft content, admin-only entities, or tenant boundaries.
4. For CoreShop and similar projects, inspect recent CI runs from external pull requests, revoke and rotate exposed CI tokens, package-publishing credentials, webhooks, and deployment keys, and disable unsafe `pull_request_target` workflows until reviewed.
5. If any exploitation signal appears, preserve workflow logs, package artifacts, Fleet server logs, and Strapi access/query logs before cleanup.

## Durable controls

- Treat package managers and MDM software-install features as command-execution interfaces: pass arguments as arrays, reject shell metacharacters, constrain execution with allowlisted package sources, and test malicious names/metadata.
- Put gRPC and API parsers behind strict schema validation, resource limits, and crash-loop detection; malformed management-plane requests should fail closed without terminating the control process.
- Enforce CMS authorization after query expansion. Relation filters, populates, sorts, and joins must be sanitized against the caller's role and tenant before the database query runs.
- Never run untrusted pull-request code in `pull_request_target` with write tokens or release secrets. Split metadata labeling from build/test execution, pin checked-out refs intentionally, and use read-only tokens for forked contribution paths.
- Add regression tests for spoofed forwarding headers, command metacharacters in package metadata, malformed gRPC messages, relation-filter data leaks, and privileged CI execution from forked pull requests.
