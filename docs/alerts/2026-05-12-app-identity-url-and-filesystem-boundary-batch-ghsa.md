# App identity, URL, and filesystem-boundary batch

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because many independent apps failed at canonicalization or identity binding: OAuth email state, normalized paths, host/path case handling, symlinked drive roots, formula exports, and URL parser edge cases all crossed trust boundaries after an earlier check had already passed.

## Advisories covered

- **Nhost OAuth email verification bypass** — [GHSA-6g38-8j4p-j3pr](https://github.com/advisories/GHSA-6g38-8j4p-j3pr): OAuth account takeover risk when provider email verification is trusted without strict local binding.
- **Dapr service invocation path traversal ACL bypass** — [GHSA-85gx-3qv6-4463](https://github.com/advisories/GHSA-85gx-3qv6-4463): service-invocation policy checks can diverge from routing when paths are normalized differently.
- **Angular Platform-Server SSRF** — [GHSA-45q2-gjvg-7973](https://github.com/advisories/GHSA-45q2-gjvg-7973): protocol-relative and backslash URLs can escape intended server-side fetch rules.
- **Heimdall authorization normalization bugs** — [GHSA-3q34-rx83-r6mq](https://github.com/advisories/GHSA-3q34-rx83-r6mq), [GHSA-72h4-mxfc-jx37](https://github.com/advisories/GHSA-72h4-mxfc-jx37), [GHSA-43jv-5j4x-qv67](https://github.com/advisories/GHSA-43jv-5j4x-qv67): path normalization, host case, and URL-encoded slash handling can make policy and backend interpretation disagree.
- **zrok WebDAV drive symlink escape** — [GHSA-74m3-9qvm-rp9h](https://github.com/advisories/GHSA-74m3-9qvm-rp9h): drive backends followed symlinks outside `DriveRoot`, allowing host filesystem read/write.
- **Kimai XLSX formula injection and Team API BOLA** — [GHSA-3xc2-h5r3-wv3r](https://github.com/advisories/GHSA-3xc2-h5r3-wv3r), [GHSA-jv9x-w4gm-hwcm](https://github.com/advisories/GHSA-jv9x-w4gm-hwcm): exported tag names need spreadsheet formula neutralization, and object-level team authorization must be checked per resource.
- **Sync-in timing username enumeration** — [GHSA-43fj-qp3h-hrh5](https://github.com/advisories/GHSA-43fj-qp3h-hrh5): auth flows can leak account existence through timing even when response bodies are generic.
- **LibreNMS command injection and duplicate withdrawn XSS advisory** — [GHSA-x645-6pf9-xwxw](https://github.com/advisories/GHSA-x645-6pf9-xwxw), [GHSA-rp7w-624x-95qv](https://github.com/advisories/GHSA-rp7w-624x-95qv): authenticated admin tooling still needs shell-free command construction; withdrawn duplicates should not drive duplicate work.

## Operator triage

1. Patch affected identity gateways, service meshes, admin dashboards, WebDAV/drive backends, and spreadsheet export paths.
2. Test authorization with mixed-case hosts, encoded slashes, backslashes, `//host` URLs, dot segments, symlinks, and alternate path separators.
3. Treat spreadsheet exports as code-adjacent output: prefix or otherwise neutralize `=`, `+`, `-`, `@`, tab, and carriage-return starts in user-controlled cells.
4. For OAuth, bind accounts to verified provider claims and expected issuers; do not auto-link solely by an email string unless the provider and verification semantics are explicitly trusted.

## Durable controls

- Run allow/deny decisions on the same canonical representation that the downstream router, filesystem, HTTP client, or spreadsheet consumer will use.
- Object-level authorization belongs at every object read/write, not only at collection or team-entry endpoints.
- Filesystem products should use no-follow or post-open containment checks for every file operation under delegated roots.
- Authentication UX should use constant-time-ish and constant-work failure paths where account enumeration matters.
