# Render, code, and encrypted-context boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because it shows three recurring rendering failures: map/print dynamic table features becoming code execution, encrypted component parameters missing authenticated context binding, and media-helper APIs resolving attacker-controlled paths outside their intended workspace.

## Advisories covered

- **Mapfish Print dynamic table code injection** — [GHSA-q7m6-wpvf-mvwx](https://github.com/advisories/GHSA-q7m6-wpvf-mvwx), CVE-2026-44672: unauthenticated attackers could execute arbitrary code through Dynamic table handling. Affected `org.mapfish.print:print-lib` and `org.mapfish.print:print-servlet` release lines from `3.23.0` through vulnerable `4.0.x`; patched versions include `3.28.28`, `3.30.30`, `3.31.21`, `3.33.14`, and `4.0.3` depending on release line.
- **Astro server island encrypted-parameter replay** — [GHSA-xr5h-phrj-8vxv](https://github.com/advisories/GHSA-xr5h-phrj-8vxv), CVE-2026-45028: `astro < 6.1.10` encrypted server-island props/slots with AES-GCM but did not bind ciphertext to the target component and parameter purpose, allowing cross-component or props-to-slots replay in narrow configurations.
- **short-video-maker REST path traversal** — [GHSA-935g-9rq5-q95c](https://github.com/advisories/GHSA-935g-9rq5-q95c), CVE-2026-8115: `short-video-maker <= 1.3.4` accepted `req.params.tmpFile` through a REST route in `src/server/routers/rest.ts`, enabling remote path traversal. No patched npm version was listed at scan time.

## Operator triage

1. Patch Mapfish Print immediately if the print service is reachable from users, map clients, or unauthenticated networks. Treat Dynamic table input as RCE-relevant, not merely template customization.
2. If Mapfish Print cannot be patched quickly, remove unauthenticated access, disable Dynamic table features where possible, and isolate the service account from secrets, shell tools, writeable deploy directories, and internal network reachability.
3. Upgrade Astro to `6.1.10`. Review server island components for overlapping prop/slot names where attacker-controlled props could be replayed as raw slots.
4. For `short-video-maker`, avoid exposing the REST API until a fix is available or locally patch path handling. Inspect request logs for encoded traversal, absolute paths, separator variants, and tmp-file names that resolve outside the intended temp directory.

## Durable controls

- Rendering and export subsystems should run as sandboxed workers with strict egress, read-only application code, no shell by default, and per-job CPU/memory/time limits.
- Treat “dynamic table,” “template,” “expression,” and “formatter” features as code-execution surfaces unless the implementation proves otherwise.
- Bind encrypted payloads to context using authenticated additional data: component identity, field purpose, tenant/session/user where relevant, schema version, and replay domain.
- Validate path inputs after URL decoding, Unicode normalization, route-param extraction, symlink resolution, and final join. The final resolved path must remain under the expected root.
- Regression tests should include cross-context ciphertext replay, prop/slot swaps, path traversal through route params, and renderer payloads that attempt process execution.
