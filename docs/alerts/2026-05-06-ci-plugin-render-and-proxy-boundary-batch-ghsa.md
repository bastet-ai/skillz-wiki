# CI, plugin, render, and proxy-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-06** batch across Jenkins plugins, MISP modules, Nitro route rules, and Spring static-resource handling where convenience features crossed authorization, rendering, and routing boundaries.

## Advisories covered

- **Jenkins plugin boundary issues** — [GHSA-w22p-4x9f-486v](https://github.com/advisories/GHSA-w22p-4x9f-486v), [GHSA-f8h4-46xv-h7jj](https://github.com/advisories/GHSA-f8h4-46xv-h7jj), [GHSA-jp6g-g3v3-6gvf](https://github.com/advisories/GHSA-jp6g-g3v3-6gvf), [GHSA-wg26-8wmj-cf9p](https://github.com/advisories/GHSA-wg26-8wmj-cf9p), [GHSA-jp9r-mmhw-vff3](https://github.com/advisories/GHSA-jp9r-mmhw-vff3), [GHSA-p334-gfhq-c7w6](https://github.com/advisories/GHSA-p334-gfhq-c7w6): XSS, open redirect, missing permission checks, unsafe deserialization, and classpath enumeration in CI plugin surfaces.
- **MISP modules website and expansion boundaries** — [GHSA-j4rh-7jcr-qm69](https://github.com/advisories/GHSA-j4rh-7jcr-qm69), [GHSA-fhq3-2gf3-8f3j](https://github.com/advisories/GHSA-fhq3-2gf3-8f3j): missing CSRF protection and unsafe remote resource fetching.
- **Nitro route-rule URL/proxy bypasses** — [GHSA-9phm-9p8f-hw5m](https://github.com/advisories/GHSA-9phm-9p8f-hw5m), [GHSA-5w89-w975-hf9q](https://github.com/advisories/GHSA-5w89-w975-hf9q): protocol-relative redirects and percent-encoded traversal could bypass wildcard route-rule intent.
- **Spring static-resource DoS/cache/temp-file issues** — [GHSA-6p4f-wcwh-5vvm](https://github.com/advisories/GHSA-6p4f-wcwh-5vvm), [GHSA-wg35-8jpf-2xv3](https://github.com/advisories/GHSA-wg35-8jpf-2xv3), [GHSA-5843-p793-ghmm](https://github.com/advisories/GHSA-5843-p793-ghmm): static resource resolution and multipart temp handling require resource and cache boundaries.

## Why this is durable

CI systems, plugin ecosystems, and framework route rules combine privileged identities with user-authored content. Anything that renders build output, tests a connection, follows a URL, deserializes plugin state, or resolves static content needs explicit policy checks at the exact feature boundary.

## Immediate triage

1. Patch Jenkins core/plugin stacks, MISP modules, Nitro, and Spring components where deployed.
2. Disable legacy HTML wrappers, plugin endpoints, route-rule proxies, and remote-expansion modules that are not business-critical.
3. Re-test plugin endpoints with low-privilege users for connection tests, approval queues, classpath listings, redirects, and deserialization entrypoints.
4. Normalize and re-validate redirect/proxy targets after percent-decoding, path cleanup, and protocol-relative URL parsing.
5. Add upload, multipart, and static-resource budgets for file count, temp bytes, path depth, cache key length, and processing time.

## Durable controls

- Put CI plugin endpoints behind the same permission model as the secrets, classpaths, and SCM integrations they touch.
- Render build artifacts and reports with strict CSP, no ambient admin cookies, and isolated origins when possible.
- Treat route-rule proxies as SSRF-capable unless every redirect and decoded path is rechecked against an allowlist.
- Keep framework static-resource pipelines covered by fuzz tests for cache-key confusion, traversal, decompression, and temp-file exhaustion.
