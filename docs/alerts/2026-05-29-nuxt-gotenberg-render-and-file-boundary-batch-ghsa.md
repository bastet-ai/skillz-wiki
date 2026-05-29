# Nuxt island middleware bypass and Gotenberg SSRF/file-boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-hg3f-28rg-4jxj](https://github.com/advisories/GHSA-hg3f-28rg-4jxj) / CVE-2026-47200, [GHSA-86m8-88fq-xfxp](https://github.com/advisories/GHSA-86m8-88fq-xfxp) / CVE-2026-45741, [GHSA-hwc4-gmrw-5222](https://github.com/advisories/GHSA-hwc4-gmrw-5222) / CVE-2026-44829, and [GHSA-vp73-vjw8-8f32](https://github.com/advisories/GHSA-vp73-vjw8-8f32) / CVE-2026-45742.

This batch is durable because it gives three reusable operator patterns: framework-renderer entrypoints that skip route middleware, server-side document converters as SSRF pivots, and archive-entry name confusion caused by Linux/Windows path separator drift.

## What changed

- **Nuxt page-island middleware bypass** — with `experimental.componentIslands` enabled, `.server.vue` files under `pages/` are registered as `page_*` server islands. Direct requests to `/__nuxt_island/page_<routeName>_<hash>` rendered the page component without instantiating Vue Router, so `definePageMeta({ middleware })` auth checks did not run. Patched in `nuxt@4.4.6` and `nuxt@3.21.6`.
- **Gotenberg outbound SSRF deny-list bypass** — `IsPublicIP` unmaps IPv4-mapped IPv6 but did not block IPv6 prefixes that embed or route to internal IPv4 ranges, including `2002::/16` 6to4, `64:ff9b::/96` NAT64, `64:ff9b:1::/48` local-use NAT64, and deprecated `fec0::/10` site-local. On dual-stack or NAT64-enabled hosts, a controlled DNS AAAA record can route converter fetches toward metadata or internal addresses despite `WithDenyPrivateIPs(true)`.
- **Gotenberg zip entry path traversal** — multipart upload filenames are normalized with Linux `filepath.Base`, which does not treat backslash as a separator. A filename such as `..\\..\\Windows\\System32\\evil.pdf` can survive into multi-output ZIP entry names, and Windows extractors may treat it as traversal.
- **Gotenberg `downloadFrom` race** — multiple `downloadFrom` entries can concurrently write shared context maps and terminate the process. This is availability-only, so treat it as secondary evidence unless a program explicitly rewards DoS.

## Operator triage

1. **Nuxt targets:** look for Nuxt 4 or Nuxt 3 apps that use server islands, expose `/__nuxt_island/`, and place `.server.vue` pages under `pages/` with route middleware as the only auth or role check.
2. **Route-name mapping:** infer page island keys from file paths (`pages/secret.server.vue` → `page_secret_*`; nested/dynamic routes may transform names). Compare normal page requests with direct island endpoint requests.
3. **Gotenberg exposure:** prioritize internet-facing or internal shared Gotenberg converters, especially default-style deployments where conversion endpoints are reachable without authentication and remote fetching is enabled.
4. **Outbound fetch surfaces:** test routes that fetch remote content (`downloadFrom`, Chromium URL conversion, LibreOffice/doc conversion with remote assets) and environments that may support IPv6, NAT64, or 6to4 routing.
5. **Archive consumer boundary:** for Gotenberg ZIP traversal, identify workflows where generated ZIPs are downloaded and extracted on Windows desktops, CI workers, helpdesk tooling, document pipelines, or downstream automation.

## Replayable validation boundaries

### Nuxt server-island auth bypass checks

- **Baseline auth proof:** request the canonical page URL while unauthenticated and capture the expected redirect, 401, or 403 from route middleware.
- **Direct island proof:** request the matching `/__nuxt_island/page_<routeName>_<marker>` endpoint and compare status/body. A vulnerable proof is unauthenticated server-rendered page content that should have been middleware-protected.
- **Content minimization:** use a lab page or benign marker text where possible. For production testing, prove exposure with harmless page chrome, role label, or canary element rather than extracting sensitive user data.
- **Control check:** confirm whether the page also performs a server-side session check in its data layer. If it does, the direct island request should still fail and the finding may be non-exploitable.

### Gotenberg SSRF canonicalization checks

- **Controlled DNS harness:** use an authorized domain whose AAAA record maps to a non-sensitive canary target first. Then test internal-range encodings only in a lab or explicitly authorized environment.
- **Prefix variants:** compare deny-list behavior for direct private IPv4, IPv4-mapped IPv6, `2002:a9fe:a9fe::` for `169.254.169.254`, NAT64 `64:ff9b::a9fe:a9fe`, local-use NAT64, and site-local addresses. The useful evidence is parser/route disagreement, not metadata theft.
- **Full-read proof boundary:** when testing URL-to-PDF or `downloadFrom`, use a tester-owned HTTP listener that returns a unique marker and captures resolver/request metadata. Do not request live cloud metadata endpoints outside a scoped lab.
- **Environment note:** record host IPv6/NAT64 routing, Gotenberg version, route used, `downloadFrom` / deny-private configuration, and whether the response body returns in the generated artifact.

### Gotenberg ZIP entry traversal checks

- **Benign filename marker:** upload a harmless PDF using a multipart filename with Windows-style parent segments and a canary name, then call a multi-output route such as PDF split that returns a ZIP.
- **Archive inspection:** inspect raw central-directory entry names or `ZipInfo.orig_filename` to prove literal backslashes and `..` segments survived. Do not rely only on tools that silently normalize display names.
- **Downstream extraction proof:** if Windows extraction behavior is in scope, extract only inside a disposable sandbox and use canary paths that cannot overwrite real files. Capture whether entries escape or create unexpected directory trees.
- **`downloadFrom` filename variant:** when authorized, serve `Content-Disposition: attachment; filename="..\\..\\canary.pdf"` from a tester-owned server and confirm whether that remote filename flows into ZIP entries.

## Reporting heuristics

- For Nuxt, report the exact page file pattern, Nuxt version, `experimental.componentIslands` state, middleware name, normal-route response, island-route response, and whether any server-side data-layer auth exists.
- For Gotenberg SSRF, report the route, fetch feature, DNS/control harness, IP encoding variant, network environment, and artifact response evidence. Keep impact tied to reachable internal services only when that reachability was authorized and proven safely.
- For Gotenberg ZIP traversal, report upload filename bytes, output route, ZIP entry names, extractor tested, and whether impact is downstream-client file write rather than server-side file write.
- Treat the Gotenberg `downloadFrom` race as a secondary availability issue; include it only when the program accepts DoS or when it strengthens the case for hardening exposed unauthenticated converter endpoints.

## Notes on skipped items from this scan

- `@ai-sdk/provider-utils` `createJsonResponseHandler` resource consumption (GHSA-866g-f22w-33x8 / CVE-2026-8769) was reviewed as low-detail resource-consumption material and not promoted as standalone offensive operator guidance.
- CISA KEV stayed on catalog `2026.05.28`; its newest Nx Console, TanStack, Daemon Tools Lite, LiteSpeed, Drupal, Langflow, and Trend Micro entries were already reflected or previously triaged for Skillz operator value.
- PortSwigger stayed on the Top 10 web hacking techniques of 2025, ProjectDiscovery stayed on already-covered Neo/Nuclei/DAST material, GitHub Security Blog remained GHES signing-key rotation / IR-oriented, Trail of Bits `/feed.xml` returned 404, and Disclosed DNS still failed.
