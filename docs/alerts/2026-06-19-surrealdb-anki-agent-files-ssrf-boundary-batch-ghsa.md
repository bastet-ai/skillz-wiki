# SurrealDB, Anki, MCP, file-read, SSRF, and workflow boundary checks

Source: hourly offensive-security scan, 2026-06-19. Primary entries: GitHub advisories [GHSA-869j-r97x-hx2g](https://github.com/advisories/GHSA-869j-r97x-hx2g), [GHSA-cw6h-ffmh-x6vh](https://github.com/advisories/GHSA-cw6h-ffmh-x6vh), [GHSA-hv6h-hc26-q48p](https://github.com/advisories/GHSA-hv6h-hc26-q48p), [GHSA-h4h3-3rfj-x6fq](https://github.com/advisories/GHSA-h4h3-3rfj-x6fq), [GHSA-cc8f-fcx3-gpjr](https://github.com/advisories/GHSA-cc8f-fcx3-gpjr), [GHSA-h5rg-8p7f-47g2](https://github.com/advisories/GHSA-h5rg-8p7f-47g2), [GHSA-4xgf-cpjx-pc3j](https://github.com/advisories/GHSA-4xgf-cpjx-pc3j), [GHSA-g2gw-q38m-vjfc](https://github.com/advisories/GHSA-g2gw-q38m-vjfc), [GHSA-h5x8-xp6m-x6q4](https://github.com/advisories/GHSA-h5x8-xp6m-x6q4), [GHSA-f4xh-w4cj-qxq8](https://github.com/advisories/GHSA-f4xh-w4cj-qxq8), [GHSA-c3xh-98xp-6qhf](https://github.com/advisories/GHSA-c3xh-98xp-6qhf), [GHSA-4cc2-g9w2-fhf6](https://github.com/advisories/GHSA-4cc2-g9w2-fhf6), [GHSA-wvrh-2f4m-924v](https://github.com/advisories/GHSA-wvrh-2f4m-924v), [GHSA-h3m5-97jq-qjrf](https://github.com/advisories/GHSA-h3m5-97jq-qjrf), [GHSA-x975-rgx4-5fh4](https://github.com/advisories/GHSA-x975-rgx4-5fh4), [GHSA-c795-2g9c-j48m](https://github.com/advisories/GHSA-c795-2g9c-j48m), [GHSA-v3f4-w7r7-v3hm](https://github.com/advisories/GHSA-v3f4-w7r7-v3hm), [GHSA-6gqw-jqv7-v88m](https://github.com/advisories/GHSA-6gqw-jqv7-v88m), [GHSA-xhv3-q4xx-349r](https://github.com/advisories/GHSA-xhv3-q4xx-349r), [GHSA-x26h-xmv8-gxf7](https://github.com/advisories/GHSA-x26h-xmv8-gxf7), [GHSA-6vxv-wg6j-5qwp](https://github.com/advisories/GHSA-6vxv-wg6j-5qwp), [GHSA-97pr-9hgg-3p8r](https://github.com/advisories/GHSA-97pr-9hgg-3p8r), [GHSA-mrvx-jmjw-vggc](https://github.com/advisories/GHSA-mrvx-jmjw-vggc), [GHSA-xcqx-9jf5-w339](https://github.com/advisories/GHSA-xcqx-9jf5-w339), [GHSA-48x2-6pr9-2jjf](https://github.com/advisories/GHSA-48x2-6pr9-2jjf), [GHSA-6x2m-p4xp-wg22](https://github.com/advisories/GHSA-6x2m-p4xp-wg22), and [GHSA-mxjx-28vx-xjjj](https://github.com/advisories/GHSA-mxjx-28vx-xjjj). Nearby parser-only DoS and memory-safety entries were reviewed but not promoted as standalone operator content.

This batch is durable because the advisories cluster around repeatable boundaries: local desktop HTTP servers reachable by browsers or same-host apps, database query features that cross row/field authorization into graph traversal, analyzer file reads, redirect-following JWKS fetches, secrets-directory symlinks, SDK URL path validation, arbitrary API-parameter signing, tracing middleware file inclusion, issue-title to workflow command injection, SOAP/WSDL SSRF, symlink-following corpus writes, cross-realm bulk actions, MCP UI rendering, agent memory traversal, browser-originated localhost MCP transports, tenant-blind memory operations, notebook preview rendering, LiveQuery ACL drift, MCP search URL readers, and agent environment backup/approval control planes.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-869j-r97x-hx2g | Anki `aqt` local HTTP server | request validation on a local desktop server was insufficient | Treat desktop helper servers as attack surface when reachable from browsers, plugins, or same-host malware; validate route auth, Host/Origin handling, and side effects with a disposable profile. |
| GHSA-cw6h-ffmh-x6vh | Anki iframe user scripts | framed user scripts could access internal Anki APIs | Test renderer isolation by placing harmless user-script canaries in iframes and checking whether privileged desktop APIs are exposed. |
| GHSA-hv6h-hc26-q48p | SurrealDB field permissions | graph/reference traversals could bypass field-level `SELECT` restrictions | For database-backed apps, include relation traversal and graph edges in field-level access-control matrices, not only direct `SELECT` projections. |
| GHSA-h4h3-3rfj-x6fq | SurrealDB indexed ordering | `ORDER BY` over restricted indexed fields leaked relative value ordering | Treat ordering, pagination, and cursor behavior as side channels for restricted fields; prove with seeded low-sensitivity ranking markers. |
| GHSA-cc8f-fcx3-gpjr | SurrealDB analyzer mapper | `DEFINE ANALYZER` mapper filters could read arbitrary files | Review database extension/analyzer features as server filesystem boundaries; evidence should use synthetic canary files only. |
| GHSA-h5rg-8p7f-47g2 | SurrealDB JWT JWKS fetch | JWKS URL fetching followed redirects into unintended destinations | SSRF tests must include redirect hops for IdP/JWKS configuration, not just initial URL validation; use owned callback chains. |
| GHSA-4xgf-cpjx-pc3j | `pydantic-settings` `NestedSecretsSettingsSource` | symlinks under `secrets_dir` escaped the intended secret root and bypassed size limits | Validate secret loaders with symlink and nested-path canaries before trusting directory-root checks. |
| GHSA-g2gw-q38m-vjfc | Lokka Azure Resource Manager path validation | URL path validation failed for Azure Resource Manager requests | SDK reviews should compare intended ARM resource IDs with the exact path sent under the attached Azure token, using mocked tenants. |
| GHSA-h5x8-xp6m-x6q4 | Payload Cloudinary plugin | caller-controlled Cloudinary parameters could be signed | Treat media-upload signing endpoints as capability brokers; test whether arbitrary transformation, delivery, or admin parameters are included in signatures. |
| GHSA-f4xh-w4cj-qxq8 | LangSmith SDK `TracingMiddleware` | request-controlled tracing middleware paths could cause server-side file reads | Instrumentation and tracing middleware can become file-boundary sinks; prove only with temp canaries, not app secrets. |
| GHSA-c3xh-98xp-6qhf | `githubtoplanguages` GitHub Action | issue titles crossed into Discord notification workflow command execution | Include issue/PR titles and other collaboration metadata in CI command-construction reviews; use inert shell markers in throwaway repos. |
| GHSA-4cc2-g9w2-fhf6 | Zeep SOAP client | WSDL or service-fetch behavior could perform SSRF | SOAP integrations deserve URL-fetch harnesses for WSDL imports, redirects, and service endpoint rewrites with owned callbacks. |
| GHSA-wvrh-2f4m-924v | ChatterBot `UbuntuCorpusTrainer` | symlink-following corpus training wrote outside the expected target | Corpus import/training tools should be tested like archive extractors: symlink chains, path roots, and disposable outside-root markers. |
| GHSA-h3m5-97jq-qjrf | OpenRemote Manager `removeAlarms` | bulk alarm deletion crossed realm boundaries by ID | For IoT/building platforms, compare bulk action route scoping against single-object route scoping using two lab realms. |
| GHSA-x975-rgx4-5fh4 | `appium-mcp` locator generator UI | unescaped locator data rendered in an MCP UI resource | MCP UI/resource renderers need locator, selector, and device-name DOM canaries before trusting generated operator interfaces. |
| GHSA-c795-2g9c-j48m | EverOS memory API | unvalidated `sender_id` traversed filesystem paths under `/api/v1/memory/add` | Agent-memory APIs should canonicalize tenant/user IDs before path joins; test with marker-only memory stores. |
| GHSA-v3f4-w7r7-v3hm | Uni-CLI legacy HTTP MCP transport | browser-originated localhost requests were accepted by a local MCP transport | Local MCP transports need CSRF/Origin/Host validation; test owned browser pages against harmless tool-list or echo routes only. |
| GHSA-6gqw-jqv7-v88m | `stigmem-node` decay sweep | expiry/counting operated across tenants | Background memory maintenance tasks are authorization surfaces; seed two tenants and verify scheduled or API-triggered sweeps stay scoped. |
| GHSA-xhv3-q4xx-349r | `stigmem-node` quarantine review | quarantine review exposed and mutated other tenants' facts | Review moderation/quarantine queues for tenant filters distinct from normal read APIs. |
| GHSA-x26h-xmv8-gxf7 | `stigmem-node` RTBF tombstones | tenant-blind tombstones suppressed other tenants' reads | Privacy/delete markers can become cross-tenant denial or data-hiding primitives; prove with synthetic facts and tombstones. |
| GHSA-6vxv-wg6j-5qwp | Gogs notebook renderer | outdated notebook rendering allowed `.ipynb` XSS | Git forge previewers need notebook metadata/cell-output DOM canaries, especially when rendering contributor-controlled files. |
| GHSA-97pr-9hgg-3p8r | Parse Server LiveQuery | subscriptions leaked object data after ACL read-access changes | Realtime APIs need post-subscription authorization checks; test ACL flips with two disposable users and canary object fields. |
| GHSA-mrvx-jmjw-vggc | SearXNG MCP `web_url_read` | DNS-resolved private hostnames reached SSRF targets | MCP URL readers should resolve and re-check host/IP on every request and redirect; prove with owned split-horizon or mocked DNS only. |
| GHSA-xcqx-9jf5-w339 | SearXNG MCP `web_url_read` | unbounded body reads bypassed response-size expectations | For agent fetch tools, include byte-limit, decompression, chunked, and slow-stream controls; evidence should be synthetic response size deltas. |
| GHSA-48x2-6pr9-2jjf | Network-AI environment restore | backup IDs with traversal copied arbitrary directories into environment data | Environment restore flows are filesystem import boundaries; prove with disposable outside-root directories. |
| GHSA-6x2m-p4xp-wg22 | Network-AI environment backup | symlinked directories under the environment root were copied into backups | Backup/export features should reject symlink escapes and preserve scope decisions from live workspace access. |
| GHSA-mxjx-28vx-xjjj | Network-AI approval inbox | unauthenticated HTTP approval server could approve pending agent actions | Agent approval services are control planes; validate bind address, authentication, and whether approvals are tied to the original user/session. |

## Operator triage

1. **Classify the control surface first.** Desktop helpers, MCP transports, agent approval inboxes, database analyzers, tracing middleware, and SDK signing endpoints may look internal but often become reachable through browsers, dev tunnels, SSRF relays, plugins, or CI metadata.
2. **Use two-principal labs.** SurrealDB field permissions, OpenRemote realms, `stigmem-node` tenants, Parse LiveQuery ACLs, and agent memory stores all require at least two users/tenants/realms to prove authorization drift without touching real data.
3. **Treat redirects and resolution as first-class inputs.** JWKS, SOAP/WSDL, MCP URL readers, and ARM/Cloudinary SDK wrappers should be tested for initial URL validation, redirect behavior, DNS rebinding/split-horizon behavior, and final request path under credentials.
4. **Keep file proofs synthetic.** For analyzer, secrets-dir, tracing middleware, corpus trainer, EverOS memory, and Network-AI backup/restore checks, create disposable canary files or directories and never read real keys, notebooks, environment files, model artifacts, or customer data.
5. **Separate browser and direct-client paths.** Localhost Anki and MCP transports may have different exposure to same-host processes, browser pages, iframes, and raw HTTP clients. Record `Host`, `Origin`, route, and authentication evidence for each.
6. **Skip pure crash proofs unless they unlock a workflow.** Nearby SurrealDB deep-chain DoS, Quiche FFI memory-safety, and MessagePack crash advisories were not converted into standalone operator pages because they lack a durable authorized exploit workflow beyond availability testing.

## Replayable validation boundaries

### Local desktop and MCP transport checks

- Build an isolated desktop or containerized lab profile with no real notes, decks, credentials, devices, or MCP tools.
- Enumerate listener address, port, advertised routes, `Host` handling, `Origin` handling, and whether browser requests can reach the service.
- Exercise only harmless routes: version, health, tool-list, echo, or a lab note/profile marker.
- For iframe or UI isolation, use inert DOM markers and confirm whether internal APIs are reachable from the untrusted frame or resource.
- Negative controls: loopback-only bind, authenticated route, session-bound CSRF token, strict `Origin` allowlist, and refusal of non-browser direct clients without credentials.

### Database and realtime authorization matrices

- Seed low-sensitivity canary rows/objects with direct fields, related graph edges, indexed restricted fields, and realtime subscriptions.
- Test direct reads, relation traversal, graph traversal, ordering, pagination, LiveQuery subscription creation, and ACL changes after subscription.
- Positive proof is a canary value, ordering relationship, or realtime update that a low-privilege principal cannot obtain through the canonical direct route.
- Do not run destructive bulk actions against production realms; for OpenRemote-like APIs, use two lab realms and disposable alarms only.

### URL fetch, redirect, DNS, and credential forwarding

- Route all callback evidence to owned domains or mocked upstream services.
- Exercise initial URL, redirect target, DNS answer changes, path normalization, encoded delimiters, and same-host route confusion.
- Capture whether credentials, JWT/JWKS trust, Azure/Cloudinary tokens, or agent fetch privileges are applied before or after final URL validation.
- Do not target internal metadata services, production admin endpoints, real Cloudinary tenants, or customer ARM resources.

### Filesystem import/read/write boundaries

- Create a temp root, an outside-root canary file, and an outside-root canary directory. Use only names that clearly identify the lab.
- Test symlinks, nested paths, traversal IDs, trainer/import inputs, analyzer mappers, tracing include paths, and backup/restore IDs.
- Positive evidence should be marker presence, file listing of the synthetic path, or copied canary content under the lab output.
- Negative controls: patched version, canonicalized path, symlink rejection, root-relative open APIs, and max-size checks performed after resolving real paths.

### CI and collaboration metadata execution

- In a throwaway repository, map every collaborator-controlled field consumed by workflows: issue title, PR title, branch name, label, comment body, package metadata, and generated notification text.
- Replace dangerous commands with inert markers that can only write inside the runner workspace.
- Compare the raw metadata, shell-escaped form, workflow command, and resulting marker.
- Do not test against production Discord webhooks, organization secrets, or shared runners containing real credentials.

## Reporting notes

- State the crossed boundary precisely: **local desktop HTTP route to privileged API**, **iframe user script to internal desktop API**, **graph traversal to restricted field**, **indexed ordering to restricted-value oracle**, **database analyzer to server file read**, **JWKS redirect to SSRF**, **secret-directory symlink to outside-root read**, **SDK path validation to bearer-tokened route confusion**, **media signing endpoint to arbitrary API capability**, **tracing middleware to file read**, **issue title to CI shell command**, **SOAP WSDL import to SSRF**, **corpus symlink to outside-root write**, **bulk action IDOR to cross-realm mutation**, **MCP UI locator to DOM sink**, **agent memory ID to path traversal**, **browser localhost MCP to tool access**, **tenant-blind memory maintenance**, **notebook preview to forge-origin script**, **LiveQuery subscription to stale ACL data**, **MCP URL reader to private-host SSRF**, **agent backup symlink/traversal to filesystem copy**, or **approval inbox to unauthenticated agent action approval**.
- Keep evidence boring: canary records, route matrices, redacted headers, owned callbacks, mock clouds, harmless DOM markers, temp files, and synthetic tenant IDs.
- Avoid mitigation-first phrasing in findings; lead with reachability, preconditions, exact trust boundary, controls tested, and authorized impact.
