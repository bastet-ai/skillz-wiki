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

## July 1 SurrealDB realtime/session authorization update

Additional GitHub Advisory Database entries published on 2026-07-01 reinforce the same database authorization theme: [GHSA-6g9v-7gq3-p2c6](https://github.com/advisories/GHSA-6g9v-7gq3-p2c6), [GHSA-4m82-p8cx-f94j](https://github.com/advisories/GHSA-4m82-p8cx-f94j), [GHSA-gcwr-5mrf-fvch](https://github.com/advisories/GHSA-gcwr-5mrf-fvch), [GHSA-4v76-cw68-4vc9](https://github.com/advisories/GHSA-4v76-cw68-4vc9), [GHSA-6vg3-hgrw-p5gf](https://github.com/advisories/GHSA-6vg3-hgrw-p5gf), [GHSA-vjjx-rfw4-rmfc](https://github.com/advisories/GHSA-vjjx-rfw4-rmfc), [GHSA-98fx-66cf-fc7c](https://github.com/advisories/GHSA-98fx-66cf-fc7c), [GHSA-4vgr-h27g-cf9p](https://github.com/advisories/GHSA-4vgr-h27g-cf9p), [GHSA-5qfp-32cf-69jh](https://github.com/advisories/GHSA-5qfp-32cf-69jh), and adjacent CrateDB blob authorization advisory [GHSA-2xv8-gjwh-fv8p](https://github.com/advisories/GHSA-2xv8-gjwh-fv8p) / CVE-2026-49989. Availability-only SurrealDB parser and WebSocket memory-amplification items from the same wave were reviewed but not promoted beyond noting that they should stay in bounded lab stress tests.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-6g9v-7gq3-p2c6](https://github.com/advisories/GHSA-6g9v-7gq3-p2c6) | SurrealDB field permissions | error messages could disclose fields hidden by field-level `SELECT` permissions | Add error paths to field-permission tests; positive evidence is a synthetic hidden value reflected in an error, not direct table dumping. |
| [GHSA-4m82-p8cx-f94j](https://github.com/advisories/GHSA-4m82-p8cx-f94j) | SurrealDB Live Query | subscriptions could survive session state changes | Realtime authorization must be rechecked after logout, token rotation, role change, and ACL mutation, not only when the subscription is created. |
| [GHSA-gcwr-5mrf-fvch](https://github.com/advisories/GHSA-gcwr-5mrf-fvch) | SurrealDB `KILL` statement | callers could terminate other users' live queries | Treat control statements for subscriptions/jobs as cross-principal control planes; prove with two disposable users and marker subscription IDs. |
| [GHSA-4v76-cw68-4vc9](https://github.com/advisories/GHSA-4v76-cw68-4vc9) | SurrealDB crafted `LIVE` queries | live-query construction could write to a table without the expected table permission | Query features that look read-only can have write side effects; validate with a disposable table and marker rows only. |
| [GHSA-6vg3-hgrw-p5gf](https://github.com/advisories/GHSA-6vg3-hgrw-p5gf) and [GHSA-vjjx-rfw4-rmfc](https://github.com/advisories/GHSA-vjjx-rfw4-rmfc) | SurrealDB record-id paths and graph traversal | composite record IDs and graph traversal could bypass table or field `SELECT` permissions | Expand authorization matrices to cover record-id normalization, graph edges, relation traversal, and path aliases in addition to direct `SELECT`. |
| [GHSA-98fx-66cf-fc7c](https://github.com/advisories/GHSA-98fx-66cf-fc7c) | SurrealDB `TABLE` scraping | table scraping could expose data despite no available permissions for the current auth level | Test metadata/export/scrape helpers separately from normal query APIs; use seeded non-sensitive rows and expected-deny controls. |
| [GHSA-4vgr-h27g-cf9p](https://github.com/advisories/GHSA-4vgr-h27g-cf9p) and [GHSA-5qfp-32cf-69jh](https://github.com/advisories/GHSA-5qfp-32cf-69jh) | SurrealDB HTTP RPC sessions | race conditions or session-list leakage could expose or hijack attached session UUIDs | Session identifiers exposed by RPC/control endpoints are credentials; prove with anonymous-vs-authenticated lab users and sanitized UUID evidence only. |
| [GHSA-2xv8-gjwh-fv8p](https://github.com/advisories/GHSA-2xv8-gjwh-fv8p) / CVE-2026-49989 | CrateDB Blob HTTP handler | blob download route bypassed authorization | Include object/blob endpoints in database authorization matrices; compare SQL/table permission denial with blob-route access to synthetic objects. |

### Realtime/session/database auth harness

- Preconditions: isolated SurrealDB or CrateDB lab, patched negative-control version when available, two disposable principals, and only synthetic tables, blobs, sessions, and live-query IDs.
- Seed low-sensitivity markers for hidden fields, relation targets, graph edges, table rows, blob objects, and realtime events.
- Build a matrix for direct `SELECT`, graph traversal, composite record IDs, error responses, `LIVE` query creation, post-subscription ACL changes, logout/token rotation, `KILL`, table-scrape helpers, blob HTTP routes, and HTTP RPC session listing.
- Positive evidence should be a canary field, row, relation, blob marker, live event, or session UUID visible to a principal that the canonical direct route denies.
- Stop at proof of boundary crossing. Do not dump production tables, subscribe to other users' live data, terminate real workloads, collect live session IDs, or run resource-exhaustion payloads.

### Reviewed but not promoted in this update

- [GHSA-65rj-r9fh-jp2v](https://github.com/advisories/GHSA-65rj-r9fh-jp2v), [GHSA-q8qp-67f9-wr3f](https://github.com/advisories/GHSA-q8qp-67f9-wr3f), [GHSA-wjjj-24cx-f28g](https://github.com/advisories/GHSA-wjjj-24cx-f28g), and [GHSA-q729-696q-g9pq](https://github.com/advisories/GHSA-q729-696q-g9pq) are availability-focused parser/RPC/WebSocket issues; keep any validation to explicit lab stress testing and do not turn them into production operator playbooks.
- [GHSA-m492-gv72-xvxj](https://github.com/advisories/GHSA-m492-gv72-xvxj) is a stale password-reset-link issue; it was processed without promotion because it does not add a distinct workflow beyond existing reset-token lifecycle checks.

## July 1 SurrealDB query, session, and network-policy follow-up

Additional same-day SurrealDB advisories extend this page's database authorization matrix: [GHSA-f82j-v89j-mf86](https://github.com/advisories/GHSA-f82j-v89j-mf86), [GHSA-6wqw-vhfr-9999](https://github.com/advisories/GHSA-6wqw-vhfr-9999), [GHSA-97vg-427p-8hx5](https://github.com/advisories/GHSA-97vg-427p-8hx5), [GHSA-wp87-mgvq-5j93](https://github.com/advisories/GHSA-wp87-mgvq-5j93), [GHSA-c8jx-96c9-8xrp](https://github.com/advisories/GHSA-c8jx-96c9-8xrp), [GHSA-fwg2-gr34-q3w8](https://github.com/advisories/GHSA-fwg2-gr34-q3w8), and [GHSA-whwg-vh4f-pmmf](https://github.com/advisories/GHSA-whwg-vh4f-pmmf). They are promotable because they add repeatable checks for relation mutation, Live subscription authorization, redirect-following network policy, namespace/database creation authorization, indexed aggregate side channels, JWT algorithm handling, and edge delete permissions.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-f82j-v89j-mf86](https://github.com/advisories/GHSA-f82j-v89j-mf86) | SurrealDB `RELATE` | relation creation could overwrite an existing edge record without `UPDATE` permission | Add pre-existing edge rows to relation-permission tests; positive evidence is only a synthetic edge marker changing state. |
| [GHSA-6wqw-vhfr-9999](https://github.com/advisories/GHSA-6wqw-vhfr-9999) | SurrealDB Live subscriptions | authenticated subscribers could read records hidden by `SELECT` permissions via live events | Realtime authorization must be compared against canonical `SELECT` denial for the same principal and row. |
| [GHSA-97vg-427p-8hx5](https://github.com/advisories/GHSA-97vg-427p-8hx5) | SurrealDB `--deny-net` | port-specific network-deny rules could be bypassed when HTTP redirects changed the final target | Treat database URL fetchers as redirect-aware SSRF surfaces; test final host and port, not only the first URL. |
| [GHSA-wp87-mgvq-5j93](https://github.com/advisories/GHSA-wp87-mgvq-5j93) | SurrealDB `USE NS` / `USE DB` | implicit namespace/database creation could bypass `DEFINE` authorization | Include namespace and database creation side effects in auth matrices, not only table-level operations. |
| [GHSA-c8jx-96c9-8xrp](https://github.com/advisories/GHSA-c8jx-96c9-8xrp) | SurrealDB indexed `COUNT` fast paths | indexed aggregate paths could bypass field-level `SELECT` permissions | Test aggregate/count/index shortcuts as restricted-field oracles with seeded canary rows. |
| [GHSA-fwg2-gr34-q3w8](https://github.com/advisories/GHSA-fwg2-gr34-q3w8) | SurrealDB JWT parsing | ES512 could be silently downgraded to ES384 because of a library limitation | JWT validation checks should compare declared algorithm, accepted key type/curve, and fixed-version denial with disposable tokens. |
| [GHSA-whwg-vh4f-pmmf](https://github.com/advisories/GHSA-whwg-vh4f-pmmf) | SurrealDB edge permissions | `PERMISSIONS FOR delete` on edges could be bypassed when a connected node was deleted | Edge authorization tests need node deletion side effects; prove with disposable graph nodes and relations only. |

### Follow-up harness additions

- Extend the two-principal lab with synthetic graph nodes, pre-existing relation rows, restricted fields, indexed fields, Live subscriptions, namespace/database names, and disposable JWT issuers.
- For relation and edge checks, capture before/after edge records and canonical permission-denied controls. Do not mutate production graph data.
- For Live subscription checks, show direct `SELECT` denial for the same row, then whether a live event reveals the marker after create/update/delete by another principal.
- For `--deny-net`, use an owned redirector that changes only host/port within a lab callback environment. Do not target cloud metadata, internal services, or customer networks.
- For JWT checks, use disposable keys and non-sensitive claims; evidence is accept/deny behavior by algorithm and key class, not token contents.
- For implicit namespace/database creation, use throwaway names and capture route/query state only. Do not create production namespaces, tables, or users.

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
