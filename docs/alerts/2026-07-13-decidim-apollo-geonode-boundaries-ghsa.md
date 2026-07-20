# Decidim tenant-boundary, Apollo config, and GeoNode trusted-render checks

Source: hourly offensive-security scans, 2026-07-13 and 2026-07-20 GitHub advisory waves. Primary entries: [GHSA-r3v7-5x4c-c69q](https://github.com/advisories/GHSA-r3v7-5x4c-c69q) / CVE-2026-45414, [GHSA-3mvf-82qp-8qh5](https://github.com/advisories/GHSA-3mvf-82qp-8qh5) / CVE-2026-45378, [GHSA-767h-63j4-5226](https://github.com/advisories/GHSA-767h-63j4-5226) / CVE-2026-45377, [GHSA-jvqq-cvh4-xm37](https://github.com/advisories/GHSA-jvqq-cvh4-xm37) / CVE-2026-45376, [GHSA-86fh-w43w-338c](https://github.com/advisories/GHSA-86fh-w43w-338c) / CVE-2026-45330, [GHSA-vq6j-hj8w-7v39](https://github.com/advisories/GHSA-vq6j-hj8w-7v39) / CVE-2026-45086, [GHSA-q79h-67vx-m9xg](https://github.com/advisories/GHSA-q79h-67vx-m9xg) / CVE-2026-45415, [GHSA-2g9c-vf8h-prxx](https://github.com/advisories/GHSA-2g9c-vf8h-prxx) / CVE-2026-45573, [GHSA-533c-2vh9-4r86](https://github.com/advisories/GHSA-533c-2vh9-4r86) / CVE-2026-45572, [GHSA-jxpj-9j24-w337](https://github.com/advisories/GHSA-jxpj-9j24-w337) / CVE-2025-32781, [GHSA-h4pc-58cc-hc95](https://github.com/advisories/GHSA-h4pc-58cc-hc95) / CVE-2026-59955, [GHSA-4w3q-qpfq-v992](https://github.com/advisories/GHSA-4w3q-qpfq-v992) / CVE-2026-59954, and [GHSA-rwcv-whm8-fmxm](https://github.com/advisories/GHSA-rwcv-whm8-fmxm) / CVE-2024-27091.

This batch is durable because each item maps to a repeatable operator boundary: host-selected tenants trusting JWTs issued for a different organization, protected download wrappers redirecting to reusable Active Storage bearer URLs, tenant-scoped admin IDs loaded globally, admin-only route families reachable by participant/participant-manager accounts, user-controlled search terms reaching raw `ORDER BY` SQL expressions, stored push endpoints becoming outbound request sinks, admin-editable HTML content becoming trusted browser execution, config release IDs bypassing application/namespace permissions, Apollo ConfigService AccessKey decisions parsing a different app ID than the downstream config handler, and rich-text map/CMS content rendering inside a trusted same-origin admin session.

!!! warning "Authorized validation only"
    Keep proofs to disposable Decidim, Apollo Portal/ConfigService, and GeoNode labs. Use synthetic organizations, users, exports, verification records, CSV census rows, push endpoints, release IDs, app IDs, clusters, namespaces, AccessKey settings, config values, and harmless DOM markers. Do not collect identity documents, participant personal data, production exports, real config secrets, account tokens, notification payloads, or live tenant data. Do not run destructive SQL, perform production account takeover, point SSRF probes at internal services, or use stored script payloads against real users.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-r3v7-5x4c-c69q](https://github.com/advisories/GHSA-r3v7-5x4c-c69q) | Decidim GraphQL/API JWT auth | A JWT issued for Org 1 can be replayed against an Org 2 host/API context, including admin/API-user paths | Add host/tenant binding checks to API token tests for multi-org Decidim deployments. |
| [GHSA-3mvf-82qp-8qh5](https://github.com/advisories/GHSA-3mvf-82qp-8qh5) | Decidim identity-document verification | Admin review pages expose scanned document variants through reusable `/rails/active_storage/disk/` signed URLs | Test whether sensitive admin-viewed attachments become bearer URLs outside the authenticated review controller. |
| [GHSA-767h-63j4-5226](https://github.com/advisories/GHSA-767h-63j4-5226) | Decidim private data exports | Owner-scoped export download routes redirect to reusable Active Storage blob URLs not bound to the user session | Add redirect-chain bearer URL replay checks to private export/download flows. |
| [GHSA-86fh-w43w-338c](https://github.com/advisories/GHSA-86fh-w43w-338c) | Decidim verification admin records | `pending_authorization_id` records are loaded globally instead of through `current_organization` | Test numeric/object-ID route families for cross-organization read and state-change drift. |
| [GHSA-vq6j-hj8w-7v39](https://github.com/advisories/GHSA-vq6j-hj8w-7v39) | Decidim demographics questions | A participant account can directly load the `/admin/demographics/questions` editor surface | Add direct-route checks for admin UI pages that expose live update form actions even when sibling admin pages deny access. |
| [GHSA-q79h-67vx-m9xg](https://github.com/advisories/GHSA-q79h-67vx-m9xg) | Decidim CSV census admin records | Participant-manager sessions can open and mutate `/admin/csv_census/census_logs` records | Add role-drift tests for verification/admin record forms where partial administrative roles should not manage authorization data. |
| [GHSA-2g9c-vf8h-prxx](https://github.com/advisories/GHSA-2g9c-vf8h-prxx) | Decidim push notification subscriptions | User-supplied push endpoint is stored and later passed to `WebPush.payload_send` when VAPID delivery runs | Add stored-SSRF checks to notification/webhook subscription features that defer outbound delivery until a later server-side event. |
| [GHSA-533c-2vh9-4r86](https://github.com/advisories/GHSA-533c-2vh9-4r86) | Decidim HTML content blocks | Admin-editable landing-page HTML renders through `html_safe` without a sanitization boundary | Treat delegated CMS/admin content blocks as trusted-origin browser sinks even when exploitation requires an editor role. |
| [GHSA-jvqq-cvh4-xm37](https://github.com/advisories/GHSA-jvqq-cvh4-xm37) | Decidim admin organization user search | `params[:term]` is interpolated into raw PostgreSQL similarity sort expressions | Add `ORDER BY` SQLi timing checks to admin autocomplete/search endpoints that use ranking helpers. |
| [GHSA-jxpj-9j24-w337](https://github.com/advisories/GHSA-jxpj-9j24-w337) | Apollo Portal config releases | `GET /envs/{env}/releases/{releaseId}` returns release data by ID without enforcing application/namespace visibility | Test IDOR across config-center applications/namespaces using synthetic release IDs and marker values. |
| [GHSA-h4pc-58cc-hc95](https://github.com/advisories/GHSA-h4pc-58cc-hc95) / CVE-2026-59955 | Apollo ConfigService raw config endpoint before `2.5.2` | `/configfiles/raw/{appId}/{clusterName}/{namespace}` authentication parses `appId` as literal `raw`; if no AccessKey exists for an app named `raw`, downstream handling can still resolve the protected app ID | Add path-segment parser-differential checks to signed config-file endpoints where authentication and resource lookup use different route models. |
| [GHSA-4w3q-qpfq-v992](https://github.com/advisories/GHSA-4w3q-qpfq-v992) / CVE-2026-59954 | Apollo ConfigService `/configs` and `/configfiles` before `2.5.2` | A non-canonical app ID misses the exact AccessKey cache while an accent-insensitive or PAD SPACE database collation resolves it to the protected app | Test canonicalization gaps where signature enforcement, AccessKey lookup, database equality, and config retrieval do not normalize app IDs identically. |
| [GHSA-rwcv-whm8-fmxm](https://github.com/advisories/GHSA-rwcv-whm8-fmxm) | GeoNode rich-text editor | Stored rich text can execute in the trusted GeoNode origin and perform same-origin CSRF-tokened actions | Treat geospatial/CMS metadata renderers as account-control surfaces; prove with harmless DOM and request canaries only. |

## Replayable validation boundaries

### Decidim JWT tenant replay

1. Stand up a Decidim lab with two organizations on distinct hosts, for example `org1.localhost` and `org2.localhost`, with only synthetic participants and proposals.
2. Issue an API-user or admin JWT for Org 1. Record the issuing organization, host, token audience/claims if visible, and role. Do not use participant tokens or real program accounts.
3. Send a control GraphQL request to the Org 1 API that returns only a synthetic canary field.
4. Replay the same JWT to the Org 2 host/API context and request only seeded Org 2 canaries, such as a fake participant marker or dummy proposal mutation path.
5. Add negative controls: Org 2 request without a token, Org 2 request with an Org 2 token, and a patched build where token organization/host binding is enforced.

Report this as **Org 1 JWT -> Org 2 host-selected API context -> cross-tenant GraphQL/API access**. Redact tokens and avoid fields that expose names, emails, IDs, documents, or real proposal content.

### Decidim reusable Active Storage bearer links

1. Seed the lab with one fake identity-document image and one fake private export file containing a marker such as `DECIDIM-CANARY-ONLY`.
2. Through the intended authenticated route, load the verification review page or private export wrapper URL as the rightful admin/owner.
3. Capture only the final Active Storage URL shape and marker filename from the redirect chain or rendered HTML. Do not copy real document URLs.
4. Replay the final `/rails/active_storage/disk/...` or `/rails/active_storage/blobs/redirect/...` URL in a logged-out browser profile.
5. Record URL lifetime, status, content disposition, and whether the marker file loads. Include a control showing the protected wrapper route still rejects unauthenticated or wrong-user access.

Report this as **authenticated protected route -> signed storage URL in client-visible URL chain -> unauthenticated bearer replay**. Keep evidence to synthetic files and redact signed tokens.

### Decidim cross-organization object IDs and admin-route drift

1. Create two organizations and seed Org 2 with a fake verification authorization and Org 1 with an unrelated admin user.
2. As the Org 1 admin, request the Org 2 pending authorization route by numeric ID, such as the `confirmations/new` route family, using a marker-only record.
3. Test whether read, approve, or reject actions are scoped through `current_organization` or only through the global ID.
4. As a normal participant, request `/admin/demographics/questions/edit_questions` and any live form action exposed by the rendered page. Keep mutations to disposable questions only.
5. Include route/role controls: Org 2 admin succeeds on Org 2 records, Org 1 admin should fail on Org 2 records, participant should fail on admin editor, and patched routes should deny direct access.

Report the exact drift: **global authorization ID -> cross-org verification read/state change** or **participant session -> admin questionnaire route -> editor/update surface**. Do not display identity images or collect participant answers.

### Decidim CSV census role drift

1. Enable the CSV census verification method in a Decidim lab and seed only synthetic census rows such as `CSV-CENSUS-CANARY`.
2. Create a participant-manager role that should manage participants but should not administer verification census records.
3. Request the `/admin/csv_census/census_logs` route family directly, including the new-record and edit/update/delete paths, from that participant-manager session.
4. Record whether forms render and whether disposable rows can be created, changed, or removed despite normal admin-only expectations.
5. Include controls for a full admin, a normal participant, disabled CSV census, and a patched build where census record routes enforce the intended admin policy.

Report this as **partial admin role -> direct CSV census admin route -> verification data mutation**. Use marker rows only and do not enumerate or export real voter/participant records.

### Decidim stored push-endpoint SSRF

1. Use a lab where VAPID push delivery is enabled and create a disposable authenticated user.
2. Register a notification subscription whose endpoint points to an owned HTTPS callback endpoint. Do not target internal IPs, metadata services, or third-party push endpoints you do not control.
3. Trigger a benign notification event for the disposable user and capture whether the app server later sends an outbound WebPush request to the stored endpoint.
4. Verify persistence by inspecting only the lab user's notification settings or by using application logs; do not capture notification contents from real users.
5. Include controls for an approved push-service endpoint, an invalid scheme/host, disabled VAPID delivery, and patched builds that constrain endpoints to expected push providers.

Report this as **user subscription endpoint -> stored notification setting -> deferred server-side WebPush request**. Evidence should be callback metadata and route/state controls, not internal-network reachability.

### Decidim HTML content-block trusted rendering

1. Create a landing page or content block in a disposable Decidim organization with an editor/admin role that is intentionally allowed to manage that page.
2. Store a harmless DOM marker in an HTML content block and load the public page as a separate lab visitor account.
3. Confirm whether the content renders through a trusted same-origin execution context rather than a sanitized rich-text subset.
4. If proving state-change impact, use only a synthetic same-origin request against a lab-only setting or route that cannot affect real participants.
5. Compare with patched behavior where the HTML block is sanitized or restricted before render.

Report this as **delegated page editor -> raw HTML content block -> trusted-origin browser execution**. Make the role prerequisite explicit and avoid presenting this as participant-controlled XSS unless that path is independently proven.

### Decidim admin search `ORDER BY` SQLi

1. Use an authenticated organization-admin lab account and seed one disposable user whose name/email/nickname matches a harmless probe string.
2. Send a normal `GET /admin/organization/users?term=<probe>` request with `Accept: application/json` and record response time.
3. Send a timing-only payload that affects only PostgreSQL evaluation time, not data extraction. Keep sleep intervals short enough for the program and lab, and never run against shared production databases.
4. Verify that the `WHERE` bind parameters are not the sink; the positive boundary is the raw `Arel.sql(...)` similarity ranking expression in `ORDER BY`.
5. Compare with a patched build or branch where the sort expression uses bound parameters or safely quoted literals.

Report this as **admin search term -> similarity ranking `ORDER BY` -> SQL expression execution**. Evidence should be timing tables and sanitized query fragments, not schema dumps, row extraction, or destructive SQL.

### Apollo Portal release-ID config IDOR

1. Build a Portal lab with `configView.memberOnly.envs` enabled, two applications/namespaces, and two low-privileged users.
2. Publish a release in App/Namespace A containing a fake value such as `APOLLO-CONFIG-CANARY`, then sign in as a user who should only view App/Namespace B.
3. Request `GET /envs/{env}/releases/{releaseId}` for the A release ID from the B-only session.
4. Record whether the API returns the A release metadata/config despite list pages or normal config views hiding it.
5. Include controls for invalid IDs, allowed IDs, and a patched build where `UserPermissionValidator.shouldHideConfigToCurrentUser(...)` or equivalent permission checks run before response.

Report this as **valid release ID -> missing application/namespace permission check -> cross-scope config disclosure**. Use fake configuration values and never include real credentials, endpoints, or service topology.

### Apollo ConfigService AccessKey parser differentials

1. Build a ConfigService lab with AccessKey authentication enabled, one protected app such as `payments-api`, one unrelated app, and only fake config values such as `APOLLO-AUTH-CANARY`.
2. For the raw config route, confirm an unsigned ordinary protected route is denied, then send a legitimate signed request to `/configfiles/raw/{appId}/{clusterName}/{namespace}` and record the expected signature/app ID decision.
3. Send the raw-route request unsigned. On affected builds, authentication may derive `appId=raw` while the config-file handler resolves the real `{appId}` segment. If no AccessKey exists for an app named `raw`, record whether the protected canary is returned without a valid protected-app signature.
4. For non-canonical app ID matching, first record the lab database collation. Build one harmless variant grounded in that collation: a trailing-space form under PAD SPACE behavior, or an accent variant under an accent-insensitive collation.
5. Prove all three comparison decisions before claiming a bypass: exact application-string comparison says different; AccessKey cache lookup for the variant finds no protected-app key; database equality/release lookup treats the variant as the protected app.
6. Send unsigned `/configs` and `/configfiles` requests using the canonical and non-canonical app IDs. Do not spray Unicode variants or enumerate apps.
7. Include controls for a correctly signed request, an unsigned canonical request, a nonexistent app, an app literally named `raw` if present in the lab, Apollo `2.5.2`, and a database collation that does not equate the chosen variant.

Report this as **request path/app ID variant -> AccessKey lookup on different identity -> downstream protected config returned**. For the non-canonical case, include the exact-cache-versus-database decision table; an unusual app ID alone is not proof. Use synthetic app IDs and config markers only; never include real namespaces, secrets, service URLs, or production AccessKey material.

### GeoNode trusted rich-text renderer account-control proof

1. Use a disposable GeoNode lab with two fake accounts and no real maps, layers, API keys, or federation credentials.
2. Identify rich-text fields that render in a trusted same-origin page for an authenticated victim role. Seed a harmless script/HTML marker that only changes a local DOM flag or sends a request to an owned lab endpoint.
3. Confirm whether the renderer executes the marker in the GeoNode origin and whether same-origin CSRF-tokened requests are possible with the disposable account.
4. If proving account-control impact, use only a fake account setting such as a temporary email value on a lab user. Do not target real accounts or collect CSRF tokens as evidence.
5. Compare with sanitized rendering or a patched commit where rich text is cleaned before insertion.

Report this as **stored rich-text metadata -> trusted GeoNode origin execution -> same-origin state-change capability**. Do not publish credential-harvesting payloads, persistent takeover chains, or payloads intended for real users.

## Reporting notes

- Lead with preconditions: Decidim multi-organization host routing and JWT/API-user setup; identity-document or private-download modules; Org admin, participant, participant-manager, push-notification, or page-editor role; Apollo Portal `configView.memberOnly.envs`; Apollo ConfigService AccessKey authentication, affected route family, and database collation for non-canonical app IDs; GeoNode rich-text rendering path and victim role.
- Prefer decision tables: route, tenant/application, role, object ID, stored endpoint/content block, expected authorization boundary, observed status, canary returned, patched/negative control.
- Redact JWTs, signed Active Storage tokens, release IDs tied to real deployments, verification IDs, participant data, push subscription keys, notification payloads, config keys/values, app IDs/namespaces from real deployments, AccessKey material, CSRF tokens, and browser history/proxy logs.
- Skip nearby advisories that only restate generic data exposure unless the route/object/tenant boundary is specific enough to replay safely in an authorized lab.
