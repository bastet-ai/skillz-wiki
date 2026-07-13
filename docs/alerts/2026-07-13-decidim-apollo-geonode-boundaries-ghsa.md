# Decidim tenant-boundary, Apollo config, and GeoNode trusted-render checks

Source: hourly offensive-security scan, 2026-07-13 GitHub advisory wave. Primary entries: [GHSA-r3v7-5x4c-c69q](https://github.com/advisories/GHSA-r3v7-5x4c-c69q) / CVE-2026-45414, [GHSA-3mvf-82qp-8qh5](https://github.com/advisories/GHSA-3mvf-82qp-8qh5) / CVE-2026-45378, [GHSA-767h-63j4-5226](https://github.com/advisories/GHSA-767h-63j4-5226) / CVE-2026-45377, [GHSA-jvqq-cvh4-xm37](https://github.com/advisories/GHSA-jvqq-cvh4-xm37) / CVE-2026-45376, [GHSA-86fh-w43w-338c](https://github.com/advisories/GHSA-86fh-w43w-338c) / CVE-2026-45330, [GHSA-vq6j-hj8w-7v39](https://github.com/advisories/GHSA-vq6j-hj8w-7v39) / CVE-2026-45086, [GHSA-jxpj-9j24-w337](https://github.com/advisories/GHSA-jxpj-9j24-w337) / CVE-2025-32781, and [GHSA-rwcv-whm8-fmxm](https://github.com/advisories/GHSA-rwcv-whm8-fmxm) / CVE-2024-27091.

This batch is durable because each item maps to a repeatable operator boundary: host-selected tenants trusting JWTs issued for a different organization, protected download wrappers redirecting to reusable Active Storage bearer URLs, tenant-scoped admin IDs loaded globally, admin-only route families reachable by participant accounts, user-controlled search terms reaching raw `ORDER BY` SQL expressions, config release IDs bypassing application/namespace permissions, and rich-text map/CMS content rendering inside a trusted same-origin admin session.

!!! warning "Authorized validation only"
    Keep proofs to disposable Decidim, Apollo Portal, and GeoNode labs. Use synthetic organizations, users, exports, verification records, release IDs, config values, and harmless DOM markers. Do not collect identity documents, participant personal data, production exports, real config secrets, account tokens, or live tenant data. Do not run destructive SQL, perform production account takeover, or use stored script payloads against real users.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-r3v7-5x4c-c69q](https://github.com/advisories/GHSA-r3v7-5x4c-c69q) | Decidim GraphQL/API JWT auth | A JWT issued for Org 1 can be replayed against an Org 2 host/API context, including admin/API-user paths | Add host/tenant binding checks to API token tests for multi-org Decidim deployments. |
| [GHSA-3mvf-82qp-8qh5](https://github.com/advisories/GHSA-3mvf-82qp-8qh5) | Decidim identity-document verification | Admin review pages expose scanned document variants through reusable `/rails/active_storage/disk/` signed URLs | Test whether sensitive admin-viewed attachments become bearer URLs outside the authenticated review controller. |
| [GHSA-767h-63j4-5226](https://github.com/advisories/GHSA-767h-63j4-5226) | Decidim private data exports | Owner-scoped export download routes redirect to reusable Active Storage blob URLs not bound to the user session | Add redirect-chain bearer URL replay checks to private export/download flows. |
| [GHSA-86fh-w43w-338c](https://github.com/advisories/GHSA-86fh-w43w-338c) | Decidim verification admin records | `pending_authorization_id` records are loaded globally instead of through `current_organization` | Test numeric/object-ID route families for cross-organization read and state-change drift. |
| [GHSA-vq6j-hj8w-7v39](https://github.com/advisories/GHSA-vq6j-hj8w-7v39) | Decidim demographics questions | A participant account can directly load the `/admin/demographics/questions` editor surface | Add direct-route checks for admin UI pages that expose live update form actions even when sibling admin pages deny access. |
| [GHSA-jvqq-cvh4-xm37](https://github.com/advisories/GHSA-jvqq-cvh4-xm37) | Decidim admin organization user search | `params[:term]` is interpolated into raw PostgreSQL similarity sort expressions | Add `ORDER BY` SQLi timing checks to admin autocomplete/search endpoints that use ranking helpers. |
| [GHSA-jxpj-9j24-w337](https://github.com/advisories/GHSA-jxpj-9j24-w337) | Apollo Portal config releases | `GET /envs/{env}/releases/{releaseId}` returns release data by ID without enforcing application/namespace visibility | Test IDOR across config-center applications/namespaces using synthetic release IDs and marker values. |
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

### GeoNode trusted rich-text renderer account-control proof

1. Use a disposable GeoNode lab with two fake accounts and no real maps, layers, API keys, or federation credentials.
2. Identify rich-text fields that render in a trusted same-origin page for an authenticated victim role. Seed a harmless script/HTML marker that only changes a local DOM flag or sends a request to an owned lab endpoint.
3. Confirm whether the renderer executes the marker in the GeoNode origin and whether same-origin CSRF-tokened requests are possible with the disposable account.
4. If proving account-control impact, use only a fake account setting such as a temporary email value on a lab user. Do not target real accounts or collect CSRF tokens as evidence.
5. Compare with sanitized rendering or a patched commit where rich text is cleaned before insertion.

Report this as **stored rich-text metadata -> trusted GeoNode origin execution -> same-origin state-change capability**. Do not publish credential-harvesting payloads, persistent takeover chains, or payloads intended for real users.

## Reporting notes

- Lead with preconditions: Decidim multi-organization host routing and JWT/API-user setup; identity-document or private-download modules; Org admin or participant role; Apollo `configView.memberOnly.envs`; GeoNode rich-text rendering path and victim role.
- Prefer decision tables: route, tenant/application, role, object ID, expected authorization boundary, observed status, canary returned, patched/negative control.
- Redact JWTs, signed Active Storage tokens, release IDs tied to real deployments, verification IDs, participant data, config keys/values, CSRF tokens, and browser history/proxy logs.
- Skip nearby advisories that only restate generic data exposure unless the route/object/tenant boundary is specific enough to replay safely in an authorized lab.
