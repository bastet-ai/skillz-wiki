# phpMyFAQ auth, SQLi, and render-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a concentrated phpMyFAQ batch updated on **2026-05-06**. The durable pattern is one application exposing the same trust-boundary mistakes across login, API authorization, SQL persistence, path handling, and HTML/SVG rendering.

## Advisories covered

- **Unauthenticated BuiltinCaptcha SQL injection via User-Agent** — [GHSA-289f-fq7w-6q2w](https://github.com/advisories/GHSA-289f-fq7w-6q2w): critical SQL injection in `thorsten/phpmyfaq` and `phpmyfaq/phpmyfaq`; fixed in 4.1.2.
- **OAuth token-field SQL injection** — [GHSA-pm8c-3qq3-72w7](https://github.com/advisories/GHSA-pm8c-3qq3-72w7): unescaped OAuth token fields reached `CurrentUser::setTokenData`; fixed in 4.1.2.
- **Unauthenticated 2FA brute force** — [GHSA-9pq7-mfwh-xx2j](https://github.com/advisories/GHSA-9pq7-mfwh-xx2j): `/admin/check` accepted arbitrary user IDs and enabled excessive attempts; fixed in 4.1.2.
- **FAQ permission bypass** — [GHSA-99qv-g4x9-mgc3](https://github.com/advisories/GHSA-99qv-g4x9-mgc3): fallback lookup in `getFaqBySolutionId` bypassed FAQ visibility checks; fixed in 4.1.2.
- **Admin API authorization gap** — [GHSA-jrc5-w569-h7h5](https://github.com/advisories/GHSA-jrc5-w569-h7h5): ordinary authenticated users could reach admin-only API endpoints; fixed in 4.1.2.
- **Configuration-tab information disclosure** — [GHSA-rm98-82fr-mcfx](https://github.com/advisories/GHSA-rm98-82fr-mcfx): missing `CONFIGURATION_EDIT` checks exposed admin configuration endpoints; fixed in 4.1.2.
- **Client folder path traversal deletion** — [GHSA-gh9p-q46p-57g2](https://github.com/advisories/GHSA-gh9p-q46p-57g2): non-super-admin admins could delete arbitrary directories through client-folder path traversal; fixed in 4.1.2.
- **Search-result stored XSS** — [GHSA-pqh6-8fxf-jx22](https://github.com/advisories/GHSA-pqh6-8fxf-jx22): `| raw` rendering plus decode/strip bypasses enabled stored XSS; fixed in 4.1.2.
- **SVG sanitizer and FAQ content stored XSS** — [GHSA-whqh-9pq5-c7r3](https://github.com/advisories/GHSA-whqh-9pq5-c7r3), [GHSA-f5p7-2c9q-8896](https://github.com/advisories/GHSA-f5p7-2c9q-8896): entity-depth and encode/decode sanitizer bypasses reached stored XSS; fixed in 4.1.2.

## Why this is durable

Batches like this are a warning that the app's authorization, data-access, and rendering controls are scattered per endpoint instead of enforced by shared choke points. Patch first, then look for sibling routes with the same helper calls.

## Immediate triage

1. Upgrade phpMyFAQ packages to **4.1.2 or later** and prioritize public or admin-exposed deployments.
2. Review web logs for `User-Agent` SQL metacharacters, unusual OAuth token fields, `/admin/check` bursts, and non-admin calls to admin API paths.
3. Audit FAQ visibility queries for fallback paths that skip ownership/category/permission predicates.
4. Review delete/import/client-folder actions for canonical root checks after path normalization.
5. Treat stored FAQ/search/SVG content as hostile until re-sanitized with the fixed version.

## Durable controls

- Bind all SQL inputs, including headers and OAuth-derived fields; never special-case “trusted” framework metadata.
- Centralize authorization at route and service boundaries; tests should assert ordinary users cannot call admin APIs.
- Apply rate limits and user binding to every second-factor check.
- Sanitize before storage and encode on output; avoid raw template filters for user-influenced content.
- Resolve filesystem operations by descriptor/root and verify the opened target remains under the intended directory.
