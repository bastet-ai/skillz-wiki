# Web app auth, render, and export-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced web-application advisories updated on **2026-05-06** across phpMyFAQ, wger, and Lemur.

## Advisories covered

- **phpMyFAQ missing authorization on tag deletion** — [GHSA-7cx3-2qx2-3g6w](https://github.com/advisories/GHSA-7cx3-2qx2-3g6w): any authenticated user could delete tags in affected `phpmyfaq/phpmyfaq` / `thorsten/phpmyfaq` releases. Fixed in 4.1.2.
- **phpMyFAQ admin authorization bypass** — [GHSA-hpgw-ww76-c68r](https://github.com/advisories/GHSA-hpgw-ww76-c68r): permission checks did not terminate execution on all admin pages. Fixed in 4.1.2.
- **phpMyFAQ stored XSS in comment URL rendering** — [GHSA-9525-27vj-c8r8](https://github.com/advisories/GHSA-9525-27vj-c8r8): `Utils::parseUrl()` comment rendering could preserve executable markup. Fixed in 4.1.2.
- **wger cross-tenant password reset and plaintext disclosure** — [GHSA-mhc8-p3jx-84mm](https://github.com/advisories/GHSA-mhc8-p3jx-84mm): `gym=None` handling could cross tenant boundaries and expose/reset credentials. Fixed in 2.6.
- **wger member export formula injection** — [GHSA-xq9m-hmp9-fw87](https://github.com/advisories/GHSA-xq9m-hmp9-fw87): CSV/TSV exports could emit attacker-controlled formulas. Fixed in 2.6.
- **wger trainer login open redirect** — [GHSA-vqv8-j3mj-wjxj](https://github.com/advisories/GHSA-vqv8-j3mj-wjxj): `next=` was not constrained to the local host. Fixed in 2.6.
- **Lemur LDAP filter injection privilege escalation** — [GHSA-3r34-vq8m-39gh](https://github.com/advisories/GHSA-3r34-vq8m-39gh): post-auth LDAP filter construction could grant unintended privileges. Fixed in 1.9.0.

## Why this is durable

These are separate products, but the same boundary pattern repeats: authenticated routes, admin gates, tenant selectors, redirects, LDAP filters, comments, and exports are not “safe” just because a user is logged in. Each sink needs its own authorization, encoding, and type-specific policy.

## Immediate triage

1. Patch phpMyFAQ to 4.1.2, wger to 2.6, and Lemur to 1.9.0 where present.
2. Review logs for non-admin hits to admin/tag deletion routes, unexpected tenant/gym IDs, password reset events, and suspicious LDAP search filters.
3. Treat stored XSS in admin/helpdesk views as session and privileged-action compromise; rotate affected admin sessions and audit follow-on changes.
4. Sanitize CSV/TSV exports by prefixing formula-leading cells (`=`, `+`, `-`, `@`, tab, CR) and preserving raw values only in trusted machine-readable formats.
5. Validate redirects with framework-native same-origin helpers; reject scheme-relative, encoded-host, and backslash variants.

## Durable controls

- Make permission failures terminal: authorization helpers should return or throw, not merely set flags.
- Couple tenant scoping to the authenticated principal in the query itself; never trust optional request parameters like `gym=None` as isolation boundaries.
- Encode at the final sink: HTML comments, URLs, LDAP filters, CSV cells, and redirects all require different encoders.
- Add negative tests for authenticated low-privilege users against every admin, export, and cross-tenant route.
