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

## October 7 follow-up: wger five-advisory wave — the `None != None` fail-open guard made explicit (CVE-2026-43976 / [GHSA-c72h-82w6-rqfp](https://github.com/advisories/GHSA-c72h-82w6-rqfp) high 7.1 + CVE-2026-46434 / [GHSA-x249-cx55-2h87](https://github.com/advisories/GHSA-x249-cx55-2h87), CVE-2026-46437 / [GHSA-v3x9-6gg8-c2c9](https://github.com/advisories/GHSA-v3x9-6gg8-c2c9), CVE-2026-45161 / [GHSA-xf64-4pmc-h8qf](https://github.com/advisories/GHSA-xf64-4pmc-h8qf), CVE-2026-46438 / [GHSA-rjpf-7pf5-q54x](https://github.com/advisories/GHSA-rjpf-7pf5-q54x))

The product this page's `gym=None` lesson came from shipped a coordinated five-pack, and the flagship is the *worked example* of this page's durable control, with a public fix diff: **five gym views guard with `if request.user.userprofile.gym != user.userprofile.gym: forbid()` — when both users have `gym=None`, `None != None` is `False` and the guard silently passes.** An unassigned trainer reads any other unassigned user's private admin notes, documents, contracts, config, and permission data, because the follow-on queryset filters only on the attacker-supplied `member_id`. The advisory ships the patch shape: compare `gym_id` with an explicit `is None → forbid` branch, *plus* a secondary gym-scoped queryset filter.

Durable axes:

1. **Null-as-equal is a fail-open on every "same scope?" guard written as value inequality.** Generalize beyond Django: `if a.scope != b.scope` (Python `!=`, JS `!==` with `null`, Java `.equals` NPE-swallowed, SQL `<>` returning NULL) passes whenever *both* sides are null/unassigned. Sweep rule: grep tenant/scope/org equality guards and ask what happens for two null-scope users — every multi-tenant product has unassigned-user states (invited-but-unassigned, pre-provisioning, orphaned accounts). Two disposable unassigned accounts are the whole harness. This is the exact-match complement to this wiki's absent-field rule (Oct 2 BC page): *both-fields-null* is the third branch nobody tests.
2. **OR-aggregated permission tuples have no privilege direction.** `WgerMultiplePermissionRequiredMixin(('gym.manage_gym','gym.manage_gyms','gym.gym_trainer'))` lets the *lowest* listed permission reach the same view as the highest — a `gym_trainer` deactivates `gym_manager` accounts. Same ANY-of-vs-ALL-of axis as this quarter's Candlepin leg on the Sept 21 precedence page; the wger twist is the missing **hierarchy check between subject and target** — enumerate views whose permission tuple mixes tiers, then act *upward* (low role → high role's object) with two lab accounts.
3. **Sibling legs class-covered, noted for target lists**: bearer DRF authtoken + JWT refresh survive logout and password change (GHSA-v3x9 — lifecycle-revocation invariant already on this wiki's May 8 Nhost/Ech0 pages; the *probe* is reusable: after password change, one replayed `Authorization: Token` + one `/token/refresh` call settles it in two requests); `trainer_login` accepts GET = forced-login/session-rebind CSRF (known verb-class); missing ownership check on `WorkoutLog.slot_entry` (known class).
4. Same-product waves repeat lineage: GHSA-mhc8 (May, wger `gym=None` reset/disclosure) and GHSA-c72h (Oct, same root pattern in 5 more views) mean **when one product is audited once, its guard pattern is re-tested everywhere after each feature drop** — re-sweep sibling views of any historically-patched guard on the same codebase.
