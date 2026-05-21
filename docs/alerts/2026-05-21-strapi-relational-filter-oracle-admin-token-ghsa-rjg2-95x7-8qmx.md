# Strapi relational-filter oracle to admin reset-token extraction

Source: [GitHub Security Advisory GHSA-rjg2-95x7-8qmx](https://github.com/advisories/GHSA-rjg2-95x7-8qmx), updated 2026-05-21.

Strapi's relational filtering bug is more than a generic data leak. On affected `@strapi/strapi` deployments (`>=4.0.0, <5.37.0`), unauthenticated callers could send `where` filters through publicly accessible Content API routes, traverse admin relation fields such as `updatedBy`, and turn response counts into a boolean oracle over private `admin_users` columns. The high-value exploit path is admin reset-token recovery followed by administrative account takeover.

!!! warning "Authorized validation only"
    Use these checks only in owned labs or explicitly authorized assessments. A token oracle can expose live admin secrets; stop as soon as impact is proven and preserve evidence for the report.

## Why operators should care

- The attack starts from a normal public content endpoint, not an admin login.
- The primitive is a query-sanitization failure: relation traversal reaches fields the caller cannot read directly.
- The response body does not need to print the secret. Any count, presence/absence, pagination total, or stable response difference can become the oracle.
- `resetPasswordToken`, `email`, `password`, `confirmationToken`, and profile fields are useful canaries for relation-filter boundary testing.

## Recon heuristic

1. Fingerprint Strapi targets by static asset paths, API shapes, headers, admin panel exposure, package metadata leaks, or known Strapi error formats.
2. Enumerate public Content API endpoints and content types that expose ownership-style relations: `createdBy`, `updatedBy`, `publishedBy`, tenant/user references, or custom admin relations.
3. Confirm the endpoint accepts nested `where` filters without relying on destructive actions.
4. Compare baseline result counts against a harmless impossible predicate, then against a likely true prefix or nullability predicate.

Example request shape for a lab-owned target:

```http
GET /api/articles?where[updatedBy][resetPasswordToken][$startsWith]=a HTTP/1.1
Host: target.example
Accept: application/json
```

If varying the final character reliably changes result count, status, pagination totals, or response size, treat it as a boolean oracle and stop after proving the boundary issue.

## Validation workflow

- Establish a stable baseline with identical cache headers and authentication state.
- Test only low-volume, single-character probes first; avoid brute-forcing live tokens during production assessments unless the rules of engagement explicitly allow it.
- Prefer fields that prove unauthorized relation traversal without extracting secrets, such as known admin email prefixes supplied by the customer, a controlled lab admin, or a non-sensitive custom relation field.
- Capture enough evidence for replay: endpoint, filter chain, two contrasting predicates, response metadata, affected package range, and patched-version reference.
- If reset-token extraction is in scope, use a controlled admin account and immediately rotate the token/password after validation.

## Report signals

Include these artifacts in a bug-bounty or pentest report:

- Affected package: `@strapi/strapi >=4.0.0, <5.37.0`; fixed in `5.37.0`.
- Public endpoint and content type used for the oracle.
- Relation path, for example `updatedBy.resetPasswordToken`.
- Two requests that differ only in predicate value and produce different observable outcomes.
- Impact chain: unauthenticated Content API filter → private admin-table oracle → reset-token inference → admin account takeover.
- Safety boundary: whether the test used a controlled admin/token and whether token extraction was stopped after proof.

## Log patterns worth checking

Look for public Content API requests that traverse admin relations and iterate candidate values:

```text
where[(updatedBy|createdBy|publishedBy)][(email|password|resetPasswordToken|confirmationToken|firstname|lastname|preferedLanguage)][$(startsWith|contains|eq|gt|lt|ge|le|in|notIn|notNull|null)]
```

High-signal supporting evidence includes bursts of same-shaped requests with only the suffix changing, followed by `POST /admin/reset-password` or successful admin password changes.

## Durable lesson

CMS query builders must authorize after query expansion, not just at the top-level route. Relation filters, populates, sorts, and joins need caller-aware schema sanitization before SQL generation, and public endpoints should have regression tests that attempt traversal into private admin, tenant, and ownership relations.
