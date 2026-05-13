# Strapi session, SQL, and rate-limit boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

Three Strapi advisories landed together and share a useful durable lesson: CMS admin conveniences are production security boundaries. Session revocation, schema builders, and rate-limit keys must be driven by server-side identity and route semantics, not optional caller-supplied fields.

## Advisories covered

- **Password reset did not revoke existing refresh sessions** — [GHSA-hvp3-26wx-g2w4](https://github.com/advisories/GHSA-hvp3-26wx-g2w4), CVE-2026-22706: `@strapi/admin` and `@strapi/plugin-users-permissions` `<= 5.33.2` only revoked refresh tokens when a caller supplied `deviceId`. Fixed in **5.33.3**.
- **Content-Type Builder SQL injection** — [GHSA-3xcq-8mjw-h6mx](https://github.com/advisories/GHSA-3xcq-8mjw-h6mx), CVE-2026-22599: authenticated Content-Type Builder writes could pass `column.defaultTo` raw tuples into Knex schema migration SQL. Affects `@strapi/content-type-builder` `>= 5.0.0, < 5.33.2` and `@strapi/plugin-content-type-builder` `>= 4.0.0, < 4.26.1`. Fixed in **5.33.2** / **4.26.1**.
- **Users-permissions rate-limit bypass** — [GHSA-7mqx-wwh4-f9fw](https://github.com/advisories/GHSA-7mqx-wwh4-f9fw), CVE-2025-64526: rate-limit keys used attacker-controlled `email` fields even on routes whose contract did not include `email`, allowing key rotation and brute-force amplification. Affects `@strapi/plugin-users-permissions` `<= 5.44.0`; fixed in **5.45.0**.

## Operator triage

1. Inventory Strapi v4/v5 deployments, including separately pinned `@strapi/*` packages in monorepos, containers, plugins, and lockfiles.
2. Patch to at least Strapi **v5.45.0** for users-permissions rate-limit fixes; ensure v5 deployments are at least **5.33.3** for refresh-token revocation and **5.33.2** for Content-Type Builder hardening. Patch v4 content-type-builder users to **4.26.1** or later.
3. Treat password reset as containment only after confirming all user refresh tokens were invalidated. For high-risk users, force logout all sessions and rotate API/admin credentials where needed.
4. Search access logs for unexpected `POST`/`PUT` requests to `/content-type-builder/` from non-internal sources, high-volume auth/reset traffic with rotating body `email` values, and token refreshes issued after a user's latest password reset.
5. Review database logs for unusual `DEFAULT` clauses, raw SQL fragments, filesystem helper calls, migration errors, or crashes immediately after content-type changes.

## Durable controls

- Session revocation must be keyed by authenticated user identity, not optional device identifiers supplied by the request.
- Production CMS schema builders should be disabled or restricted to trusted administrative networks; migrations should be source-controlled and reviewed.
- Never pass UI configuration fields directly into raw SQL builders. Schema DSLs need structural allowlists for type, default, constraint, and migration operations.
- Rate-limit keys must be derived from route-specific, normalized identifiers. Ignore unknown body fields and keep a stable fallback key, usually IP plus route, when the route has no trusted user identifier.
- Add regression tests for containment flows: password reset revokes old refresh tokens; production Content-Type Builder endpoints are unreachable; auth/reset routes cannot bypass throttles by adding unrelated JSON fields.
