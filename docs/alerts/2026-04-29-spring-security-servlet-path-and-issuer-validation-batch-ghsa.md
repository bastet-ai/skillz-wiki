# Spring Security servlet-path, issuer, and X.509 validation batch (GHSA-4wrg-8wpc-h923 / GHSA-4vrc-j85c-598c / GHSA-cvc6-q2cp-2xhw / GHSA-2jrg-rf5x-568g)

**Signal:** GitHub Security Advisories updated **2026-04-29** for several Spring Security authorization and identity-validation edge cases.

## What it is
The batch affects Spring Security configurations that rely on path matching, OIDC issuer discovery, or X.509 client certificates:

- `GHSA-4wrg-8wpc-h923` / `CVE-2026-22753`: `HttpSecurity#securityMatchers` may fail to include the servlet path when matching. Fixed in `spring-security-config` `7.0.5`.
- `GHSA-4vrc-j85c-598c` / `CVE-2026-22754`: XML authorization rules may fail to include the servlet path. Fixed in `spring-security-config` `7.0.5`.
- `GHSA-cvc6-q2cp-2xhw` / `CVE-2026-22748`: `withIssuerLocation` can create a security misconfiguration risk. Fixed in `spring-security-oauth2-jose` `6.5.10` and `7.0.5`; older maintained lines should follow Spring guidance.
- `GHSA-2jrg-rf5x-568g` / `CVE-2026-22747`: X.509 client certificate auth can allow unauthorized user impersonation. Fixed in `spring-security-web` `7.0.5`.

References:

- <https://github.com/advisories/GHSA-4wrg-8wpc-h923>
- <https://github.com/advisories/GHSA-4vrc-j85c-598c>
- <https://github.com/advisories/GHSA-cvc6-q2cp-2xhw>
- <https://github.com/advisories/GHSA-2jrg-rf5x-568g>

## Triage
1. Inventory Spring Security `7.0.0` through `7.0.4`, plus affected `6.3`-`6.5` OAuth2 JOSE users.
2. Search configs for `securityMatchers`, XML authorization rules, servlet context paths, `withIssuerLocation`, and X.509 authentication.
3. Prioritize apps deployed under non-root servlet paths, behind reverse proxies, or with admin/API routes protected by path-specific matchers.
4. Add regression tests that request protected endpoints through the exact deployed context path and proxy prefix.

## Mitigation
- Upgrade Spring Security components to the fixed patch levels (`7.0.5+`, `6.5.10+` where applicable).
- Avoid relying only on path matchers for high-risk actions; pair route authorization with method-level checks.
- Pin and validate expected OIDC issuer metadata instead of discovering from attacker-influenced locations.
- For X.509 auth, bind identities to validated certificate fields and test ambiguous/duplicate subject cases.

## Detection ideas
- Review access logs for protected paths reached through alternate servlet prefixes, encoded slashes, or proxy-rewritten paths.
- Hunt for authentication successes from certificates with unexpected subject/SAN mappings.
- Watch OIDC metadata fetches to nonstandard issuers or endpoints outside the identity-provider allowlist.

## Durable lesson
Authorization rules must be tested in the deployed URL shape, not just the framework-local route shape. Context paths, proxy prefixes, issuer discovery, and certificate identity mapping are all trust boundaries.
