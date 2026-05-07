# Directory identity and parser-resource boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where directory services, WebAuthn origin policy, image upload validators, and filter parsers crossed authentication or resource boundaries.

## Advisories covered

- **ldap3_proto stack exhaustion** — [GHSA-qcxq-75wr-5cm8](https://github.com/advisories/GHSA-qcxq-75wr-5cm8): LDAP filter parsing can exhaust stack resources without recursion and depth limits.
- **Kanidm / SCIM process aborts and validator ordering** — [GHSA-r5fr-9gmv-jggh](https://github.com/advisories/GHSA-r5fr-9gmv-jggh), [GHSA-84jc-3hj2-hwc7](https://github.com/advisories/GHSA-84jc-3hj2-hwc7): SCIM filter parsing and PNG validators can crash services, including when validation runs before authorization.
- **Kanidm OAuth2 client-secret timing and stored HTML injection** — [GHSA-53hj-r94p-8c8f](https://github.com/advisories/GHSA-53hj-r94p-8c8f), [GHSA-gpxg-fx2g-qxj2](https://github.com/advisories/GHSA-gpxg-fx2g-qxj2): secret comparison and htmx-driven partial rendering remain identity boundaries.
- **WebAuthn origin validation mismatch** — [GHSA-22w3-693w-x895](https://github.com/advisories/GHSA-22w3-693w-x895): subdomain allowance can create relying-party origin mismatches.
- **ShellHub filter/sort crash DoS** — [GHSA-47r2-v3x6-wff9](https://github.com/advisories/GHSA-47r2-v3x6-wff9): field injection in query filters can terminate service processes.

## Why this is durable

Directory and identity systems are availability and trust anchors. Parser crashes, validator-before-auth ordering, non-constant secret comparisons, and permissive origin matching can all become authentication bypass, outage, or account-takeover primitives.

## Immediate triage

1. Patch Kanidm, WebAuthn, LDAP/SCIM parser libraries, and ShellHub where present.
2. Add recursion, token, and byte limits to LDAP/SCIM/filter parsers; reject over-budget inputs before allocation or recursion.
3. Move authorization checks before image, filter, or partial-render validators that can panic or perform expensive work.
4. Replace secret comparisons with constant-time functions and remove timing differences from error paths.
5. Re-test WebAuthn relying-party IDs with sibling subdomains, wildcard-like configurations, and mixed origin canonicalization.

## Durable controls

- Treat every identity-directory parser as exposed infrastructure; fuzz it with depth, nesting, malformed Unicode, and oversized fields.
- Keep validation cheap before auth and expensive parsing after auth, quota, and object-ownership checks.
- Bind WebAuthn credentials to exact relying-party IDs and explicit, reviewed subdomain policy.
- Render htmx/partial templates with the same sanitization and CSRF assumptions as full-page HTML.
