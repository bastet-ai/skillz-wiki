# WordPress REST batch-route and `WP_Query` SQL boundary chain

Sources: [WordPress 7.0.2 security release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/), [CVE-2026-60137](https://nvd.nist.gov/vuln/detail/CVE-2026-60137), [CVE-2026-63030](https://nvd.nist.gov/vuln/detail/CVE-2026-63030), and the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). CISA added both CVEs on 2026-07-21 and describes the pair as a chain that can reach unauthenticated remote code execution on affected default installations.

This page is not a generic patch alert. The durable operator lesson is to test framework chains one boundary at a time: a REST batch router may interpret a subrequest differently from the target route, while a query abstraction that is safe for typed callers can become injectable when an extension passes attacker-controlled values into it.

!!! warning "Lab or explicitly approved customer validation only"
    These CVEs are in KEV. Do not replay the active chain against an internet-facing site. Use a disposable WordPress lab with synthetic posts/users, no real plugins, credentials, media, database, mail, or outbound access. Stop at a boolean or timing-free synthetic query differential; do not attempt code execution, file writes, account creation, credential access, or persistence.

## Confirmed scope

| CVE | Confirmed affected line | Boundary |
| --- | --- | --- |
| CVE-2026-60137 / GHSA-fpp7-x2x2-2mjf | WordPress 6.8 before 6.8.6, 6.9 before 6.9.5, and 7.0 before 7.0.2 | A plugin or theme can pass untrusted `author__not_in` input into `WP_Query`; core did not sanitize that parameter correctly. This is facilitated SQL injection, not a universal unauthenticated core route by itself. |
| CVE-2026-63030 / GHSA-ff9f-jf42-662q | WordPress 6.9 before 6.9.5 and 7.0 before 7.0.2 | REST API batch-route confusion can expose the query boundary and chain with CVE-2026-60137. WordPress 6.8 is not listed as affected by this second issue. |

Versions before 6.8 are not affected according to the vendor release. WordPress also shipped fixes in 7.1 beta 2.

## Recon and reachability

1. Confirm WordPress ownership and exact core version from approved inventory, authenticated Site Health output, package manifests, or a lab image. Do not rely on generator tags alone.
2. Inventory the REST API root and batch endpoint from WordPress route discovery. Record whether the batch route is present, whether authentication is required, and which methods/subroutes it accepts.
3. Inventory plugins/themes or custom code that pass request-derived data to `WP_Query`, especially `author__not_in`. For CVE-2026-60137 alone, document the exact extension-to-core call path; core version presence does not prove reachability.
4. Build a route matrix for direct target-route requests versus the same harmless request wrapped as a REST batch subrequest. Record route, method, authentication decision, argument schema, normalized parameter type, and handler reached.

## Marker-only chain validation

Seed a disposable database with two synthetic authors and uniquely marked public posts. Preserve a normal direct request and normal batch request as controls. Then vary only the `author__not_in` representation across an integer, integer array, duplicate value, string form, malformed delimiter/quote canary, and the upstream regression fixture if it is available in the vendor test suite.

Capture these boundaries separately:

1. **Batch interpretation:** Does the outer batch router authenticate, normalize, or validate the subrequest differently from a direct request to the same route?
2. **Type transition:** What raw value reaches the route callback, extension, and `WP_Query`? Record types rather than sensitive SQL text.
3. **Query construction:** Does the generated prepared-statement/parameter trace retain the value as data, or does query structure change?
4. **Observable proof:** Does only the synthetic public result set change in a way the typed control cannot produce?

Use database query logging only in the disposable lab and redact unrelated statements. Avoid time-delay, stacked-query, file, user-table, option-table, or database-function payloads. A safe finding is **unauthenticated batch subrequest -> parameter type/route confusion -> extension passes attacker-controlled `author__not_in` -> synthetic `WP_Query` result differs**.

## Negative controls and reporting

- Compare 6.8.6, 6.9.5, or 7.0.2 with the matching affected release.
- Repeat the target route directly, outside the batch wrapper.
- Remove or replace the extension call path that forwards untrusted `author__not_in`.
- Use a typed integer-array request that should produce the intended exclusion.
- Show that an unrelated malformed parameter is rejected, preventing a generic “REST accepts bad input” claim.
- State whether only CVE-2026-60137 is reachable or whether the CVE-2026-63030 batch-route precondition is also proven.
- Do not claim RCE from SQL behavior alone. The report must keep query injection, privilege/context, and any execution sink as separate boundaries; this workflow intentionally stops before the final sink.