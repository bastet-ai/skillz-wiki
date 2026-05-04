# Config provenance and query-validation boundary batch (GHSA)

**Signal:** GitHub Security Advisories surfaced a **2026-05-04** batch where URL path decoding exposed server configuration files, Git signature revocation policy lost provenance, and GraphQL validation allowed small compressed requests to burn large CPU budgets.

## Advisories in this batch

- **XWiki WebJars path traversal to configuration files** — `org.xwiki.platform:xwiki-platform-webjars-api >= 7.1.4, < 16.10.7` and `>= 17.0.0-rc-1, < 17.4.0-rc-1` can expose configuration files such as `WEB-INF/xwiki.cfg` through encoded separators in WebJars URLs. Fixed in 16.10.7 and 17.4.0-rc-1. Reference: <https://github.com/advisories/GHSA-qww7-89xh-x7m7>, CVE-2025-55747.
- **sequoia-git hard-revocation handling gap** — `sequoia-git < 0.6.0` could miss hard revocations removed from a signing policy after a cache-key bug truncated the policy hash to zero bytes, allowing a malicious merge to strip a compromised signer revocation. Fixed in 0.6.0. Reference: <https://github.com/advisories/GHSA-g27r-r6ph-vf5r>.
- **webonyx/graphql-php inline-fragment validation DoS** — `webonyx/graphql-php < 15.32.2` has quadratic `OverlappingFieldsCanBeMerged` validation cost for flattened inline fragments, letting low-rate requests consume PHP workers before execution. Fixed in 15.32.2. Reference: <https://github.com/advisories/GHSA-fc86-6rv6-2jpm>.

## Why this is durable

These are not one-off bugs. They are trust-boundary failures around **canonicalization**, **policy provenance**, and **pre-execution resource budgeting**:

- URL components decoded differently during routing and filesystem assembly can turn static asset APIs into secret-file readers.
- Security policy caches are only safe when the cache key faithfully represents the whole policy state, including revocations.
- Validation logic is part of the request attack surface; cheap-looking syntax can trigger expensive semantic comparisons before auth, complexity checks, or resolvers run.

## Immediate triage

1. Patch XWiki to 16.10.7 or 17.4.0-rc-1, sequoia-git to 0.6.0, and webonyx/graphql-php to 15.32.2.
2. For internet-exposed XWiki, review access logs for `/webjars/` requests containing encoded slashes, repeated `..`, `WEB-INF`, `xwiki.cfg`, or unusual wiki prefixes.
3. For projects relying on `sq-git`, review recent signing-policy changes and merge requests touching policy files, especially those removing hard revocations or signer metadata.
4. For GraphQL PHP services, rate-limit validation failures and long validations immediately; reduce request body size limits after decompression, not just before compression.

## Hunt ideas

- Search reverse-proxy and app logs for encoded traversal patterns: `%2f`, `%2F`, `%252f`, `%5c`, `..%2f`, and `wiki%3A` around static or WebJars routes.
- Diff signed-project policy files across recent commits for removed revocations, changed certificate material, or unexpected policy rewrites bundled with unrelated code.
- Instrument GraphQL validation duration separately from resolver duration; alert on queries with many repeated inline fragments, tiny complexity/depth scores, or high gzip compression ratios.
- Review PHP-FPM metrics for worker exhaustion where CPU time is spent before resolver execution or application logs show no corresponding business action.

## Durable controls

- Decode URL paths exactly once at the routing edge, reject encoded separators where filesystem paths are later assembled, and enforce canonical containment after final decode.
- Keep secret configuration outside web-accessible trees when possible; if not, deny sensitive path suffixes before static asset resolution.
- Treat signing-policy files as protected security controls: require code-owner review, semantic diffs, and explicit approval for revocation removal.
- Cache security-policy decisions with complete, collision-resistant keys and include regression tests where policy removal must not hide prior hard revocations.
- Give validators independent budgets: wall-clock timeout, comparison counter, AST-node/selection caps, decompressed body-size limits, and per-client concurrency caps.

## Operator lesson

Pre-execution code is still attack surface. Canonicalize before authority, preserve revocation provenance, and budget validators like they are exposed parsers—because they are.
