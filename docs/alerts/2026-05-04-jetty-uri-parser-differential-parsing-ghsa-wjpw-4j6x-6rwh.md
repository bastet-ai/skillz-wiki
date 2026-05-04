# Jetty URI parser differential parsing (GHSA-wjpw-4j6x-6rwh / CVE-2025-11143)

**Signal:** GitHub Security Advisories updated **2026-05-04**. Eclipse Jetty `jetty-http` parses some malformed or unusual URIs differently from other common URL parsers, creating bypass risk when one component validates a URL and another component later routes, fetches, redirects, or authorizes it.

## What it is

Jetty's URI parser disagreed with other parsers on several edge cases:

- malformed schemes such as `https>://...`;
- malformed or IPv4-mapped IPv6 literals;
- bracket / delimiter priority around IPv6-style hosts, userinfo-like `@`, query strings, and fragments.

The advisory is rated low in isolation, but it is durable because parser disagreement becomes high-impact when URL policy is split across components: proxy allowlists, SSRF filters, redirect validators, auth middleware, cache keys, WAF rules, and application routing can each interpret the same bytes differently.

Affected Maven package: `org.eclipse.jetty:jetty-http` in Jetty 9.4.x, 10.0.x, 11.0.x, 12.0.x, and 12.1.x ranges. Fixed open-source versions are **12.0.31** and **12.1.5**; older EOL branches require commercial/backport support or migration.

References: <https://github.com/advisories/GHSA-wjpw-4j6x-6rwh>, <https://github.com/jetty/jetty.project/security/advisories/GHSA-wjpw-4j6x-6rwh>, <https://nvd.nist.gov/vuln/detail/CVE-2025-11143>

## Triage

1. Inventory Jetty-backed services that make security decisions from request target, host, scheme, redirect destination, or user-supplied URLs.
2. Prioritize services where Jetty sits behind another proxy/parser, or where Jetty validates a URL that a different HTTP client, framework, browser, WAF, or cache later consumes.
3. Review allowlist, denylist, SSRF, open-redirect, CORS/origin, tenant-routing, and virtual-host logic for parser mixing.
4. Identify EOL Jetty branches (`9.4`, `10`, `11`) and decide whether to buy backports, isolate, or migrate; do not assume EOL branches receive public Maven fixes.

## Mitigation

- Upgrade to Jetty **12.0.31** or **12.1.5** where possible.
- Centralize URL parsing for each security decision: parse once, canonicalize once, and pass the structured result forward instead of re-parsing raw strings in downstream components.
- Reject malformed authority, bracket, scheme, userinfo, fragment/query delimiter, and IPv4-mapped IPv6 edge cases at ingress before allowlist checks.
- For SSRF and redirect controls, validate the final resolved destination after redirects and after DNS/IP normalization, not just the original string.
- Add regression tests that compare the exact parsers in production: edge proxy, Jetty, application framework, HTTP client, browser/client, and cache.

## Hunt ideas

- Search request logs for `[` or `]` in host/path positions, `@` in authority-like strings, `#@`, `?@`, malformed schemes, and bracketed IPv6 literals.
- Review 3xx responses, SSRF guard denials, proxy rejects, and WAF blocks for mismatches: one layer accepts while another rejects or rewrites.
- Compare canonical host/scheme/path values recorded by proxy logs vs application logs for the same request ID.
- Add canary tests for known-bad URL forms to CI and edge-health checks so parser changes fail closed.

## Durable lesson

URL parsing is a trust boundary, not a utility detail. Security-sensitive URL decisions need one canonical parser/policy path and adversarial differential tests across every parser that will touch the request.
