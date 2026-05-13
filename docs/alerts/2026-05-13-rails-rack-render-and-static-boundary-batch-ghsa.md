# Rails, Rack, render, and static-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because framework helper APIs are easy to treat as inherently safe. The advisories show that escaping, formatting, debug output, byte-range handling, and static-file path matching all need their own trust-boundary tests.

## Advisories covered

- **Active Support `SafeBuffer#%` XSS** — [GHSA-89vf-4333-qx8v](https://github.com/advisories/GHSA-89vf-4333-qx8v): formatted strings could cross an HTML-safety boundary in `activesupport` before `7.2.3.1`, `8.0.4.1`, and `8.1.2.1`.
- **Active Support `number_to_delimited` ReDoS** — [GHSA-cg4j-q9v8-6v38](https://github.com/advisories/GHSA-cg4j-q9v8-6v38): delimiter formatting could consume excessive CPU on crafted input. Patch `activesupport` to the fixed Rails release line.
- **Action View tag-helper XSS** — [GHSA-v55j-83pf-r9cq](https://github.com/advisories/GHSA-v55j-83pf-r9cq): Rails tag helpers could produce unsafe output in affected `actionview` versions before the fixed Rails release lines.
- **Action Pack debug-exception XSS** — [GHSA-pgm4-439c-5jp6](https://github.com/advisories/GHSA-pgm4-439c-5jp6): debug exception rendering could become scriptable in `actionpack 8.1.0` through `<8.1.2.1`.
- **Decidim user-name XSS** — [GHSA-fc46-r95f-hq7g](https://github.com/advisories/GHSA-fc46-r95f-hq7g): attacker-controlled user names could become stored XSS in `decidim-core` before `0.30.5` and in `0.31.0.rc1`.
- **Rack multipart byte-range DoS** — [GHSA-x8cg-fq8g-mxfx](https://github.com/advisories/GHSA-x8cg-fq8g-mxfx): excessive overlapping ranges could exhaust request-processing resources. Patch Rack to `2.2.23`, `3.1.21`, or `3.2.6`.
- **Rack::Static `header_rules` bypass** — [GHSA-q4qf-9j86-f5mh](https://github.com/advisories/GHSA-q4qf-9j86-f5mh): URL-encoded paths could bypass header rules before the fixed Rack releases.
- **Rack::Static prefix exposure** — [GHSA-h2jq-g4cq-5ppq](https://github.com/advisories/GHSA-h2jq-g4cq-5ppq): prefix matching could expose unintended files under the static root before the fixed Rack releases.

## Operator triage

1. Patch Rails/Rack stacks first when they expose user profile names, debug pages, static-file roots, or large file downloads.
2. Confirm production disables debug exception rendering and that staging debug hosts are not internet-accessible.
3. Search access logs for overlapping `Range` headers, URL-encoded static paths, unusually long numeric delimiters, and stored profile-name payloads.
4. Add regression tests that render representative untrusted strings through helper APIs rather than only testing direct template interpolation.

## Durable controls

- Treat “safe string” helpers as context-sensitive encoders, not blanket declassification of user input.
- Put length, count, and overlap budgets on `Range` handling before framework multipart helpers allocate work.
- Canonicalize URL paths once before static-file allow/deny/header-rule decisions; do not mix decoded and raw prefix checks.
- Keep debug renderers behind auth, network policy, and production-off switches because they often combine stack metadata with HTML output.
