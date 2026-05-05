# Parser, render, and resource-budget boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because old parser assumptions keep resurfacing: recursive JavaScript utilities, GraphQL lexers, HTTP/2 atoms, OCSP URL strings, HTML helper methods, NoSQL filters, and observability UIs all need explicit budgets and output contexts.

## Advisories covered

- **Underscore recursion DoS** — [GHSA-qpx9-hpmf-5gmw](https://github.com/advisories/GHSA-qpx9-hpmf-5gmw): `_.flatten` and `_.isEqual` can recurse without bound.
- **OpAMP unbounded response bodies** — [GHSA-w2jh-77fq-7gp8](https://github.com/advisories/GHSA-w2jh-77fq-7gp8): client reads HTTP response bodies without size limits.
- **Prometheus old web UI heatmap XSS** — [GHSA-fw8g-cg8f-9j28](https://github.com/advisories/GHSA-fw8g-cg8f-9j28): crafted histogram bucket label values can trigger stored XSS.
- **GraphQL-Ruby token-count bypass** — [GHSA-3h96-34p3-xm76](https://github.com/advisories/GHSA-3h96-34p3-xm76): Ruby lexer excludes comment tokens from `max_query_string_tokens` accounting.
- **ip-address HTML helper XSS** — [GHSA-v2v4-37r5-5v8g](https://github.com/advisories/GHSA-v2v4-37r5-5v8g): Address6 HTML-emitting methods can produce XSS.
- **Mongoose `$nor` sanitizeFilter gap** — [GHSA-wpg9-53fq-2r8h](https://github.com/advisories/GHSA-wpg9-53fq-2r8h): improper `$nor` sanitization can allow NoSQL injection.
- **rust-openssl OCSP responder UB** — [GHSA-xp3w-r5p5-63rr](https://github.com/advisories/GHSA-xp3w-r5p5-63rr): non-UTF-8 OCSP URLs in certificates can trigger undefined behavior.
- **Plug.Cowboy HTTP/2 atom-table exhaustion** — [GHSA-q8x4-x7mp-5vg2](https://github.com/advisories/GHSA-q8x4-x7mp-5vg2): unauthenticated HTTP/2 `:scheme` values can exhaust the atom table.

## Operator triage

1. Add regression tests for nested arrays, cyclic/equivalent-object comparisons, GraphQL comments, malformed HTTP/2 pseudo-headers, and certificates with non-UTF-8 responder URLs.
2. Enforce query/token/depth/node/time budgets before parsing GraphQL, JSON, recursive utility input, observability labels, and client protocol responses.
3. Search dashboards, admin UIs, and library HTML helpers for labels or address strings rendered without context-specific escaping.
4. Review Mongo/Mongoose filters for `$nor`, nested operator injection, and places where `sanitizeFilter` is assumed to be a complete authorization boundary.
5. Patch internet-facing HTTP/2 services quickly when parser/resource bugs are reachable pre-auth.

## Durable controls

- Every parser and client needs explicit byte, token, node, recursion, allocation, and wall-clock limits with fail-closed errors.
- Security filters must parse into typed ASTs and reject unknown operators; string-key sanitizers are not enough for query authorization.
- Observability labels and helper-rendered values are untrusted display input and require HTML/context encoding like any user field.
- Certificate and URL libraries must treat non-UTF-8 and malformed extension values as validation failures, not as lossy strings.
- Prefer finite protocol vocabularies for atoms/enums; never convert untrusted wire strings into non-garbage-collected atoms or interned identifiers.
