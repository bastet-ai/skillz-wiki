# Parser, deserialization, and resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced parser and deserialization advisories updated on **2026-05-06** for Nokogiri and Jackson Databind.

## Advisories covered

- **Nokogiri CSS selector tokenizer ReDoS** — [GHSA-c4rq-3m3g-8wgx](https://github.com/advisories/GHSA-c4rq-3m3g-8wgx): crafted CSS selectors could trigger excessive regular-expression backtracking.
- **Nokogiri XSLT transform memory leak** — [GHSA-v2fc-qm4h-8hqv](https://github.com/advisories/GHSA-v2fc-qm4h-8hqv): repeated XSLT transforms could leak memory and degrade availability.
- **Jackson Databind unsafe deserialization/gadget typing batch** — [GHSA-9m6f-7xcq-8vf8](https://github.com/advisories/GHSA-9m6f-7xcq-8vf8), [GHSA-c265-37vj-cwcc](https://github.com/advisories/GHSA-c265-37vj-cwcc), [GHSA-j823-4qch-3rgm](https://github.com/advisories/GHSA-j823-4qch-3rgm), [GHSA-27xj-rqx5-2255](https://github.com/advisories/GHSA-27xj-rqx5-2255), and [GHSA-5p34-5m6p-p58g](https://github.com/advisories/GHSA-5p34-5m6p-p58g): older gadget/typing advisories refreshed in GitHub metadata.

## Why this is durable

Parsers and serializers are program interpreters. CSS selectors, XSLT, JSON type metadata, and polymorphic binding can consume unbounded resources or instantiate attacker-influenced behavior unless type and resource budgets are explicit.

## Immediate triage

1. Upgrade Nokogiri and Jackson Databind dependencies, including transitive copies bundled by frameworks.
2. Identify endpoints that accept HTML/XML/CSS selectors, XSLT, JSON with polymorphic typing, or user-controlled object type metadata.
3. Disable Jackson default typing for untrusted input; use allowlisted subtypes and DTOs instead of binding directly to domain objects.
4. Put parser operations behind CPU, memory, recursion, node-count, transform-count, and wall-clock limits.
5. Review availability telemetry for regex backtracking spikes, XSLT transform memory growth, and unexpected deserialization classes.

## Durable controls

- Treat every parser feature as a budgeted interpreter: measure and enforce limits before content reaches business logic.
- Keep untrusted data in data-only formats; do not deserialize into arbitrary runtime classes.
- Centralize XML/XSLT/CSS/JSON parser configuration so unsafe defaults cannot be reintroduced per endpoint.
- Add regression corpora for selector backtracking, large transforms, gadget type metadata, and deeply nested documents.
