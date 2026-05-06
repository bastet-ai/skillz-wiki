# Spring AI and framework resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced Spring AI, Spring gRPC, and Micronaut advisories updated on **2026-05-06**.

## Advisories covered

- **Spring AI VectorStore filter-expression injection** — [GHSA-qc4j-qjqx-vr58](https://github.com/advisories/GHSA-qc4j-qjqx-vr58): attacker-controlled vector-store filters could become backend queries. Fixed in 1.0.6 / 1.1.5.
- **Spring AI CosmosDBVectorStore SQL injection** — [GHSA-63c8-m9m2-cvr3](https://github.com/advisories/GHSA-63c8-m9m2-cvr3): delete filters could inject Cosmos DB query syntax. Fixed in 1.0.6 / 1.1.5.
- **Spring AI VectorStoreChatMemoryAdvisor cross-tenant memory exfiltration** — [GHSA-v6x6-pjxw-3pv2](https://github.com/advisories/GHSA-v6x6-pjxw-3pv2): conversation scoping could mix tenant memory. Fixed in 1.0.6 / 1.1.5.
- **Spring AI ONNX predictable world-writable model cache** — [GHSA-r5hp-3cgj-j6xv](https://github.com/advisories/GHSA-r5hp-3cgj-j6xv): default `/tmp` cache placement could let local users influence model files. Fixed in 1.0.6 / 1.1.5.
- **Spring AI PDF reader OOM** — [GHSA-26gg-9gv2-v27j](https://github.com/advisories/GHSA-26gg-9gv2-v27j): attacker-controlled PDFs could exhaust memory. Fixed in 1.0.6 / 1.1.5.
- **Spring gRPC SecurityContext leak** — [GHSA-4g9c-3x4p-mfpp](https://github.com/advisories/GHSA-4g9c-3x4p-mfpp): authorization failure paths could leak security context across requests. Fixed in 1.0.3.
- **Spring gRPC reflected AuthenticationException messages** — [GHSA-37w2-q6vh-45v6](https://github.com/advisories/GHSA-37w2-q6vh-45v6): remote clients could receive internal authentication exception content. Fixed in 1.0.3.
- **Micronaut unbounded language caches** — [GHSA-8hjv-92q9-g4xj](https://github.com/advisories/GHSA-8hjv-92q9-g4xj), [GHSA-3rfq-4wpf-qqw3](https://github.com/advisories/GHSA-3rfq-4wpf-qqw3): `Accept-Language`-derived formatter/message caches could grow without bound. Fixed in 4.10.22.

## Why this is durable

AI framework glue is still application framework code: vector filters become queries, chat memory becomes tenant data, model caches become local trust roots, and document readers become parsers. Resource and identity boundaries must survive the convenience abstraction.

## Immediate triage

1. Patch Spring AI to 1.0.6 / 1.1.5, Spring gRPC to 1.0.3, and Micronaut to 4.10.22 where applicable.
2. Inventory vector-store filters, chat-memory keys, PDF ingestion endpoints, ONNX/model cache paths, and gRPC interceptors.
3. Search logs for unusual filter syntax, cross-tenant conversation IDs, large or malformed PDFs, rare `Accept-Language` values, and authentication exceptions returned to clients.
4. Move model caches to service-owned, non-world-writable directories with atomic creation and integrity checks.
5. Put document parsing and language negotiation behind request-size, cache-cardinality, CPU, memory, and wall-clock limits.

## Durable controls

- Compile vector filters from typed allowlisted fields and operators; never concatenate user expressions into backend query syntax.
- Scope chat memory by immutable tenant and principal IDs, not display names or caller-supplied conversation labels.
- Clear or recreate security context on every gRPC request path, including authorization exceptions.
- Bound caches keyed by attacker-controlled headers; normalize languages before lookup and evict aggressively.
