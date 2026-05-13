# Supply-chain, crypto, events, and data-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

Package compromise and data-format advisories are durable because they live between trust domains: package registries, event streams, blockchain certificates, HTML helpers, and broker/client semantics.

## Advisories covered

- **PyTorch Lightning PyPI package compromise** — [GHSA-w37p-236h-pfx3](https://github.com/advisories/GHSA-w37p-236h-pfx3): published package versions were compromised, requiring dependency, token, and build-host triage.
- **sse-channel event-field injection** — [GHSA-84hm-wfh8-c5pg](https://github.com/advisories/GHSA-84hm-wfh8-c5pg): unsanitized event fields could inject Server-Sent Event semantics.
- **ip-address Address6 HTML XSS** — [GHSA-v2v4-37r5-5v8g](https://github.com/advisories/GHSA-v2v4-37r5-5v8g): HTML-emitting helpers could render address data as scriptable output.
- **bsv-sdk ARC broadcaster success confusion** — [GHSA-9hfr-gw99-8rhx](https://github.com/advisories/GHSA-9hfr-gw99-8rhx): INVALID, MALFORMED, or ORPHAN responses were treated as successful broadcasts.
- **bsv-sdk and bsv-wallet unverified certifier signatures** — [GHSA-hc36-c89j-5f4j](https://github.com/advisories/GHSA-hc36-c89j-5f4j): certificate acquisition paths persisted unverified certifier signatures.
- **RoadRunner HTTP request/response smuggling** — [GHSA-g9pc-8g42-g6vq](https://github.com/advisories/GHSA-g9pc-8g42-g6vq): a vulnerable dependency created request/response boundary ambiguity.

## Operator triage

1. Patch affected packages and hosted services first where the vulnerable component is internet-facing, tenant-facing, or reachable by untrusted project data.
2. Inventory transitive exposure; many of these bugs live in helpers, plugins, middleware, scanner images, or framework defaults rather than application code.
3. Search logs for boundary probes: encoded paths, unusual headers, oversized bodies, duplicate auth attempts, symlinked project files, private-network URLs, and stored HTML/script payloads.
4. Add regression tests at the trust boundary, not only at the direct vulnerable function. Exercise canonicalized paths, redirects, alternate address syntax, concurrent auth, and malformed protocol inputs.

## Durable controls

- Canonicalize once, authorize after canonicalization, and execute/use only the canonicalized object.
- Give every parser, helper, cache, upload, range handler, and HTTP client explicit byte, item, time, and recursion budgets.
- Treat user-controlled templates, package metadata, project files, identity headers, event fields, and backup archives as untrusted code-adjacent inputs.
- Prefer positive allowlists tied to resolved identities/resources over deny-lists tied to raw input strings.

