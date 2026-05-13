# Parser, resource, HTTP, and Rack-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because many issues are not classic injection bugs: they are parser differentials, unbounded caches, response panics, and framework edge cases that become exploitable only under weird but valid protocol inputs.

## Advisories covered

- **Snappier framed-input infinite loop** — [GHSA-pggp-6c3x-2xmx](https://github.com/advisories/GHSA-pggp-6c3x-2xmx): malformed SnappyStream frames could hang decompression.
- **Granian WSGI response-header panic** — [GHSA-f5p7-9fr5-8jmj](https://github.com/advisories/GHSA-f5p7-9fr5-8jmj): response header handling could panic and deny service.
- **Granian WebSocket subprotocol panic** — [GHSA-vrg7-482j-p6f6](https://github.com/advisories/GHSA-vrg7-482j-p6f6): unauthenticated WebSocket subprotocol input could panic the server.
- **Micronaut TimeConverterRegistrar cache exhaustion** — [GHSA-8hjv-92q9-g4xj](https://github.com/advisories/GHSA-8hjv-92q9-g4xj): Accept-Language variation populated an unbounded formatter cache.
- **Micronaut ResourceBundleMessageSource cache exhaustion** — [GHSA-3rfq-4wpf-qqw3](https://github.com/advisories/GHSA-3rfq-4wpf-qqw3): Accept-Language variation populated an unbounded bundle cache.
- **PhpSpreadsheet XLSX row-dimension CPU DoS** — [GHSA-7c6m-4442-2x6m](https://github.com/advisories/GHSA-7c6m-4442-2x6m): unbounded row numbers drove excessive work.
- **PhpSpreadsheet SpreadsheetML row-index CPU DoS** — [GHSA-84wq-86v6-x5j6](https://github.com/advisories/GHSA-84wq-86v6-x5j6): unbounded row indexes drove excessive XML reader work.
- **vLLM hidden-state speculative-decoding crash** — [GHSA-83vm-p52w-f9pw](https://github.com/advisories/GHSA-83vm-p52w-f9pw): penalty parameters could crash extract_hidden_states serving paths.
- **vLLM special-token placeholder DoS** — [GHSA-hpv8-x276-m59f](https://github.com/advisories/GHSA-hpv8-x276-m59f): special token placeholders could remotely deny service.
- **ciguard unbounded SCA HTTP body** — [GHSA-xw8c-rrvx-f7xq](https://github.com/advisories/GHSA-xw8c-rrvx-f7xq): the client read response bodies without a size cap.
- **OpAMP unbounded HTTP response bodies** — [GHSA-w2jh-77fq-7gp8](https://github.com/advisories/GHSA-w2jh-77fq-7gp8): client response handling lacked a body budget.
- **phpseclib ASN.1 OID amplification DoS** — [GHSA-3qpq-r242-jqj7](https://github.com/advisories/GHSA-3qpq-r242-jqj7): CVE-2024-27355 mitigation could be bypassed through ASN1::decodeOID allocation.
- **Bouncy Castle excessive allocation** — [GHSA-4cx2-fc23-5wg6](https://github.com/advisories/GHSA-4cx2-fc23-5wg6): certificate/API parsing could allocate excessively.
- **Tomcat resource shutdown/release** — [GHSA-hgrr-935x-pq79](https://github.com/advisories/GHSA-hgrr-935x-pq79): request/resource lifecycle handling could be abused.
- **Tomcat relative path traversal** — [GHSA-wmwf-9ccg-fff5](https://github.com/advisories/GHSA-wmwf-9ccg-fff5): path normalization crossed intended resource boundaries.
- **Tomcat escape/control sequence neutralization** — [GHSA-vfww-5hm6-hx2j](https://github.com/advisories/GHSA-vfww-5hm6-hx2j): control sequences were not neutralized correctly.
- **Tomcat resource shutdown follow-up** — [GHSA-gqp3-2cvr-x8m3](https://github.com/advisories/GHSA-gqp3-2cvr-x8m3): resource shutdown/release flaws remained a durable Tomcat patch target.
- **Addressable template ReDoS** — [GHSA-h27x-rffw-24p4](https://github.com/advisories/GHSA-h27x-rffw-24p4): template parsing could hit catastrophic regular-expression behavior.
- **rdiscount out-of-bounds read** — [GHSA-6r34-94wq-jhrc](https://github.com/advisories/GHSA-6r34-94wq-jhrc): Markdown/native parsing crossed memory-safety boundaries.
- **Rack session decrypt-failure fallback** — [GHSA-33qg-7wpp-89cq](https://github.com/advisories/GHSA-33qg-7wpp-89cq): cookie secret handling could fall back into secretless forgery and Marshal deserialization.
- **Rack invalid Host characters** — [GHSA-g2pf-xv49-m2h5](https://github.com/advisories/GHSA-g2pf-xv49-m2h5): Host allowlists could be bypassed with invalid characters.
- **Rack::Files Content-Length mismatch** — [GHSA-q2ww-5357-x388](https://github.com/advisories/GHSA-q2ww-5357-x388): error responses could disagree on body length.
- **Rack::Sendfile X-Accel-Mapping regex injection** — [GHSA-qv7j-4883-hwh7](https://github.com/advisories/GHSA-qv7j-4883-hwh7): header-controlled mapping could produce unauthorized X-Accel-Redirect behavior.
- **Rack multipart unbounded chunked uploads** — [GHSA-8vqr-qjwx-82mw](https://github.com/advisories/GHSA-8vqr-qjwx-82mw): uploads without Content-Length lacked a hard budget.
- **Rack multipart escape-heavy quoted-parameter DoS** — [GHSA-v6x5-cg8r-vv6x](https://github.com/advisories/GHSA-v6x5-cg8r-vv6x): header parsing could burn resources on escaped parameters.
- **Rack::Directory regex disclosure** — [GHSA-7mqq-6cf9-v2qp](https://github.com/advisories/GHSA-7mqq-6cf9-v2qp): unescaped regex interpolation disclosed root-directory information.
- **Rack best-encoding quadratic complexity** — [GHSA-v569-hp3g-36wr](https://github.com/advisories/GHSA-v569-hp3g-36wr): wildcard Accept-Encoding negotiation could go quadratic.
- **Rack Forwarded semicolon injection** — [GHSA-qfgr-crr9-7r49](https://github.com/advisories/GHSA-qfgr-crr9-7r49): forwarded header parsing could spoof Host and scheme.
- **Rack folded multipart header CRLF preservation** — [GHSA-rx22-g9mx-qrhv](https://github.com/advisories/GHSA-rx22-g9mx-qrhv): improper unfolding preserved CRLF in parameter values.
- **Rack greedy multipart boundary parsing** — [GHSA-vgpv-f759-9wx3](https://github.com/advisories/GHSA-vgpv-f759-9wx3): parser differentials could create WAF bypasses.
- **Rails Active Storage glob injection** — [GHSA-73f9-jhhh-hr5m](https://github.com/advisories/GHSA-73f9-jhhh-hr5m): DiskService globbing could cross file-selection boundaries.
- **Rails Active Storage path traversal** — [GHSA-9xrj-h377-fr87](https://github.com/advisories/GHSA-9xrj-h377-fr87): DiskService path handling could traverse outside intended storage.
- **Rails Active Support number-helper DoS** — [GHSA-2j26-frm8-cmj9](https://github.com/advisories/GHSA-2j26-frm8-cmj9): numeric helpers had resource-exhaustion behavior.
- **Rails Active Storage proxy Range DoS** — [GHSA-r46p-8f7g-vvvg](https://github.com/advisories/GHSA-r46p-8f7g-vvvg): range requests in proxy mode could exhaust resources.
- **Rails Active Storage content-type bypass** — [GHSA-qcfx-2mfw-w4cg](https://github.com/advisories/GHSA-qcfx-2mfw-w4cg): direct-upload metadata could bypass content-type controls.

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

