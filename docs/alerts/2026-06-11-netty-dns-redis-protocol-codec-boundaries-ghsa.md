# Netty protocol codec boundary checks

Source: hourly offensive-security scan, 2026-06-11, with updated-feed follow-ups on 2026-06-29 and 2026-07-07. Primary entries: GitHub advisories [GHSA-cm33-6792-r9fm](https://github.com/advisories/GHSA-cm33-6792-r9fm) / CVE-2026-42579 for Netty `codec-dns` input validation bypass, [GHSA-rgrr-p7gp-5xj7](https://github.com/advisories/GHSA-rgrr-p7gp-5xj7) / CVE-2026-42586 for Netty `codec-redis` CRLF injection, [GHSA-p979-4mfw-53vg](https://github.com/advisories/GHSA-p979-4mfw-53vg) / CVE-2019-16869 for Netty HTTP header whitespace request smuggling, [GHSA-676x-f7gg-47vc](https://github.com/advisories/GHSA-676x-f7gg-47vc) / CVE-2026-45674 and [GHSA-5pvg-856g-cp85](https://github.com/advisories/GHSA-5pvg-856g-cp85) / CVE-2026-47691 for DNS bailiwick cache-poisoning gaps, [GHSA-h2qv-fj59-j46j](https://github.com/advisories/GHSA-h2qv-fj59-j46j) / CVE-2026-48059 for HAProxy PROXY v2 nested SSL TLV buffer leaks, and [GHSA-6jv9-x5w9-2ccm](https://github.com/advisories/GHSA-6jv9-x5w9-2ccm) / CVE-2026-48006 for Redis aggregate lifecycle leaks.

This is durable for operators because these advisories expose the same reusable test class: **application-controlled protocol tokens cross into a Netty encoder/decoder without enforcing the delimiter, length, or grammar rules that downstream protocol peers rely on**.

## Why it matters for assessments

Netty is often buried inside Java service clients, API gateways, sidecars, proxies, and bespoke integration services. A dependency finding is only useful when it maps to an attacker-controlled protocol boundary. For these advisories, the operator value is in finding places where user, tenant, webhook, or upstream service input becomes one of these protocol fields:

- DNS query names handled by `io.netty:netty-codec-dns`;
- DNS responses accepted from a controlled or semi-controlled resolver path;
- Redis inline commands built with `InlineCommandRedisMessage`;
- Redis simple-string or error responses relayed by a Netty Redis proxy or middleware;
- diagnostic, cache, queue, or feature-flag tooling that constructs Redis commands from request parameters;
- Netty-backed HTTP servers, gateways, or framework embeddings that sit behind a proxy and accept raw header syntax containing whitespace before a colon, such as `Transfer-Encoding : chunked`.

Do not treat every transitive Netty dependency as exploitable. The practical boundary is: **can an in-scope actor influence the DNS name, DNS response, Redis inline command content, Redis text response content, or raw HTTP header framing before Netty serializes or parses it?**

## What to map first

1. Confirm written authorization for dependency-to-protocol validation. DNS and Redis tests can affect shared infrastructure if aimed at production resolvers or data stores.
2. Identify Java services that include either module:
   - `io.netty:netty-codec-dns` at vulnerable versions up to `4.1.132.Final` or `4.2.12.Final`;
   - `io.netty:netty-codec-redis` at vulnerable versions up to `4.1.132.Final` or `4.2.12.Final`.
   - `io.netty:netty-all` before `4.1.42.Final`, legacy `org.jboss.netty:netty` `<= 3.2.9.Final`, or `io.netty:netty` `3.3.0.Final` through `4.0.0.Alpha8` for the HTTP whitespace request-smuggling issue.
3. Trace whether untrusted input reaches the relevant Netty message constructors or resolver paths. Prioritize:
   - webhook fetchers, URL previewers, SSRF-adjacent components, crawler jobs, and tenant-configured callback domains;
   - Redis proxies, admin consoles, cache-debug endpoints, queue-inspection tools, and custom Redis clients;
   - services that accept a user-supplied hostname and perform asynchronous Netty DNS resolution rather than JDK-only resolution.
4. Build a disposable lab or customer-approved test tenant. Use canary domains, canary Redis keys, and test-only Redis databases.
5. Keep validation non-destructive: no production key deletion, no secret reads, no cache flushing, no attempts to poison shared resolvers, and no cross-user or shared-queue request desynchronization in production.

## DNS codec validation boundary

The DNS advisory highlights three validation gaps that matter during authorized testing:

- null bytes embedded in labels, creating possible interpretation differences across Java strings, DNS packets, and C/native consumers;
- labels longer than the RFC 1035 63-byte limit, where high length values can collide with compression-pointer ranges in other parsers;
- empty labels in the middle of a name, where the encoded name may stop earlier than the application-level string implies.

Safe canary inputs for a lab resolver harness:

```text
safe-canary.example.test
safe-canary..suffix.example.test
longlabel-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.test
null-byte-canary\x00suffix.example.test
```

Record whether the application rejects the input before Netty, what DNS packet is emitted in the lab, and which name the resolver or downstream parser observes. The useful proof is a **string-to-wire mismatch** or **wire-to-decoder mismatch**, not a broad DNS poisoning attempt.

## Redis codec validation boundary

The Redis advisory is specific to text-delimited Redis message forms, not normal length-prefixed bulk strings. Focus on code paths that use:

- `InlineCommandRedisMessage` for command construction;
- `SimpleStringRedisMessage` or `ErrorRedisMessage` for proxy or middleware responses;
- custom Redis diagnostic features that concatenate command text.

Safe lab canary shape:

```text
GET skillz-canary
<CRLF>
PING skillz-canary
```

Use this only against a disposable Redis instance or a mock server controlled by the assessment. The proof should show that a single user-controlled value creates an extra RESP command boundary or forged text response in the lab. Do not demonstrate destructive Redis commands, credential extraction, `CONFIG`, `MODULE`, `EVAL`, `FLUSH*`, or production key access.

If the service uses `ArrayRedisMessage` plus `BulkStringRedisMessage`, document that the tested path is length-prefixed and not represented by this CRLF boundary unless another text command path exists.

## HTTP header whitespace request-smuggling boundary

The June 29 updated-feed item for [GHSA-p979-4mfw-53vg](https://github.com/advisories/GHSA-p979-4mfw-53vg) / CVE-2019-16869 adds an older but still useful HTTP parser differential: vulnerable Netty versions mishandle whitespace before the colon in a header field name. The canary shape is a line such as:

```text
Transfer-Encoding : chunked
```

This matters only when a front-end proxy, CDN, WAF, load balancer, or service mesh rejects or normalizes that header differently than the Netty origin. During authorized testing, treat it as a proxy-origin parser-boundary check, not as generic dependency triage.

Safe validation workflow:

1. Confirm the service is actually Netty-backed and reachable through at least one front-end hop. A direct Netty-only service without a differential parser is usually lower-value for request-smuggling proof.
2. Use a lab host or a customer-approved canary route. Avoid shared production connection pools unless the rules of engagement explicitly include request-smuggling validation.
3. Send one raw HTTP request at a time and mutate only the whitespace-before-colon boundary. Keep the second request, if any, pointed at a harmless canary path that the tester owns.
4. Record whether the front end and Netty origin disagree about the presence or meaning of `Transfer-Encoding`, `Content-Length`, or another hop-sensitive header.

Evidence should show the escaped raw bytes, front-end response, origin/canary observation, and whether the result is limited to rejection/normalization or reaches a real queue, route, cache, or auth-boundary effect. Do not publish weaponized desync payloads, target other users' requests, or use protected production paths as proof.

## July 7 DNS bailiwick and buffer-lifecycle follow-up

The July 7 updated-feed wave adds four adjacent Netty items that belong on this same protocol-boundary page rather than a duplicate alert.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-676x-f7gg-47vc](https://github.com/advisories/GHSA-676x-f7gg-47vc) / CVE-2026-45674 | Netty `DnsResolveContext#buildAliasMap` | CNAME records from DNS answers can be cached without confirming the response origin is authoritative for the queried name | Resolver assessments should test whether attacker-controlled authoritative zones can influence aliases outside their bailiwick in a disposable DNS lab. |
| [GHSA-5pvg-856g-cp85](https://github.com/advisories/GHSA-5pvg-856g-cp85) / CVE-2026-47691 | Netty `AuthoritativeNameServerList` / `handleWithAdditional` | NS records and additional A records from a subdomain response can be cached under a parent-domain authority key | DNS cache-poisoning validation should prove parent-zone authority confusion only with owned domains and mock resolvers, not public suffixes or shared resolvers. |
| [GHSA-h2qv-fj59-j46j](https://github.com/advisories/GHSA-h2qv-fj59-j46j) / CVE-2026-48059 | Netty HAProxy PROXY protocol v2 codec | syntactically valid nested `PP2_TYPE_SSL` TLVs can pin pooled buffers on successful parse paths | Edge/proxy reviews should map whether untrusted clients can send PROXY v2 frames directly to a Netty listener that assumes only a trusted load balancer speaks that protocol. |
| [GHSA-6jv9-x5w9-2ccm](https://github.com/advisories/GHSA-6jv9-x5w9-2ccm) / CVE-2026-48006 | Netty Redis `RedisArrayAggregator` | incomplete RESP arrays retained during connection teardown can leak pooled direct buffers | Redis-proxy reviews should test parser lifecycle cleanup against disposable Redis/mock services when arbitrary peers can open and drop protocol connections. |

### DNS bailiwick cache-boundary harness

Use this only with domains and resolvers you control.

- Preconditions: vulnerable Netty resolver version, an application feature that resolves user-controlled hostnames through Netty DNS, one owned parent zone, one owned delegated child zone, and a disposable recursive/cache harness.
- Configure an authoritative server for the child zone to return only canary records. Do not target public suffixes, customer parent zones, or third-party resolvers.
- For CNAME testing, answer a query for a child-zone host with an alias or record set that should be out of bailiwick for that authority. Record whether Netty caches the alias outside the intended authority boundary.
- For NS/additional testing, answer a child-zone query with a parent-zone NS claim plus additional A canaries. Record whether the parent authority cache key is populated from the child response.
- Positive evidence: subsequent resolutions in the same lab resolver context use the canary out-of-bailiwick CNAME/NS/additional data.
- Negative controls: patched Netty build, strict bailiwick rejection, empty cache after the child-zone response, and an in-bailiwick canary that remains accepted.
- Do not poison shared resolvers, `.co.uk`-style public suffixes, production parent domains, customer DNS, or real service records.

Report this as **authoritative DNS response to Netty resolver cache authority confusion**. Include zone ownership, query name, response authority, cache key observed, TTL, and patched behavior.

### PROXY v2 and Redis parser-lifecycle harness

Use this only on isolated listeners or mock services.

- Preconditions: vulnerable Netty version, a lab listener that enables the HAProxy PROXY v2 decoder or Redis aggregation path, and local metrics/logging for buffer allocation behavior.
- For PROXY v2, send a syntactically valid header with nested SSL TLV structure only to a listener explicitly configured for the test. Stop at parser acceptance and controlled buffer-retention evidence.
- For Redis, open a disposable connection to a mock Redis/Netty pipeline, start an aggregate RESP array with canary bulk strings, then close before completion. Observe whether retained buffers are released on channel teardown.
- Positive evidence: parser-success or teardown paths retain buffers across repeated lab iterations while the application releases normal messages.
- Negative controls: patched Netty, non-nested PROXY TLV, complete RESP array, and lifecycle hooks that release retained child messages.
- Do not run high-volume exhaustion, target production load balancers, spoof real client IPs, interact with production Redis, or consume live queues/keys.

Report this as **protocol parser lifecycle cleanup failure**, not generic DoS. Include listener exposure, trusted-proxy assumption, protocol frame class, iteration count, memory metric class, and patch/control comparison.

## Evidence to capture

Strong evidence includes:

- exact package name and vulnerable version from the build, SBOM, or runtime classpath;
- the reachable application feature that supplies attacker-controlled input;
- the Netty class, message type, or HTTP parser path reached by that feature;
- sanitized canary input and the corresponding lab wire output or mock-server transcript;
- confirmation that evidence used a disposable resolver, Redis database, tenant, or mock service;
- whether the impact is limited to malformed packet generation, parser differential, command injection precondition, request-smuggling precondition, or confirmed canary command/request boundary.

Keep packet captures and Redis transcripts scoped to canaries. Redact hostnames, tenant IDs, and infrastructure details that are not needed for the public report.

## Reporting heuristics

- Lead with the boundary, not the dependency: **untrusted protocol token reaches Netty DNS/Redis codec without grammar validation**.
- Separate DNS encoder, DNS decoder, and Redis encoder findings. They have different prerequisites and impact.
- For HTTP, lead with the proxy-origin parser split: **Netty and the front end disagree on a whitespace-before-colon header line**.
- For Redis, explicitly state whether the affected path uses inline/simple-string/error messages or length-prefixed bulk strings.
- For DNS, show the application-level string and the observed wire/lab-decoded name side by side.
- Do not claim DNS cache poisoning, Redis RCE, request desync impact, or data theft unless the customer-approved lab proof demonstrates that impact with canary-only artifacts.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, CISA KEV, and GitHub advisory feeds. No new non-GitHub source item produced separate durable operator guidance this hour. Previously processed axios, Keycloak, Undertow, and availability-only updated-feed entries remained represented by existing wiki coverage or did not justify a new offensive workflow page.

## July 22 HTTP bridge, text-protocol, CORS, XML, and OCSP follow-up

The late wave affects common Netty release lines before `4.1.136.Final` and `4.2.16.Final`; verify the exact module and range in each advisory. It adds five durable protocol-boundary families:

| Advisory | Boundary worth testing |
| --- | --- |
| [GHSA-c69g-56f8-xwqj](https://github.com/advisories/GHSA-c69g-56f8-xwqj) / CVE-2026-59900 | HTTP/2 `:authority` plus a literal `host` becomes two HTTP/1 `Host` fields after `Http2StreamFrameToHttpObjectCodec` or `InboundHttp2ToHttpAdapter` translation. |
| [GHSA-4mp9-239f-g9hg](https://github.com/advisories/GHSA-4mp9-239f-g9hg) / CVE-2026-59898 | WebSocket V07/V08 handshakers accept a version-7 upgrade without the HTTP `Connection: Upgrade` and `Upgrade: websocket` signals a front end expects. |
| [GHSA-gcjf-9mgh-3p7g](https://github.com/advisories/GHSA-gcjf-9mgh-3p7g) / CVE-2026-59921 | Multipart field names or filenames containing CRLF become additional MIME headers or body-part boundaries in `HttpPostRequestEncoder`. |
| [GHSA-3g8r-4pfx-jmfh](https://github.com/advisories/GHSA-3g8r-4pfx-jmfh) / CVE-2026-59920 | Raw newlines in STOMP `CONNECT`/`CONNECTED` header values become additional protocol headers because compatibility disables escaping without adding rejection. |
| [GHSA-wh89-7897-x99h](https://github.com/advisories/GHSA-wh89-7897-x99h) / CVE-2026-59919 | CRLF in an AF_UNIX address becomes a second line in HAProxy PROXY v1 output; IPv4/IPv6 format checks do not cover this address family. |
| [GHSA-6cqp-g7gg-8hr5](https://github.com/advisories/GHSA-6cqp-g7gg-8hr5) / CVE-2026-56746 | `Origin: null` selects a CORS config object even when null origin is not allowed, defeating `CorsHandler.shortCircuit()` before backend processing. |
| [GHSA-4qhr-g3c6-fcfx](https://github.com/advisories/GHSA-4qhr-g3c6-fcfx) / CVE-2026-56817 | `XmlDecoder` creates an XML factory without disabling DTD/entity handling; external resolution remains conditional on the actual Aalto async parser path. |
| [GHSA-272m-gcwp-mpwg](https://github.com/advisories/GHSA-272m-gcwp-mpwg), [GHSA-g7hg-vrcf-mvmr](https://github.com/advisories/GHSA-g7hg-vrcf-mvmr), and [GHSA-wc96-39fc-566f](https://github.com/advisories/GHSA-wc96-39fc-566f) | OCSP validation can accept a signed `GOOD` response for another certificate, accept stale status, or notify downstream handlers that TLS is ready before asynchronous revocation validation finishes. |

### HTTP/2 and WebSocket bridge matrix

Use a disposable front end plus Netty origin and a canary virtual host. For HTTP/2 translation, vary `:authority`, literal `host`, equality/order, and single-header controls; record the HTTP/2 frame, translated HTTP/1 object, every Host value, selected route, and patched result. A useful proof is **one H2 request -> two conflicting Host values -> a harmless routing/auth/cache decision uses a different authority than the edge**.

For WebSocket, compare versions 7, 8, and 13 with complete, missing, and malformed `Connection`/`Upgrade` headers. Capture the front-end interpretation, Netty handshaker choice, `101` response, and only a marker frame. The claim is **front end sees ordinary HTTP -> origin switches protocols**, not request smuggling unless a separate single-connection canary demonstrates a parser-boundary effect. Never target another user's connection or a shared production pool.

### Encoder delimiter matrix

Test encoders offline with `EmbeddedChannel` and a mock receiver. Supply a normal token, CR, LF, CRLF, quote, colon, and boundary-like marker to exactly one field at a time: multipart field name/filename, STOMP CONNECT header value, or HAProxy v1 AF_UNIX source/destination. Save escaped input bytes, serialized wire bytes, parsed field/header count, and fixed-version rejection.

Positive evidence is one application value becoming two wire-level fields or lines. Use inert names and marker headers only. Do not forge auth material, spoof real client IPs, upload executable browser content, or send malformed PROXY/STOMP traffic to production brokers and edges.

### CORS and XML controls

For CORS, place a marker-only backend handler behind `CorsHandler.shortCircuit()`, explicitly disallow null origin, and compare absent, allowed, disallowed HTTPS, and literal `Origin: null`. Record both response headers and whether the backend marker ran; CORS response-header behavior alone does not prove the short-circuit bypass.

For XML, first prove an attacker-controlled channel reaches `XmlDecoder`. Use an owned loopback entity endpoint and inert entity text, then compare DTD disabled/enabled, no-DOCTYPE, patched Netty, and the exact Aalto parser version. Report only confirmed callback or expansion behavior; an unconfigured factory is a risky sink, not automatic XXE on every runtime. Never reference local files or internal services.

### OCSP decision table

Build a local CA, mock OCSP responder, and Netty client whose first post-handshake action sends only a fixed canary to a local TLS server. Test: matching fresh `GOOD`, matching revoked, stale `GOOD`, `GOOD` for another certificate from the same CA, delayed revoked response, and patched versions. Record requested and returned CertificateID hashes/serials, `thisUpdate`/`nextUpdate`, validation event order, channel-close order, and whether the canary was sent before final status.

Keep keys and certificates disposable. Never intercept production OCSP, replay public certificate status, or send credentials as the post-handshake marker. Separate the findings as **response identity mismatch**, **freshness failure**, and **handshake/validation event-order TOCTOU**.

Availability-only Bzip2, HTTP/1 pipelining, HTTP/3, SPDY, and HAProxy decoder exhaustion items from the wave were tracked without standalone offensive guidance.
