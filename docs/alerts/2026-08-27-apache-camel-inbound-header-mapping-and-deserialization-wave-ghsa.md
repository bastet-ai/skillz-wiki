# Apache Camel inbound header-to-Exchange mapping and deserialization wave

**Date reviewed:** 2026-08-27  
**Advisories:** the July 6 Camel CVE wave plus the JMS ObjectMessage deserialization advisory  
**Severity:** Critical and High (multiple CVSS 9.x)  
**Boundary class:** inbound transport headers → Exchange property mapping without `HeaderFilterStrategy`; unsafe Java/`ObjectInputStream` deserialization in several Camel components

## What is durable here

This is a multi-component Camel wave with one recurring trust-boundary
pattern that is worth generalizing for any Camel route audit:

**Inbound transport headers are mapped into the Exchange without a
`HeaderFilterStrategy`.** When a Camel endpoint receives untrusted
inbound messages (HTTP, JMS, AMQP, SNS, CometD/Bayeux, Vertx-HTTP,
Netty-HTTP, Elasticsearch-REST), the transport's native headers are
copied into `Exchange` properties. If the route (or a default filter
that is absent) does not strip headers outside the `Camel-` namespace,
an attacker who controls inbound headers can:

- inject `Camel-*` headers that downstream components treat as
  routing/instruction material (SSRF via `CamelHttpUri`, header-based
  endpoint reselection, expression injection),
- reach components that **deserialize** Exchange property values with
  `java.io.ObjectInputStream` (JMS `ObjectMessage`, Vertx-HTTP /
  Netty-HTTP response bodies, Hazelcast managed instances, PQC AWS
  Secrets Manager key metadata),
- bypass the default `ObjectInputFilter` where the default pattern is
  permissive enough to admit `java.net.**` (enables DNS-based
  disclosure / OOB exfiltration even where full gadget chains are not
  available).

The individual advisories in this wave:

| Advisory | Component | Boundary |
| --- | --- | --- |
| [GHSA-r9cc-j7wr-p329](https://github.com/advisories/GHSA-r9cc-j7wr-p329) / CVE-2026-46454 | camel-cometd | Inbound Bayeux message headers mapped into the Exchange without a `HeaderFilterStrategy` |
| [GHSA-m5vh-3fw5-5wgh](https://github.com/advisories/GHSA-m5vh-3fw5-5wgh) / CVE-2026-40860 | camel-jms / sjms / sjms2 / amqp | Unsafe deserialization of JMS `ObjectMessage` |
| [GHSA-rp9m-hfv5-pfvr](https://github.com/advisories/GHSA-rp9m-hfv5-pfvr) / CVE-2026-46453 | camel-elasticsearch-rest-client | Exchange header constants without the `Camel` prefix bypass inbound HTTP header filtering |
| [GHSA-f755-xp6r-8q84](https://github.com/advisories/GHSA-f755-xp6r-8q84) / CVE-2026-40860, CVE-2026-43866 | camel-jms | JMS deserialization filter bypass |
| [GHSA-xww8-mxqw-m84w](https://github.com/advisories/GHSA-xww8-mxqw-m84w) / CVE-2026-43865 | camel-hazelcast | Unsafe Java deserialization in default-configured managed Hazelcast instances |
| [GHSA-6qw3-4796-5984](https://github.com/advisories/GHSA-6qw3-4796-5984) / CVE-2026-40859 | camel-vertx-http / camel-netty-http | Unsafe Java deserialization of HTTP response bodies via raw `ObjectInputStream` |
| [GHSA-w2v8-8q6c-3rhr](https://github.com/advisories/GHSA-w2v8-8q6c-3rhr) / CVE-2026-46456, CVE-2026-56140 | camel-aws2-sns | Inbound Camel-namespace filter added to `Sns2HeaderFilterStrategy` (prior versions did not strip) |
| [GHSA-7cmx-qjh8-7v3v](https://github.com/advisories/GHSA-7cmx-qjh8-7v3v) / CVE-2026-40048, CVE-2026-43867, CVE-2026-46590 | camel-pqc | AWS Secrets Manager key-lifecycle manager deserializes persisted key metadata with `java.io.ObjectInputStream` |
| [GHSA-rpv3-6645-2vqc](https://github.com/advisories/GHSA-rpv3-6645-2vqc) / CVE-2026-40047 | camel-docling | Insufficient validation of custom CLI arguments enables argument injection and path traversal |
| [GHSA-8h6p-jvhf-9hcr](https://github.com/advisories/GHSA-8h6p-jvhf-9hcr) / CVE-2026-42527 | camel (core) | Permissive default `ObjectInputFilter` pattern admits `java.net.**` (DNS-based disclosure) |

## Recon: enumerate Camel endpoints and header flows

1. **Find the Camel version.** The July 6 wave is the most recent CVE
   publication batch; the JMS `ObjectMessage` deserialization advisory
   ([GHSA-m5vh-3fw5-5wgh](https://github.com/advisories/GHSA-m5vh-3fw5-5wgh))
   was published earlier. Check `camel-core`, the transport
   components in use (`camel-vertx-http`, `camel-netty-http`,
   `camel-jms`, `camel-amqp`, `camel-cometd`, `camel-hazelcast`,
   `camel-aws2-sns`, `camel-docling`, `camel-elasticsearch-rest-client`),
   and `camel-pqc`.
2. **Map inbound endpoints.** For each `from()` that accepts untrusted
   inbound messages, note which transport is used and whether a
   `HeaderFilterStrategy` (or `CamelHttpUri`-style filtering) is
   registered on that endpoint or globally.
3. **Check the default `ObjectInputFilter`.** If the Camel version
   predates the filter fix, the default pattern admits `java.net.**`.
   Even without a full deserialization gadget chain, an attacker who
   can control an Exchange property value that reaches a
   `ObjectInputStream` can trigger DNS lookouts (OOB disclosure /
   exfiltration of the serialized payload's reachable state).
4. **Identify the `ObjectMessage` path.** If the route uses
   `camel-jms` / `camel-amqp` with `ObjectMessage` support and the
   deserialization filter is absent or bypassable (the JMS filter
   bypass advisory), a JMS broker that accepts attacker-controlled
   `ObjectMessage` payloads is a direct RCE primitive.

## Validation workflow (authorized lab / customer-approved)

### Header-injection proof (no code execution)

1. Identify an inbound HTTP endpoint that maps to a Camel route with
   no `HeaderFilterStrategy`.
2. Send a request with a benign `Camel-` namespaced header, e.g.
   `Camel-Test-Trace: skillz-canary`. If the header appears in the
   Exchange (visible in route logs, a downstream HTTP request's
   `Camel-Test-Trace` header, or a route that echoes Exchange
   properties), the mapping is unfiltered.
3. Record the route and the specific header that crossed. Do not use
   `CamelHttpUri` or other instruction headers that would cause
   SSRF / endpoint reselection during the proof.

### Deserialization-boundary proof (no code execution)

1. Confirm the component is present and the deserialization path is
   reachable (e.g. a JMS `ObjectMessage` consumer, a Vertx-HTTP
   response-body deserialization, a Hazelcast managed instance).
2. Do **not** send a gadget-chain payload. The proof is that the
   deserialization sink is reachable with attacker-controlled bytes.
   Record the component, the Exchange property that carries the bytes,
   and the route.
3. If a permissive `ObjectInputFilter` is present, a DNS-lookup canary
   (a serialized `java.net.InetAddress`-adjacent object that triggers
   an outbound DNS query to an owned domain) is acceptable OOB
   evidence. Do not use it to exfiltrate data.

### Negative evidence

- A `400`/`403` on the inbound endpoint, or the absence of the
  attacker header in the Exchange, is negative evidence.
- If the `HeaderFilterStrategy` is present but the route still
  deserializes, the finding moves from "header injection" to
  "deserialization boundary" and the proof changes accordingly.

## Reporting heuristic

- Lead with the **specific transport and route** that maps untrusted
  headers into the Exchange without filtering. The generic "Camel
  header injection" framing is not useful; the value is the route
  map.
- State the Camel version and the components in use. The advisory
  range is component-specific.
- Separate "header injection" (routing / instruction) from
  "deserialization boundary" (RCE primitive). They are different
  findings with different proofs.
- Do not publish gadget-chain payloads. The proof is the reachable
  sink + the unfiltered header mapping.

## Safety constraints

- Do not execute arbitrary code on the target.
- Do not use `CamelHttpUri` or similar instruction headers to
  redirect traffic during the proof.
- Use owned DNS callback domains only for OOB disclosure.
- Do not test against production JMS brokers or Hazelcast instances
  with live data.

## August 29 follow-up: Camel header-filter bypass wave (30 GHSAs)

The Aug 29 GitHub updated-feed wave adds **30 more Apache Camel advisories in the same bug class**: inbound message/transport headers mapped into the Exchange **without a `HeaderFilterStrategy`**, or component-specific Exchange-header constants whose names do not carry the `Camel-` prefix that the default HTTP header filter strips. Same operator pattern, more sink sites.

### Sub-patterns in the wave

1. **Non-Camel-prefixed component header constants bypass the HTTP filter.** A large group of components define Exchange-header constants with un-prefixed names (`kafka.OVERRIDE_TOPIC`, `irc.sendTo`, `QUERY` / `RETURN_LUCENE_DOCS`, `SolrParam.*` / `SolrField.*`, `operationName` / `operationNamespace`, `mail.smtp.*`, Salesforce/JIRA/Neo4j property names). An HTTP client that can reach the consumer endpoint can inject these directly.
   - **Critical, Solr** ([GHSA-4h4f-v54q-7pq8](https://github.com/advisories/GHSA-4h4f-v54q-7pq8) / CVE-2026-48203): injected `SolrParam.*` headers are server-side request forgery into Solr query parameters; `SolrField.*` injects document fields.
   - **Critical, AWS2-SQS** ([GHSA-cmc3-hr79-8mmv](https://github.com/advisories/GHSA-cmc3-hr79-8mmv) / CVE-2026-46456): inbound SQS message attributes map into the Exchange unfiltered, a message *sender* can inject Camel control headers.
   - **Critical, Keycloak** ([GHSA-mqwc-6qwc-v9gq](https://github.com/advisories/GHSA-mqwc-6qwc-v9gq) / CVE-2026-46455): the access-token validity window is not verified because the `IS_ACTIVE` check is missing from the `TokenVerifier`, expired tokens are accepted.
   - **Critical, Undertow / Atmosphere-Websocket** ([GHSA-v7h8-xhh6-gfj4](https://github.com/advisories/GHSA-v7h8-xhh6-gfj4) / CVE-2026-78329, [GHSA-m5r8-w65q-8wjf](https://github.com/advisories/GHSA-m5r8-w65q-8wjf) / CVE-2026-71300): the endpoint discards the component-specific header filter entirely; websocket dispatch headers are injected.
   - High: Lucene full-text query injection ([GHSA-566h-v38h-3xp3](https://github.com/advisories/GHSA-566h-v38h-3xp3) / CVE-2026-46585), Neo4j Cypher injection via `CamelNeo4jMatchProperties` property names, incomplete remediation of CVE-2025-66169 ([GHSA-q86m-qjpm-vqcw](https://github.com/advisories/GHSA-q86m-qjpm-vqcw) / CVE-2026-46591), CXF SOAP operation-redirect ([GHSA-mrrp-9gjm-749v](https://github.com/advisories/GHSA-mrrp-9gjm-749v) / CVE-2026-46592), Couchbase/CouchDB operation override ([GHSA-46jf-c9vx-hh79](https://github.com/advisories/GHSA-46jf-c9vx-hh79) / CVE-2026-46587, [GHSA-5g68-f6xg-vf2r](https://github.com/advisories/GHSA-5g68-f6xg-vf2r) / CVE-2026-46588), Langchain4j tool-argument headers not filtered against declared parameters ([GHSA-hh8r-75r6-qrg9](https://github.com/advisories/GHSA-hh8r-75r6-qrg9) / CVE-2026-49042), NATS/Iggy/Vertx-Websocket/Atmosphere-Websocket inbound mapping without any filter strategy ([GHSA-7v55-q9x3-83cj](https://github.com/advisories/GHSA-7v55-q9x3-83cj) / CVE-2026-46457, [GHSA-pw9q-pq7c-rfqw](https://github.com/advisories/GHSA-pw9q-pq7c-rfqw) / CVE-2026-55994, [GHSA-hgg5-gp4c-gpcg](https://github.com/advisories/GHSA-hgg5-gp4c-gpcg) / CVE-2026-46726, [GHSA-rcvm-6r79-cf4r](https://github.com/advisories/GHSA-rcvm-6r79-cf4r) / CVE-2026-55993).
   - Medium: Kafka topic override ([GHSA-mm84-qvjh-hcj7](https://github.com/advisories/GHSA-mm84-qvjh-hcj7) / CVE-2026-49098), IRC `irc.sendTo` ([GHSA-463m-2hr2-q2j7](https://github.com/advisories/GHSA-463m-2hr2-q2j7) / CVE-2026-49097), Salesforce ([GHSA-gcc7-c8mp-34qx](https://github.com/advisories/GHSA-gcc7-c8mp-34qx) / CVE-2026-49099), JIRA constants ([GHSA-64gv-6cq2-45jr](https://github.com/advisories/GHSA-64gv-6cq2-45jr) / CVE-2026-48206), Dapr Pub/Sub CloudEvent name/topic copied into producer routing headers ([GHSA-583r-f84w-33g7](https://github.com/advisories/GHSA-583r-f84w-33g7) / CVE-2026-49086), Knative CloudEvent extension fields mapped without filter ([GHSA-vvwm-3j43-7pfm](https://github.com/advisories/GHSA-vvwm-3j43-7pfm) / CVE-2026-63621).
2. **Inbound header/attribute mapping without any `HeaderFilterStrategy` at the transport boundary**, the same header-injection primitive as the original wave, now documented for NATS, Iggy, SQS, Atmosphere, and Vertx-Websocket consumers.
3. **File-download path construction from remote object names.** `Google-Storage` appends the remote object name to the local download path without sanitization ([GHSA-f78g-9385-qxqj](https://github.com/advisories/GHSA-f78g-9385-qxqj) / CVE-2026-66907); `Azure-Storage-Blob` `downloadBlobToFile` builds the local path from the blob name ([GHSA-2x37-89hj-2j95](https://github.com/advisories/GHSA-2x37-89hj-2j95) / CVE-2026-66906, critical); `Azure-Storage-DataLake` `downloadToFile` the same ([GHSA-7jwc-q3fj-c9pq](https://github.com/advisories/GHSA-7jwc-q3fj-c9pq) / CVE-2026-60093). Same class as the original wave's filename-to-local-path entries: remote metadata → local filesystem write path.
4. **`muteException` defaulting to false leaks full stack traces** in Netty-HTTP ([GHSA-42q5-xw42-xf9g](https://github.com/advisories/GHSA-42q5-xw42-xf9g) / CVE-2026-49365) and Undertow ([GHSA-hjg2-f45w-c566](https://github.com/advisories/GHSA-hjg2-f45w-c566) / CVE-2026-56139) consumers. Availability/low-value on its own; pair with header-injection findings when the same route is in scope.
5. **Mail `mail.smtp.*` header injection**, the mail producer applies attacker-supplied `mail.smtp.*`/`mail.smtps.*` headers as JavaMail session properties ([GHSA-29vj-9mgp-mwp2](https://github.com/advisories/GHSA-29vj-9mgp-mwp2) / CVE-2026-46584); the MimeMultipart data format copies MIME headers onto the Camel message when `headersInline` is enabled ([GHSA-cx47-qxp5-mmh2](https://github.com/advisories/GHSA-cx47-qxp5-mmh2) / CVE-2026-59230).
6. **PQC key-lifecycle manager** ([GHSA-857v-xvh8-7hjc](https://github.com/advisories/GHSA-857v-xvh8-7hjc) / CVE-2026-46590): HashiCorp Vault and AWS Secrets Manager key-lifecycle management headers cross into key operations, treat as a key-management authority boundary, not generic header injection.

### Durable pattern (unchanged from the original wave)

For any Camel route that consumes an inbound message:

- enumerate the component's Exchange-header constants and check whether each is `Camel-`-prefixed;
- check whether a `HeaderFilterStrategy` is configured *and* whether the endpoint's own filter is applied (two Camel endpoints in this wave discarded the component-specific filter entirely);
- for file-download components, test remote object names with path-separator and traversal markers (stop at denied/normalized-path evidence on a disposable root).

### Validation deltas from the original workflow

- **Solr SSRF:** send a canary `SolrParam.*` header that steers the query to an owned Solr/HTTP endpoint; evidence is the query parameter landing in the outbound request, not document mutation.
- **Neo4j Cypher injection:** property-name canary that reaches the `WHERE` clause; capture the rendered Cypher in a read-only lab Neo4j, no `CALL`/write procedures.
- **Keycloak token expiry:** mint a synthetic access token, let it expire, present it through a Camel route with Camel-Keycloak auth; positive = route accepts the expired token (`IS_ACTIVE` check missing). Lab realm only.
- **CloudEvent routing (Dapr/Knative):** inject a canary pub/sub name or extension field and observe producer-direction routing header propagation; stop at header-propagation evidence.

## Sources

- Aug 29 follow-up: the 30 GHSAs listed inline above, each linked in the [GitHub Advisory Database](https://github.com/advisories).
- Original wave context: the July 6 Apache Camel CVE wave and the JMS `ObjectMessage` deserialization advisory covered by this page's header.
