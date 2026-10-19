# Apache Camel October wave: message-supplied placeholder injection, fail-open guards, gate-vs-router case divergence, and unauthenticated cluster transports

**Event in one line:** On 2026-10-19 12:32Z Apache published a ~28-GHSA coordinated Camel wave (all fixed **4.18.5 / 4.22.1 / 4.23.0**; bands `4.0.0–4.18.4` and `4.19.0–4.22.0`, some from 4.4.0/4.7.0/4.11.0/4.15.0). The headline leg turns the already-known `CamelHttpUri` header override into **configuration and secret retrieval**: the HTTP producer families ran the attacker-supplied URI string through `resolvePropertyPlaceholders()` — a facility that reaches OS env vars, JVM system properties, every registered `PropertiesFunction` including the AWS/Azure/GCP/HashiCorp/IBM/CyberArk/Kubernetes **secret functions**, and through camel-bean the invocation of a no-argument method on **any bean in the registry**. A plain static `to("http://backend/api")` route was sufficient — the route author opted into none of this.

**Why this is durable operator content:** this is the second full Camel wave in eight weeks (see the [August 27 page](2026-08-27-apache-camel-inbound-header-mapping-and-deserialization-wave-ghsa.md) for the header-mapping/deserialization canon), and it generalizes beyond Camel to every integration/routing framework that (a) resolves placeholders against message content, (b) implements auth as a route processor, (c) hardens one parser path per component, or (d) treats group/multicast membership as authentication. The same-product re-sweep rule fired again: the August wave's header-injection map is exactly where October's critical lives.

## Primary sources

GitHub advisories, all published 2026-10-19 12:32Z unless noted:

| Advisory | CVE | Component(s) | Boundary |
| --- | --- | --- | --- |
| [GHSA-394j-cc2x-w9wm](https://github.com/advisories/GHSA-394j-cc2x-w9wm) | CVE-2026-78164 (high) | camel-http, camel-vertx-http, camel-undertow, camel-netty-http | Message-supplied URI run through `resolvePropertyPlaceholders()` |
| [GHSA-5m9r-c7qx-c2h6](https://github.com/advisories/GHSA-5m9r-c7qx-c2h6) | CVE-2026-80312 (high) | camel-oauth | Auth processors fall through on failure — fail-open guard |
| [GHSA-pvjg-pwh7-34pj](https://github.com/advisories/GHSA-pvjg-pwh7-34pj) | CVE-2026-80343 (high) | camel-netty-http | Case-sensitive security-constraint match vs differently-cased routing dispatch |
| [GHSA-wqmw-6vq7-3mxp](https://github.com/advisories/GHSA-wqmw-6vq7-3mxp) | CVE-2026-88900 (high) | camel-jgroups | Stock `JChannel()` = no AUTH/encryption; `ObjectMessage` deserialized on the receive thread with no filter |
| [GHSA-7j2m-8x69-fhvh](https://github.com/advisories/GHSA-7j2m-8x69-fhvh) | CVE-2026-78162 (critical) | camel-hazelcast | Deserialization-filter fix did not reach the `doStart()` copy-paste twin or the client-mode config builder |
| [GHSA-68m6-7hmq-4c53](https://github.com/advisories/GHSA-68m6-7hmq-4c53) | CVE-2026-83531 (high, from 4.4.0) | dynamic-router-control | Predicate **and language name** taken from message body/headers, then compiled — expression injection |
| [GHSA-wrg6-q24g-59j6](https://github.com/advisories/GHSA-wrg6-q24g-59j6) | CVE-2026-80344 (high) | camel-as2 | Async MDN destination taken verbatim from the inbound message — SSRF with attached credentials |
| [GHSA-62ww-q9gh-hmrv](https://github.com/advisories/GHSA-62ww-q9gh-hmrv) | CVE-2026-78163 (high, from 4.15.0) | camel-docling | Body-prefix sniffing picks fetch-URL / local-read / temp-file mode implicitly |
| [GHSA-x4v6-22c3-2wm5](https://github.com/advisories/GHSA-x4v6-22c3-2wm5) | CVE-2026-88901 (high, from 4.7.0) | camel-smooks | Default Woodstox reader resolves external entities — hardening applied to other XML siblings only |
| [GHSA-x9f8-58m2-93q2](https://github.com/advisories/GHSA-x9f8-58m2-93q2) | CVE-2026-85250 (high) | camel-xpath | `documentType=InputSource` hands payload to JDK-default `DocumentBuilder`, skipping the hardened default path — XXE |
| [GHSA-qrg3-hxwc-36jm](https://github.com/advisories/GHSA-qrg3-hxwc-36jm) | CVE-2026-91858 (medium) | camel-fop | `FEATURE_SECURE_PROCESSING` alone does not restrict external access on third-party JAXP factories (Saxon on classpath) — XXE |
| [GHSA-c92r-fmfr-3q4w](https://github.com/advisories/GHSA-c92r-fmfr-3q4w) | CVE-2026-68571 (high, published 10-16) | Apache Kylin 4.0–5.0.4 | Special parameter in JDBC URL → code injection (fix 5.0.5) |

Tracked thin legs in the same wave (same bands, class-covered or detail-free): camel-core Jgroups-adjacent deserialization, OAuth CSRF (CVE-2026-84178), Shiro/Keycloak auth gaps (CVE-2026-84181/85301), Netty-HTTP/Platform-HTTP case-sensitivity and granularity pair, Crypto-PGP integrity-check validation (CVE-2026-85243), Thrift/AS2 wrong-session data elements (CVE-2026-85245/85296), Knative cert validation (CVE-2026-85247), Tika/Mail/Core input validation (CVE-2026-85249/85314/85312), error-message/secret disclosure legs (Mina/CXF/gRPC/MLLP/HTTP cache), Jetty/Platform-HTTP permissive CORS (CVE-2026-85313/84176), PQC default permissions (CVE-2026-85300), race condition (CVE-2026-85248).

## The axes this generalizes

### 1. Placeholder resolution over message content = secret retrieval and bean invocation

`CamelHttpUri` / `CamelRestHttpUri` headers let an inbound message override the producer endpoint URI (known since the August wave's header-injection canon). The October finding: before using that string, `HttpHelper.createURL/createMethod`, `VertxHttpHelper.resolveHttpURI`, `UndertowHelper.createURL/createMethod`, and `NettyHttpHelper.createURL` — **seven call sites** — passed it through `resolvePropertyPlaceholders()`. That facility expands `{{...}}` against OS env, JVM system properties, and every `PropertiesFunction` on the classpath: `aws-secret`, `google-secret`, `azure-keyvault`, `hashicorp-vault`, `ibm-cloud-secrets-manager`, `cyberark`, `kubernetes-secret` — plus camel-bean `bean:name,method` dispatch onto any registered bean's no-argument method.

- **Audit rule:** placeholder/template resolution is safe over *deployment configuration*, never over *exchange content*. Grep for `resolvePropertyPlaceholders`, `PropertyPlaceholderConfigurer`, `{{` handling applied to any value derived from `getIn().getHeader()` / body. Then enumerate which `PropertiesFunction`s the deployment registered (they are classpath-visible) — the reachable secret backends are the blast radius.
- **Probe shape (authorized lab):** on a route with an HTTP producer and unfiltered inbound headers, send `CamelHttpUri: http://{{skillz-canary}}/` against an owned DNS domain: an expansion-triggered lookup to the canary proves resolution ran over attacker content *without* fetching anything. For bean-invocation proof use an inert no-arg bean that writes a marker file in your own lab registry — never a real bean.
- **Header-override is the entry, resolution is the escalation:** even if the URI never reaches the network (malformed after expansion), the expansion side effects (env reads, secret fetches, bean calls) already ran. Proof does not require a successful outbound request.

### 2. Fail-open route guards: auth processors that don't stop the exchange

camel-oauth's route guards, on failure to establish an authenticated session, **returned control to the route** instead of terminating the exchange — the request continued to the protected endpoint as if authenticated, on the ordinary request path, no special configuration (CVE-2026-80312).

- **Test rule:** on security *processors* (route-intercepted auth, not container filters), the oracle is the **failure path**: force an auth failure (invalid/expired token, unreachable IdP if you can induce it) and observe whether the downstream endpoint still executes. A guard that swallows its own failure is indistinguishable from absent on that branch.
- Fingerprint: `401/403` from middleware vs silent pass-through with normal downstream response. Compare behavior across: no credential, malformed credential, valid-but-revoked credential — a guard that only rejects *clean* missing credentials is fail-open for everything else.

### 3. Gate-vs-router normalization divergence (case-sensitivity edition)

camel-netty-http compared the request path against the configured security-constraint context path **case-sensitively**, while dispatch used a different casing rule — flipping one character's case made the constraint miss while the request still reached the protected endpoint (CVE-2026-80343). No credential needed.

- This is the same family as Malcolm's Lua-RBAC-vs-nginx decode split (Oct 8) and kin-openapi's decoded-vs-encoded split (Sept 15, folded Oct 15) — the invariant: **the security gate and the dispatcher are two parsers; differential-test their path normalization.** The battery now covers: case flip (both directions), `%xx` encoded-vs-decoded, trailing slash/dot, duplicate slashes, `;params`, backslash (Windows). Camel adds **case** as the drift axis for Java servlet-style constraint matching.
- On any Camel netty-http/undertow deployment with security constraints: replay each protected path with one case-flipped character per segment and compare auth behavior vs dispatch result.

### 4. Implicit cluster membership = authentication (JGroups, Hazelcast)

camel-jgroups with default config calls `new JChannel()` — the stock UDP multicast stack with **no AUTH protocol and no encryption**. Any host that can reach the multicast group or bind the port joins the cluster and sends messages. Every received `ObjectMessage` was Java-deserialized on JGroups' own receive thread with **no `ObjectInputFilter`** (neither camel-jgroups nor the shipped JGroups versions installed one) → any gadget class on the app classpath deserializes before any Camel route logic runs (CVE-2026-88900). camel-hazelcast's critical leg is the **incomplete-fix genealogy**: the CVE-2026-43865 filter fix never reached `ReplicatedHazelcastAggregationRepository.doStart()` (a copy-pasted bootstrap block that skipped `super.doStart()`) or the `hazelcastMode=client` config builder — so *node mode was filtered, client mode was not, for identical configuration* (CVE-2026-78162).

- **Recon rule:** for middleware that forms implicit clusters (JGroups, Hazelcast, Infinispan, JChannel-based caches, multicast discovery), the **cluster join is the auth boundary** and by default it is open to the L2 domain. Check for AUTH/SASL/encryption protocol stacks in the shipped config before crediting the app's authentication.
- **Mode-differential audit:** client-mode vs node-mode vs aggregation-twin config builders are separate code paths. After any deserialization fix, test *every* instantiation path — the `extends` + overridden lifecycle method that skips `super.doStart()` is a grep-able shape.
- Validation boundary: lab multicast/unicast lab network, your own classpath canary class, never join a live production cluster or deserialization-probe shared infrastructure.

### 5. Expression injection via control-plane headers (dynamic-router-control)

The dynamic-router-control endpoint (4.4.0+) took both the routing **predicate** and the **expression language name** from the message body or the `CamelDynamicRouterPredicate` / `CamelDynamicRouterExpressionLanguage` headers, resolved the language from the CamelContext, and compiled — an attacker-controlled language + expression evaluated inside the process (CVE-2026-83531). With languages like groovy/OGRL/mvel on the classpath this is code execution; even simple/spel reaches data.

- Rule: **control-plane "manage the router" endpoints are attack surface with the same trust level as an admin API, but they speak message headers.** Enumerate management/control endpoints whose *policy* arrives in message content; probe header families named after policy primitives (`*Predicate`, `*Expression`, `*Language`, `*Script`, `*Query`).
- This leg also re-validates the August canon: inbound `Camel-*` header mapping is the shared enabler — sweep it once, feed every downstream header consumer from the same map.

### 6. Attacker-picks-the-destination protocol features (AS2 async MDN)

AS2 lets the sender request the MDN receipt be delivered **asynchronously to a sender-supplied address**; camel-as2 used the inbound-supplied address verbatim — SSRF from the AS2 receiver's position, into internal-only networks, **with the deployment's MDN delivery credentials attached** (CVE-2026-80344).

- Generalizes to every protocol with a callback/receipt/webhook-to-supplied-address field (MDN, SMTP DSN, SIP contact, SAML backchannel, payment-return URLs): the destination field is untrusted input, and the outbound leg often carries an identity you never meant to spend there.
- Hunt: for each inbound "please reply to…" field, check whether the outbound fetch/POST is destination-allowlisted and whether credentials are destination-scoped (the same anti-pattern as the KEDA `hashiCorpVault.address` leg on the [June 22 control-plane page](2026-06-22-glances-opendj-spinnaker-control-plane-boundaries-ghsa.md)).

### 7. Implicit mode selection from content prefixes (docling)

DoclingProducer decided what a String body *meant* by its prefix: `http(s)://` → remote fetch, leading `/` or backslash → local file read, else temp-file convert. No endpoint option pinned the mode (CVE-2026-78163) — a route intended to convert text silently became a URL fetcher and local-file reader for anyone who controls the body.

- Rule: **content-sniffed interpretation = attacker-selected code path.** Any `startsWith`-style mode dispatch over untrusted input is a privilege switch: grep for prefix sniffing that routes between fetch / read / execute / convert. Same genealogy as the Oct 9 Nginx UI extractor-before-decide leg.
- Sibling note: camel-docling also carried the August wave's CLI-argument-injection advisory — same component, second independent boundary in seven weeks. Component-level re-sweep pays.

### 8. Parser-hardening divergence within and across components

Three XXE legs, three divergence mechanisms:

- **camel-smooks**: applied none of the hardening the other Camel XML components have; default Woodstox reader resolves external general/parameter entities and external DTDs (CVE-2026-88901).
- **camel-xpath**: hardening lived on the component's default document type; `documentType=InputSource` fell through to a JDK-default `DocumentBuilder` — the two types disagree on parser config (CVE-2026-85250).
- **camel-fop**: relied on `FEATURE_SECURE_PROCESSING` alone; on the JDK transformer that is (accidentally) sufficient, but with a third-party JAXP factory (Saxon, present because the app also uses camel-saxon/camel-xslt-saxon) FSP does **not** restrict external access — the defense's effectiveness depends on which class `TransformerFactory.newInstance()` happens to return at runtime (CVE-2026-91858).

- **Audit rule:** enumerate the *runtime factory class*, not the intended one — `TransformerFactory.newInstance()` / `DocumentBuilderFactory.newInstance()` are SPI-dispatched over the whole classpath; the FSP shape joins JAXB's `FEATURE_SECURE_PROCESSING` inversion (Oct 12) as a canon: **FSP is per-provider limiting, not blocking.**
- **Option-differential probe:** for every component with parser/config mode switches (documentType, features, providers), run the hardened-path battery against *each* option value. The vulnerability lives in the option that takes a different code path (also the fingerprint of "sibling-option incomplete fix").

## Adjacent wave item worth the note: Apache Kylin JDBC-URL code injection

Apache Kylin 4.0–5.0.4 (fix 5.0.5) published a ten-GHSA wave (12:32Z, some detail-free) whose strongest leg is **special parameter in the configured JDBC URL → code injection** (CVE-2026-68571). This is now the fourth independent validation of JDBC-connection-URL/parameter class-loading as a standing scan class (Redshift wmmv May 14, openGauss-connector 4fmq Oct 19, Avatica tracked). Kylin's JDBC source config is a *management-plane write target* — the sibling missing-authz on jdbc source config update (CVE-2026-108766) and the SQLi (CVE-2026-108776) mean an attacker who reaches the analytics console's config API gets URL-injection material directly. Kylin's own framing ("public exposure not common") does not apply to analytics platforms reachable from internal engagement scopes. Rest of the Kylin wave tracked: unauthenticated in-house broadcast + polymorphic deserialization (CVE-2026-108771), SSRF, path confinement on backup deletion, default startup profile without security settings (CVE-2026-108833 — shipped-default-insecure-profile class), info exposure during job manipulation. Second Kylin wave (first tracked Sept 18) — the same-product re-sweep rule fires again for this product.

## Validation boundaries

- Authorized lab Camel/Kylin instances only; build the route yourself so the header-mapping and placeholder paths are observable.
- Prove placeholder expansion with owned-domain canary lookups and inert registry beans writing marker files; never enumerate real secret backends or invoke application beans.
- Prove XXE legs with owned HTTP callbacks and synthetic local files you placed; no `/etc/passwd` reads, no internal-service fetches.
- Cluster transports: own multicast group or loopback unicast config only; never join or probe a production JGroups/Hazelcast cluster.
- Report per-component with the version band (`<4.18.5` / `4.19–4.22.0` / fix 4.23.0) — the ranges are component-specific and several legs are opt-in by component presence.
