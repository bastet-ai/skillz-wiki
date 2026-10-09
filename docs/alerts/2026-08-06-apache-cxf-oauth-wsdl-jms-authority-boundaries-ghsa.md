---
title: Apache CXF OAuth, WSDL-import, and JMS authority boundaries
---

# Apache CXF OAuth, WSDL-import, and JMS authority boundaries

Nine Apache CXF records published on August 6 expose three reusable testing themes: signed or encrypted protocol objects outlive the authorization decision they were meant to represent, protections on a top-level document disappear at an import boundary, and a message transport turns broker write access into Java object-reconstruction authority.

Source records:

- self-issued OIDC token claim validation: [GHSA-9rwm-8rh4-8q53 / CVE-2026-65583](https://github.com/advisories/GHSA-9rwm-8rh4-8q53) and the [Apache announcement](https://lists.apache.org/thread/fzj8yzgfl53gclxrcdrnrx3grcpkq51j);
- repeated redemption in `DefaultEncryptingCodeDataProvider`: [GHSA-7mxw-qv85-693m / CVE-2026-68079](https://github.com/advisories/GHSA-7mxw-qv85-693m) and the [Apache announcement](https://lists.apache.org/thread/6m06gdqz4rxhy9g90qz9lyqx2gqmf13o);
- dynamic client registration scope self-assignment: [GHSA-pwwh-3685-58r7 / CVE-2026-61466](https://github.com/advisories/GHSA-pwwh-3685-58r7) and the [Apache announcement](https://lists.apache.org/thread/2l1r16g79tpxd7fzrzr2q9oscwrjgljs);
- revoked encrypted token acceptance and active introspection: [GHSA-5c8v-93q6-cjxj / CVE-2026-68481](https://github.com/advisories/GHSA-5c8v-93q6-cjxj) and the [Apache announcement](https://lists.apache.org/thread/88c0h10yjb2b8201o1km3st71fs2zw2b);
- signed request-object claim overwrite in `JwtRequestCodeFilter`: [GHSA-7hjx-472h-3f7q / CVE-2026-63687](https://github.com/advisories/GHSA-7hjx-472h-3f7q) and the [Apache announcement](https://lists.apache.org/thread/drcq4chmt0btx86f17o47j17r378hzpw);
- concurrent authorization-code redemption in `JCacheCodeDataProvider`: [GHSA-4qr2-3mpc-grqm / CVE-2026-57818](https://github.com/advisories/GHSA-4qr2-3mpc-grqm) and the [Apache announcement](https://lists.apache.org/thread/7q08mz8bcbosp25wok7gr537zlp15mfz);
- XXE through imported WSDL/XSD documents: [GHSA-jvhw-7q2c-2r65 / CVE-2026-65432](https://github.com/advisories/GHSA-jvhw-7q2c-2r65) and the [Apache announcement](https://lists.apache.org/thread/5qs207krzg51jl3zs3cvnl5lt9njp8c3);
- omitted OIDC Hybrid Flow `c_hash` validation: [GHSA-h8f8-97w2-2925 / CVE-2026-57817](https://github.com/advisories/GHSA-h8f8-97w2-2925) and the [Apache announcement](https://lists.apache.org/thread/pj63c3pf7kkp1xhr53do704fwj3t3htn); and
- native deserialization of inbound JMS `ObjectMessage` bodies: [GHSA-gvw8-rcrx-9fxx / CVE-2026-66909](https://github.com/advisories/GHSA-gvw8-rcrx-9fxx) and the [Apache announcement](https://lists.apache.org/thread/lr5d4tg6tf7j29jmw8wt242oowonjqpx).

The GitHub entries were unreviewed mirrors when this page was written. Apache's records recommend CXF 4.2.3, 4.1.8, or 3.6.12. Confirm the deployed provider, flow, transport, and exact version before testing: several paths are optional and the self-issued-token validator is not enabled by default.

!!! warning "Disposable issuers, brokers, and denied sinks only"
    Use throwaway OAuth clients, synthetic identities, fake tokens, an owned XML callback, a disposable JMS broker, patched token/XML/object sinks, and inert marker objects. Never replay real authorization codes or tokens, register privileged clients in a shared identity service, read host files through XML entities, enqueue serialized gadgets, or target an operational broker.

## 1. Build a protocol-object authority map

Record each object from creation to final use:

```text
caller and client identity
  -> outer HTTP/JMS/XML input
  -> signature, encryption, cache, or parser decision
  -> claims / fields copied into internal state
  -> one-time, revocation, scope, or import policy
  -> principal, token, resource fetch, or deserializer selected
  -> patched final sink
```

Do not treat cryptographic validity as current authorization. A correctly signed request object can still overwrite stronger outer-request state; decryptable tokens can be revoked; an authorization code can be valid but already consumed; and a trusted top-level WSDL can import an untrusted parser context.

## 2. Diff outer OAuth parameters from signed request-object claims

The `JwtRequestCodeFilter` record requires a client capable of producing a validly signed request JWT. Use a disposable confidential client and fake secret. Send matching controls first, then vary only one duplicated field between the outer request and signed object:

| Field | Outer request | Signed request object | Capture |
| --- | --- | --- | --- |
| `code_challenge` | marker A | marker B | value bound to the issued code |
| `code_challenge_method` | expected method | alternate method | verifier branch selected |
| `nonce` | marker A | marker B | value returned and later validated |
| `state` | marker A | marker B | server-side state correlation |

Place recorders immediately before parameter-map merge, code issuance, and token exchange. Do not complete a real login. A bounded positive is **valid client request JWT -> security-sensitive inner claim replaces the already-established outer value -> patched code/token sink records the replacement**.

Test claim precedence rather than assuming every duplicate is exploitable. Preserve negative controls for an invalid signature, wrong client, unknown key, omitted inner claim, and fixed build.

## 3. Test authorization-code single use in serial and concurrent modes

Use synthetic codes that can mint only a token carrying a harmless canary scope. Exercise the providers separately:

1. redeem once, then replay serially against `DefaultEncryptingCodeDataProvider`;
2. redeem once, revoke or remove, then introspect provider state;
3. send two synchronized redemption requests against `JCacheCodeDataProvider`;
4. repeat with enough synchronization to reach the same cache entry, but keep request volume low; and
5. run the same fixtures against a fixed build.

Patch token issuance to return distinct random marker IDs without creating usable bearer tokens. Capture:

```text
code hash
-> provider/cache lookup
-> consume/remove decision
-> atomicity or lock boundary
-> token-issuance recorder
```

Supported findings differ:

- two serial recorder hits prove a missing consume/remove transition;
- two concurrent hits with one serial success prove a race in one-time use;
- a second HTTP success without a second issuance hit may be response replay or error handling, not duplicate token issuance.

Never race a shared identity deployment or retain reusable token material.

## 4. Verify revocation at use and introspection sinks

For `DefaultEncryptingOAuthDataProvider`, create fake encrypted access and refresh tokens in a disposable provider. Compare active, revoked, expired, malformed, and wrong-key controls. After revocation, send the same marker to both the resource-token validator and `TokenIntrospectionService`.

Record decryption separately from authorization:

```text
encrypted marker decrypts
-> token identifier and type recovered
-> revocation state loaded
-> expiry/audience/scope checks
-> introspection active decision
-> patched resource principal
```

A bounded positive is **revoked marker still decrypts -> revocation state is not enforced -> introspection reports `active:true` or a patched protected-resource sink receives the synthetic principal**. Successful decryption alone is not a bypass; prove the later active/use decision.

## 5. Test client-registration scope authority

Dynamic client registration is relevant only when the endpoint is enabled and the caller can reach it. Configure a disposable authorization server with:

- one public canary scope;
- one synthetic elevated scope that reaches only a no-op recorder; and
- an explicit registration-time allowlist that excludes the elevated scope.

Submit registration requests with the public scope, elevated scope, mixed scopes, unknown scope, duplicates, and omitted scope. Record raw metadata, normalized scope set, AS allowlist decision, persisted client metadata, and the scopes accepted during a later patched grant.

The strong proof is **registration accepts an excluded synthetic scope -> persists it on the new client -> a later authorization decision treats it as client authority**. Stored text without grant-time effect is a metadata-validation finding, not privilege escalation. Do not request real administrative or user-data scopes.

## 6. Validate self-issued ID tokens and Hybrid Flow code binding

Keep two separate harnesses because these records have different preconditions.

### Self-issued tokens

Enable self-issued ID-token support explicitly in a disposable relying party. Generate throwaway keys and vary issuer, subject, audience, time claims, and `sub_jwk` binding one at a time. The final sink should record only whether a synthetic principal would be established.

A valid signature with omitted or mismatched required claims must not authenticate. Report the exact omitted check; do not generalize this to default CXF configurations where self-issued tokens are not accepted.

### Hybrid Flow `c_hash`

Use an owned mock IdP and synthetic authorization codes. Compare:

- correct `c_hash`;
- incorrect `c_hash`;
- omitted `c_hash`;
- code from a second synthetic flow; and
- non-Hybrid Flow controls.

Capture ID-token validation, code binding, token exchange selection, and the patched session sink. The Apache record requires a non-compliant or misconfigured IdP that omits `c_hash`; establish that precondition. A missing claim that produces an error is not vulnerable, and code substitution is not proven until the mismatched code reaches the exchange or session decision.

## 7. Trace WSDL hardening across imports

Serve a top-level WSDL and imported WSDL/XSD from owned local fixtures. The top-level document should be harmless. Put an inert external-entity URL in an imported document and direct it only to an owned no-content callback recorder.

Test:

1. top-level DTD/entity as a negative control;
2. one imported WSDL containing the canary entity;
3. one imported XSD containing the canary entity;
4. nested imports;
5. same-origin and cross-origin owned imports; and
6. affected and fixed builds.

Instrument resolver and parser creation:

```text
top-level URL
-> StaxUtils feature flags
-> wsdl:import / xsd:import resolution
-> WSDL4J parser feature flags
-> external-entity resolver
-> denied callback recorder
```

A bounded positive is **top-level parser rejects the DTD control while an imported document reaches the owned denied entity resolver under weaker settings**. Do not use `file:` entities, cloud metadata, loopback services, or internal network targets. Callback reachability proves external-entity resolution, not local-file disclosure.

## 8. Treat JMS destination write access as a deserialization boundary

The JMS issue requires the ability to place a message on the service's destination. In a disposable broker, map producer identity, destination ACL, CXF consumer, classpath, and message-type handling. Replace native deserialization with a recorder or JVM serialization filter that logs the root class and rejects before object construction side effects.

Send only inert fixtures:

- ordinary `TextMessage` and `BytesMessage` controls;
- an `ObjectMessage` containing a serializable marker class with no callbacks;
- an unexpected but harmless JDK value class;
- a malformed serialization stream; and
- affected and fixed/default-disabled configurations.

Capture broker authentication, destination, JMS type, consumer dispatch, `ObjectMessage.getObject()` or equivalent entry, class-resolution request, and rejection. A bounded positive is **authorized or otherwise reachable producer -> CXF consumes `ObjectMessage` -> unrestricted native class resolution begins before a type policy decision**.

Do not enqueue gadget chains or claim RCE from native deserialization alone. RCE additionally requires a suitable reachable gadget classpath and execution sink; keep that as an untested precondition.

## Evidence bundle

```text
CXF version and exact provider/transport:
Optional feature configuration:
Synthetic client, issuer, broker, or XML fixture:
Raw outer object and nested/imported object hashes:
Signature/encryption/parser/cache decision trace:
One-time, revocation, scope, or binding decision:
Patched final sink result:
Affected-build result:
Fixed-build result:
Supported claim:
Explicitly excluded stronger claims:
```

The durable operator lesson is to follow protocol objects past their first successful validation. Preserve evidence for the final authority decision: code consumption, token activity, scope grant, principal creation, import parser, or object reconstruction.

## August 20 follow-up: JNDI config injection, OAuth2 token-claim validation, and inverted IP binding

Nine records updated 2026-08-20 on the same Apache CXF code path extend two themes from the August 6 page: a JMS configuration or JCA deployment surface that accepts operator-supplied strings all the way to a JNDI lookup, and an OAuth2 access-token validator that stops short of the claims that actually prove which resource server the token was minted for. Apache's recommended versions are `4.2.2` or `4.1.7` for every record below.

Source records:

- JNDI injection in `JMSConfigFactory` (incomplete fix for [CVE-2026-44417](https://nvd.nist.gov/vuln/detail/CVE-2026-44417)): [GHSA-93g8-qqv3-mrx8 / CVE-2026-50632](https://github.com/advisories/GHSA-93g8-qqv3-mrx8);
- JNDI injection in `DispatchMDBMessageListenerImpl` via the JCA `ra.xml` deployment descriptor or runtime activation parameters: [GHSA-qp3f-rvj8-46c8 / CVE-2026-50633](https://github.com/advisories/GHSA-qp3f-rvj8-46c8);
- missing `aud` and `iss` validation in `JwtAccessTokenValidator`: [GHSA-9mrv-8pvf-hf4m / CVE-2026-50627](https://github.com/advisories/GHSA-9mrv-8pvf-hf4m);
- inverted IP-binding check in `OAuthRequestFilter` that rejects bound-source traffic and accepts anything else: [GHSA-g5v7-jchf-7jrr / CVE-2026-50628](https://github.com/advisories/GHSA-g5v7-jchf-7jrr);
- refresh-token replay race when `recycleRefreshTokens=false`: [GHSA-83r6-96m8-r52p / CVE-2026-50631](https://github.com/advisories/GHSA-83r6-96m8-r52p);
- log injection via unsanitized `clientId`: [GHSA-f8p7-h97q-7vx7 / CVE-2026-50629](https://github.com/advisories/GHSA-f8p7-h97q-7vx7);
- CRLF injection in the `WWW-Authenticate` `realm` value (`AuthorizationUtils`): [GHSA-xf62-wr5p-5p95 / CVE-2026-50630](https://github.com/advisories/GHSA-xf62-wr5p-5p95); and
- missing `throw` in the `TokenIntrospectionService` security-context check: [GHSA-542g-m3fx-q86f / CVE-2026-50623](https://github.com/advisories/GHSA-542g-m3fx-q86f).

### 9. JNDI config injection: bind the final lookup sink

The two JNDI records differ on where untrusted input originates but share the same shape: an operator-controlled string (JMS factory URL, JCA activation property) crosses from configuration into a JNDI `InitialContext.lookup`. The August 6 JMS `ObjectMessage` record covered the message-body side; these cover the configuration and activation-parameter side.

In a lab:

1. Stand up CXF on a disposable host with a patched `JndiTemplate` recorder that logs the requested resource name and rejects before any `Reference` resolution or classload.
2. For `JMSConfigFactory`, drive the affected configuration route with two fixtures: a benign `file:` URL and an owned no-content LDAP/JRMP endpoint. Do not point at internal or production JNDI services.
3. For `DispatchMDBMessageListenerImpl`, place two synthetic `ra.xml` files in the JCA deploy directory: one with a benign activation property and one that routes the activation property through the owned callback recorder. Deploy both and confirm which one the recorder observed.
4. Record: exact CXF version, configuration or activation-parameter key, raw value, the patched-lookup result, and whether the class resolution path was entered before the policy decision.
5. Compare against `4.2.2` / `4.1.7` where the recorder is never reached.

A bounded positive is **operator-supplied JMS factory URL / JCA activation property -> JNDI `lookup` begins before a resource-name allowlist** and the recorder proves the outbound lookup target. Do not claim RCE from the lookup alone; RCE requires a resolvable reference on the target host and a reachable gadget classpath, which is a separate untested precondition.

### 10. OAuth2 token confusion: `aud` and `iss` pin the intended resource server

`JwtAccessTokenValidator` validates signature and `exp` but not `aud` or `iss`. The operator consequence is a cross-resource-server replay: a token minted for `resource-server-A` is accepted by `resource-server-B` if both use the same signing key (the common `single IdP / multiple protected APIs` deployment). This is distinct from the August 6 self-issued-token record, which concerns claims on a token the resource server minted itself.

Replayable validation:

- Two disposable resource servers in the same lab, both using the same lab IdP signing key and the same `aud` claim format.
- Mint a synthetic access token addressed to `resource-server-A` with a canary scope that reaches only `resource-server-A`'s recorder.
- Present that token to `resource-server-B` through a patched principal sink that records only whether the caller's principal would be established.
- Decision table: correct `aud`/`iss`, missing `aud`, missing `iss`, `aud` for the other server, `aud` with an extra audience, `iss` mismatch, and the same-token-same-server control.
- Positive evidence: `resource-server-B`'s principal sink records a synthetic principal established from a token whose `aud` was minted for `resource-server-A`, on an affected build only.

Do not use real IdP material, real user principals, or cross-tenant tokens. The proof is the two-server differential plus the patched principal decision, not the signature being valid.

### 11. Inverted IP binding: the allowlist rejects what it should accept

`OAuthRequestFilter`'s IP-binding check is inverted: legitimate clients from the bound address are rejected, and any other source IP is accepted. This is a logic-inversion finding, not a bypass: the intended security control is off by one comparison. Test it by standing up a lab CXF OAuth endpoint with a bound source IP and three clients (bound, same-subnet, remote) and recording which of the three the filter accepts and which it rejects. Positive evidence is **bound-source client rejected, non-bound-source client accepted**, on the affected build only. No outbound traffic beyond the lab is needed.

### 12. Refresh-token replay when `recycleRefreshTokens=false`

`AbstractOAuthDataProvider`'s refresh-token path is not atomic when `recycleRefreshTokens=false`. Send N synchronized refresh requests for the same synthetic refresh token to a patched token-issuance recorder and count how many distinct access tokens the recorder records. Positive evidence is **N > 1 distinct access tokens from one refresh token** on the affected build, with `N = 1` on the fixed build. Use low request volume (a dozen at most), synthetic refresh tokens only, and no shared production identity.

### 13. Log injection, CRLF in `realm`, and the introspection-auth `throw` gap

Three remaining records are each a single-token sanitization or control-flow gap. Treat them as report findings, not as standalone exploit chains:

- **`clientId` log injection**: send a synthetic `clientId` containing CRLF plus a fake log prefix through the OAuth authorization or token endpoint. The recorder should capture the log line and confirm the fake entry landed. Do not use this to plant content that would be read by a log-based auth flow; that is a separate, untested impact.
- **CRLF in the `WWW-Authenticate` `realm` value**: send a synthetic `realm` containing CRLF through the OAuth2 token endpoint when authentication fails. The recorder should capture the full response and confirm the injected header or body. The bounded positive is **header split**, not cache poisoning.
- **Missing `throw` in the introspection check**: on an affected build, hit `/services/oauth2/introspect` unauthenticated and record whether the `active` field reflects a real token lookup. The record explicitly notes this is a safeguard that matters only when the service itself was misconfigured to omit auth; report it as the missing control-flow branch, not as an independent bypass.

For all three: no shared production OAuth deployment, synthetic clients and tokens only, and the fixed-build negative control is required evidence.

## Reviewed but not promoted in this follow-up

The remaining CXF-adjacent records updated in this window (`Apache CXF` OAuth2 signature-trust, WS-JSON first-signature metadata, and the `TokenIntrospectionService` duplicate-range entries) are variations on the same code paths already covered above or are availability-only parser issues without a stronger reusable boundary. No new CXF page is warranted.

## October 9 12:3xZ follow-up: coordinated CXF wave — validation-cache poisoning, signature coverage gaps, and silent security controls (fixed 4.2.4 / 4.1.9 / 3.6.13)

Eleven Apache CXF records published 2026-10-09 (all fixed in 4.2.4, 4.1.9, or 3.6.13). This is the third CXF wave on this page (Aug 6, Aug 20, Oct 9) — the same-product re-sweep rule keeps paying: when a framework gets a coordinated review, re-read the *whole* validator/cache/transport surface, not just the headline CVE. Promotable legs:

- **STS token validation cache keyed by `Arrays.hashCode()` — non-cryptographic cache key = auth bypass** ([GHSA-hw52-jg43-v867 / CVE-2026-97468](https://github.com/advisories/GHSA-hw52-jg43-v867)): `STSTokenValidator`/STS cached *validated* security tokens under a 32-bit `hashCode()` of the token and treated a cache hit as proof of prior validation. Craft a UsernameToken or self-signed SAML assertion that collides with a cached legitimate token → accepted **without password validation, signature trust verification, or any STS call**, and through token renewal obtain STS-signed tokens for the victim identity. This is the validation-cache branch of this page's authority-map theme: the cache shortcut skips the entire decision, not one step of it. Sweep rule: for any "already validated" cache anywhere, ask what the key is — if the key is derived from attacker-writable content and isn't collision-resistant (32-bit hash, string prefix, length+first-bytes), a collision *is* an auth bypass. Java `String.hashCode`/`Arrays.hashCode` used as a security-relevant key is a grep-able fingerprint (`grep -rn "hashCode()" | grep -i cache`). Proof shape: synthetic token, own mock STS, collide against your own cached canary; never replay live tokens.
- **SAML trust result shared across requests — cross-request state contamination** ([GHSA-2rg8-47cf-hp2j / CVE-2026-97791](https://github.com/advisories/GHSA-2rg8-47cf-hp2j)): `STSTokenValidator` stored "was this assertion signed by a trusted cert?" in **one object shared by all requests**, so a forged assertion signed by an untrusted cert could read a legitimate in-flight request's `true` result and be accepted without reaching the STS (affected: `alwaysValidateToSts` unset). Per-request security decisions held in shared/instance state are raceable trust carriers — pair with the Oct 2 Airflow `SyncCallback` self-allow-list and the Aug 27 Camel header wave in the same contamination family. Probe: concurrent legitimate + forged pairs against a lab validator, vary timing; positive is forged acceptance correlated with in-flight legit traffic.
- **XML Signature coverage gap: unsigned wrapper presents inner signed doc as signed** ([GHSA-m89p-3qw6-fh4r / CVE-2026-100227](https://github.com/advisories/GHSA-m89p-3qw6-fh4r)): the JAX-RS XML Signature interceptors (`XmlSigInHandler`, `XmlSigInInterceptor`, streaming `XmlSecInInterceptor`) never ensured the XML *passed to the application* was the XML *covered by the signature* — wrap any document signed by a trusted key in unsigned content and the app treats the wrapper content as signed. Classic XML Signature Wrapping; the operator note is to test at the **application-visible document**, not at signature-validity: sign a canary, deliver it wrapped, check what the resource sees.
- **Netty HTTP client transport skips hostname verification even with `disableCNCheck=false`** ([GHSA-vr34-m3cj-mgxg / CVE-2026-107938](https://github.com/advisories/GHSA-vr34-m3cj-mgxg)): chain validated against trust store, endpoint identity never checked, HTTP/1.1 and HTTP/2 alike — any publicly-issued cert for an attacker domain impersonates the target service and captures credentials. The config-name-vs-implementation-leg of the Sept 15 parser page and the Oct 2 cert pages: `disableCNCheck=false` reads as "check enabled" but the Netty transport never wired the check at all. Service discovery for CXF SOAP/REST clients on captured networks: transport-artifact fingerprint (`cxf-rt-transports-http-netty-client` jar in the classpath/WSDL binding) tells you which transport is silently unprotected. Lab proof = own MITM listener with own public-domain cert; never intercept live traffic.
- **Authorization-code single-use race in the JPA provider — second concurrent-redemption leg** ([GHSA-4856-vwpx-pmq8 / CVE-2026-73179](https://github.com/advisories/GHSA-4856-vwpx-pmq8)): the Aug 6 page covered the JCache provider's find-then-delete race; the JPA code grant provider has the same non-atomic find-then-delete under `READ_COMMITTED` isolation → multiple access tokens from one code via synchronized exchanges. Provider-parity rule extended: an OAuth2 provider abstraction with multiple backends (JCache, JPA, encrypting, custom) needs the single-use fixture run against **each** backend; the framework fixing one provider does not fix the family. Reuse the Aug 6 §3 harness (patched issuance recorder, N synchronized redemptions, distinct-token count) per provider.
- **OIDC RP `state` parameter becomes an unvalidated redirect target after auth** ([GHSA-75qj-7h27-jm2v / CVE-2026-79650](https://github.com/advisories/GHSA-75qj-7h27-jm2v)): attacker-controlled `state` is preserved and later used as a post-authentication redirect target without origin validation; directly-encoded *and double-encoded* URLs take different validation paths (one catches, one doesn't). Post-auth redirect sinks leak the code/token-bearing URL to the attacker origin — the decode-branch-parity probe belongs on every OAuth RP: test plain, single-encoded, and double-encoded external URLs through the same state/redirect handling. Owned-redirector canary only.
- **`max_age` step-up enforcement silently dead: unit mismatch + inverted comparison** ([GHSA-8ph5-3q2c-4cc7 / CVE-2026-71575](https://github.com/advisories/GHSA-8ph5-3q2c-4cc7)): `OidcClientCodeRequestFilter`'s auth-freshness check compared milliseconds to seconds *and* had inverted polarity, so RPs calling `setMaxAgeOffset` to force re-authentication accepted sessions of any age. Two-step-authentication *config* that never functioned is the strongest variant of the config-silent-failure theme (Sept 21 precedence page): probe step-up by authenticating once, waiting past `max_age` in a lab, replaying the session, and checking whether the IdP re-prompt is enforced — absence of re-prompt with `max_age` set in config is the finding, and it's invisible to any audit that reads config instead of behavior.
- **DEFLATE bomb before trust: `CompressionUtils.inflate()` uncapped** ([GHSA-m259-q69p-995q / CVE-2026-78384](https://github.com/advisories/GHSA-m259-q69p-995q)): ~KB JWE (`zip=DEF`, e.g. `JoseSessionTokenProvider` RSA-OAEP) or SAML redirect/POST binding token expands to GBs on heap — decompression happens **before/independent of** signature/decryption validation. "Parse-before-verify is the DoS window" generalizes to any compressed security token: fuzz compression ratios at JWS/JWE/SAML endpoints with a tiny budget; the fix adds a 10 MiB default cap (`org.apache.cxf.compression-max-inflated-size`) — cap-system-property names are the fingerprint of the pre-verify decode path.

Tracked without publication (known classes): MTOM folded-header DoS (limits applied per physical line / per distinct header name — header-budget accounting, sibling of the Sept 15 parser page), `StaxUtils` unbounded element/character defaults (XML resource-exhaustion class), FIQL parser CPU loop (backtracking-CPU class), Dell SCG Policy Manager twelve-GHSA wave (detail-free boilerplate; fold-when-route-detail-lands watch continues — second SCG wave this week), OpenStack Mistral policy-free `/v2/maintenance` token-role-blind state change (already covered on the Oct 8 Mistral page), gvproxy host-file deletion (promoted on the May 19 Podman page), Bouncy Castle LTS native CTR counter-wrap (folded on the July 1 CTR page), sequoia-openpgp key-flag inference (folded on the Oct 2 BC field-identity page), gnutls 3.8.13 info-disclosure re-listing, and the ~50-item WordPress wave (Traveler/Ajax Search Pro/JNews/tagDiv/WPLMS blind SQLi, Zombify unauth webshell upload, GiveWP/Forminator identity spoofing, Vipps object injection, CF7 PDF pairs — standard plugin authz/XSS/SQLi singles, class-covered Sept 19).

## References (October 9 wave)

- Advisory family: <https://github.com/advisories?query=Apache+CXF+published%3A2026-10-09>
- Key records: <https://github.com/advisories/GHSA-hw52-jg43-v867>, <https://github.com/advisories/GHSA-2rg8-47cf-hp2j>, <https://github.com/advisories/GHSA-m89p-3qw6-fh4r>, <https://github.com/advisories/GHSA-vr34-m3cj-mgxg>, <https://github.com/advisories/GHSA-4856-vwpx-pmq8>, <https://github.com/advisories/GHSA-75qj-7h27-jm2v>, <https://github.com/advisories/GHSA-8ph5-3q2c-4cc7>, <https://github.com/advisories/GHSA-m259-q69p-995q>