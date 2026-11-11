# Django cache, upload, and session-boundary batch

**Signal:** The **2026-05-08 22:15 UTC** advisory scan added three Django request/response boundary issues where cache policy, upload framing, and session-cookie variation can quietly cross trust boundaries.

## Advisory cluster

- **`Vary: *` cache leakage**, [GHSA-5hrc-gvxj-w55p](https://github.com/advisories/GHSA-5hrc-gvxj-w55p): Django `UpdateCacheMiddleware` in `Django >=5.2,<5.2.14` and `>=6.0,<6.0.5` could cache responses whose `Vary` header contained `*`, risking private data being stored and served.
- **ASGI upload memory-limit bypass**, [GHSA-w26r-rmm8-9c29](https://github.com/advisories/GHSA-w26r-rmm8-9c29): missing or understated `Content-Length` values could bypass Django's `FILE_UPLOAD_MAX_MEMORY_SIZE` expectation and force large in-memory uploads in affected Django releases.
- **Session cookie cache variation gap**, [GHSA-7h2m-m8vj-598h](https://github.com/advisories/GHSA-7h2m-m8vj-598h): with `SESSION_SAVE_EVERY_REQUEST=True`, responses could fail to vary on cookies when the session was not otherwise modified, letting a cached public page expose another user's session.

## Why this matters

These are cache and framing bugs, not just framework patch notes. Shared caches must never guess whether a response is private, and application upload limits are not a substitute for byte limits at the reverse proxy or ASGI server.

## Triage

1. Patch Django to **5.2.14+** or **6.0.5+** where those trains are used; unsupported series were not fully evaluated, so treat older exposed deployments as suspect.
2. Audit sites using Django's site-cache middleware, CDN caching, or reverse-proxy caching for authenticated or session-adjacent pages.
3. Put upload byte limits at the edge (`client_max_body_size`, Envoy/HAProxy body limits, ASGI server limits), not only in Django settings.
4. Review `SESSION_SAVE_EVERY_REQUEST=True` deployments and any public pages that can touch session middleware while being cacheable.
5. Hunt cache logs for authenticated responses stored with `Vary: *`, absent `Vary: Cookie`, or unexpectedly large ASGI request bodies with missing/short `Content-Length`.

## Durable controls

- Treat `Vary: *`, cookies, authorization headers, and session middleware as hard cache-deny signals unless explicitly proven safe.
- Enforce request-size limits before request bodies reach framework parsers.
- Make cache keys include every identity-bearing dimension or do not cache the response.
- Add integration tests for shared-cache behavior around anonymous-to-authenticated transitions.

## August 7 follow-up: cache grammar, signed-cookie namespaces, and domain validation

An updated Django advisory wave adds six replayable framework-boundary checks:

- [GHSA-qpc8-7fxc-cm4p / CVE-2026-35193](https://github.com/advisories/GHSA-qpc8-7fxc-cm4p): `UpdateCacheMiddleware` could store an authorization-bearing private response without adding `Authorization` to `Vary`.
- [GHSA-8cjm-8mp7-r2xf / CVE-2026-8404](https://github.com/advisories/GHSA-8cjm-8mp7-r2xf): mixed-case or uppercase `Cache-Control` directives could evade case-sensitive cache-policy matching.
- [GHSA-923m-gv2p-w5qp / CVE-2026-48587](https://github.com/advisories/GHSA-923m-gv2p-w5qp): whitespace around individual `Vary` values could make `has_vary_header()` disagree with the cache key.
- [GHSA-3h9f-r86x-qvjx / CVE-2026-48588](https://github.com/advisories/GHSA-3h9f-r86x-qvjx): `UpdateCacheMiddleware` and `cache_page()` could cache cookie-varying responses when a request carried unrelated cookies.
- [GHSA-h7pc-vwp9-298g / CVE-2026-6873](https://github.com/advisories/GHSA-h7pc-vwp9-298g): `HttpRequest.get_signed_cookie()` concatenated cookie name and caller salt into a non-injective namespace, so distinct `(name, salt)` tuples could select the same signing-key namespace.
- [GHSA-8qcx-xf44-272x / CVE-2026-53878](https://github.com/advisories/GHSA-8qcx-xf44-272x): `DomainNameValidator` accepted newline-bearing values. Django's own `HttpResponse` rejects newlines, so header injection requires a separate application or downstream serialization sink.

The affected supported trains are Django before 5.2.15/6.0.6 for the June cache and signed-cookie records, and before 5.2.16/6.0.7 for the July cookie-cache and domain-validator records. Unsupported series were not fully evaluated. Use exact package and commit provenance rather than assuming all older branches behave identically.

### Shared-cache decision matrix

1. Stand up an affected and corrected Django build behind a disposable shared cache. Seed only two synthetic users and one anonymous client; every response body should contain a random principal marker, never real account data.
2. Exercise the same harmless route with no credentials, `Authorization`, a session cookie, an unrelated cookie, and both cookie classes together. Record request identity inputs, response `Cache-Control`/`Vary`, normalized cache key, hit/miss state, stored marker, and returned marker.
3. Repeat each response policy using lower-, upper-, and mixed-case directives. Test `Vary` tokens with normal spacing, leading/trailing whitespace, duplicate fields, and multiple header lines. Preserve raw headers as well as the cache's parsed representation.
4. Use a barrier-controlled two-request proof: the authorized synthetic user warms the cache, then the anonymous client requests the same URL. Reverse the order and repeat with a second user. A bounded positive is a marker crossing principals through a deterministic shared-cache hit.
5. Test framework middleware alone and the deployed CDN/reverse proxy separately. Do not report a data-disclosure path unless the actual cache topology stores and replays the response; helper output or a malformed header by itself is not enough.

### Signed-cookie namespace collision matrix

1. Inventory every application call to `get_signed_cookie(name, salt=...)`, including wrappers. Record the cookie's purpose, tuple `(name, salt)`, serializer, maximum age, and authorization decision reached after verification.
2. Generate pairs whose concatenations are equal but tuple boundaries differ, for example conceptual pairs shaped like `("ab", "c")` and `("a", "bc")`. Use random disposable values and let the affected application produce all signatures; do not obtain or expose `SECRET_KEY`.
3. Sign a marker in the lower-authority context, present it under the colliding higher-authority name/salt tuple, and patch the final session, role, or workflow sink to record then deny. Compare a non-colliding pair and the corrected build.
4. The positive boundary is **valid low-context signed value -> colliding `(name, salt)` namespace -> higher-context verifier acceptance**. Acceptance is not automatically account takeover; preserve the downstream purpose and denied authorization sink before assigning impact.

### Validator-to-header sink check

Trace newline-bearing domain values from the exact non-form input path through `DomainNameValidator` to the final consumer. Patch header serializers, redirect builders, email grammar, proxy configuration, and outbound-request constructors to record the raw and normalized value before denying side effects. `CharField` and Django `HttpResponse` are important negative controls because they strip or reject newlines. Report header injection only when an application-specific serializer emits a second synthetic header; validator acceptance alone is a validation mismatch.

Keep cache proofs to isolated caches and fake principals. Never prime shared production caches, retrieve another user's response, forge operational cookies, or send newline canaries to a real downstream service.
