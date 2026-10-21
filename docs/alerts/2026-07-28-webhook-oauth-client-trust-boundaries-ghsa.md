---
title: Webhook and OAuth client trust boundaries from July 28 advisory updates
---

# Webhook and OAuth client trust boundaries from July 28 advisory updates

Four July 28 advisory records yield one reusable operator theme: security state is attached to a default route, origin, or random-looking value, but the application later accepts an alternate route, redirected origin, or predictable value without carrying the original trust decision forward.

Sources:

- [GHSA-3fcr-jvgp-7f58: pytonapi custom webhook paths skip bearer validation](https://github.com/nessshon/tonapi/security/advisories/GHSA-3fcr-jvgp-7f58)
- [pytonapi custom-path fix](https://github.com/nessshon/tonapi/commit/854222b7ee68d3fb7b4d6d899d200f388483bd86)
- [GHSA-pp92-crg2-gfv9: Ruby OAuth2 client retains bearer auth across a protocol-relative redirect](https://github.com/ruby-oauth/oauth2/security/advisories/GHSA-pp92-crg2-gfv9)
- [Ruby OAuth2 redirect fix](https://github.com/ruby-oauth/oauth2/commit/0f0a474f1b38453e119e660c2daca742d4378ce9)
- [GHSA-prq8-7wvh-44qh: Ruby OAuth 1 token requests follow cross-origin redirects](https://github.com/ruby-oauth/oauth/security/advisories/GHSA-prq8-7wvh-44qh)
- [Ruby OAuth 1 cross-origin redirect fix](https://github.com/ruby-oauth/oauth/commit/d069dc8c4c9631947451215f07460d6cdf0caf3f)
- [CVE-2026-16615: librest PKCE verifier generation uses a non-cryptographic PRNG](https://nvd.nist.gov/vuln/detail/CVE-2026-16615)
- [GNOME librest issue 25](https://gitlab.gnome.org/GNOME/librest/-/issues/25)

The reviewed ranges are pytonapi `>=2.0.0,<2.2.1`, Ruby `oauth2` `>=0.4.0,<=2.0.21`, and Ruby `oauth` `>=0.5.5,<=1.1.5`; fixed controls are 2.2.1, 2.0.22, and 1.1.6 respectively. The librest record is sparse and does not provide a package range in GitHub's entry, so identify the exact distribution build and source patch instead of inferring exposure from a product name alone.

!!! warning "Authorized validation only"
    Use local dispatchers, fake webhook events, two owned loopback HTTP listeners, synthetic OAuth credentials, and deterministic test-only PRNG seeds. Never forge a payment or blockchain event against a live handler, collect a real bearer token or OAuth signature, redirect a production integration, target metadata/internal services, or attempt to predict a real PKCE verifier.

## Boundary matrix

| Surface | Trusted decision that gets lost | Controlled proof |
| --- | --- | --- |
| pytonapi custom webhook route | expected bearer token is stored under the default suffix, not the handler's custom path | no-auth and wrong-auth calls increment only a local canary handler on the custom path |
| Ruby OAuth2 resource request | a `Location: //host/path` changes authority while the original bearer header survives | a fake bearer reaches the second owned listener only on the affected build |
| Ruby OAuth 1 token request | a token endpoint redirect mutates the consumer site and causes a newly signed request to another origin | the second owned listener records only fake OAuth parameter names and a request counter |
| librest PKCE | `code_verifier` looks random but is derived from GLib `GRand` state | controlled seeds reproduce synthetic verifier output; a fixed build does not use the deterministic non-CSPRNG path |

## pytonapi: compare default and custom webhook routes

The affected dispatcher registers a handler's custom `path=` in its route map but stores the webhook token under the event type's default suffix. Its request processor retrieves the expected token by the incoming path and checks authentication only when that lookup is non-null. The missing custom-path entry therefore becomes **authentication not required**, rather than a configuration error.

Use the library directly with a fake webhook client; network exposure is unnecessary:

1. Register one account-event handler at the default path and one equivalent handler at a custom path. Each handler should increment a different in-memory counter and accept only a synthetic event marker.
2. Run dispatcher setup with a fake client that returns a known test token. Record the route map and token-map keys, but do not log any real token.
3. For each path, call the processor with no authorization, a wrong test token, and the valid test token. Reset counters between rows.
4. Affected behavior is: default/no-auth rejects, default/wrong rejects, default/valid increments, while custom/no-auth and custom/wrong also increment.
5. Repeat on 2.2.1. Every routed custom path should have an expected token; missing or wrong auth should reject before payload parsing or handler invocation.

Evidence table:

| Route | Authorization | Affected result | Fixed result |
| --- | --- | --- | --- |
| default | absent | reject | reject |
| default | valid synthetic token | handler counter +1 | handler counter +1 |
| custom | absent | **handler counter +1** | reject |
| custom | wrong synthetic token | **handler counter +1** | reject |
| custom | valid synthetic token | handler counter +1 | handler counter +1 |

Report the exact downstream handler effect separately. A callback invocation proves webhook-event forgery, not financial loss or account takeover; use a no-op counter and explain what production logic would be reachable without exercising it.

## Ruby OAuth2: preserve origin and credential decisions across redirects

The affected `OAuth2::Client#request` merges a raw redirect location into the prior URL. A network-path reference such as `//second.test/canary` replaces the authority under URI reference resolution. The recursive request then reuses the options dictionary containing the original `Authorization` header.

Build a two-listener fixture:

1. Bind two owned loopback listeners on different ports. Listener A is the configured resource server; listener B only records request path, method, and whether the exact fake bearer marker is present.
2. Point an `OAuth2::AccessToken` containing a synthetic token at A. Establish a 200 baseline and verify B receives nothing.
3. Make A return `302 Location: /same-origin`. Confirm the normal same-origin redirect remains on A.
4. Make A return `302 Location: //127.0.0.1:<B-port>/canary`. Record the resolved authority and whether B receives the fake authorization marker.
5. Add absolute cross-origin and scheme-relative controls, plus 303 and 307 only when the request body is inert. Never substitute a private or metadata address.
6. Repeat on 2.0.22. A cross-origin redirect must not deliver the fake bearer to B; preserve evidence of whether the client rejects, stays on the original authority, or strips credentials.

A bounded positive result is **one redirect response from owned listener A causes a request to owned listener B carrying the exact synthetic bearer header**. Do not describe this as an IdP compromise unless a separately proven application path lets an attacker influence the upstream redirect.

## Ruby OAuth 1: token endpoints are not general redirectors

The affected `OAuth::Consumer#token_request` follows `300..399`, can replace the configured site when the host changes but path matches, and recursively signs the next token request. This is not the same as OAuth2 bearer replay: the redirected request contains a new OAuth 1 signature bound to method, URL, nonce, timestamp, and parameters.

Reuse the two-listener lab with fake consumer credentials:

1. Configure listener A as the token endpoint and listener B as the candidate redirected origin.
2. Log only request method/path, OAuth parameter **names**, and a random run ID. All keys, secrets, nonces, timestamps, and signatures must be synthetic and discarded after the test.
3. Return a same-origin relative redirect from A and record the compatible baseline.
4. Return an absolute redirect to B with the same token path. Confirm whether the affected client contacts B and whether the request carries OAuth parameter names indicating that it was re-signed.
5. Add a different-path control and a short redirect loop to characterize path handling and redirect limits without creating load.
6. Repeat on 1.1.6. Cross-origin token redirects should reject by default; test the explicit compatibility opt-in only if the integration genuinely requires it.

Report **cross-origin signed-request dispatch** and the exact precondition that controls A's `Location`. A captured test signature does not prove consumer-secret recovery, general signature replay, or access-token theft.

## librest: test PKCE entropy without predicting a user's verifier

CVE-2026-16615 states that librest generated PKCE code verifiers with GLib `GRand`, which is not a cryptographic generator. The durable review heuristic is to trace PKCE generation all the way to the entropy source; verifier length, allowed characters, and SHA-256 challenge formation do not compensate for predictable source state.

Use source instrumentation or a test-only wrapper:

1. Identify the exact function that creates `code_verifier`, the GLib RNG calls it reaches, and any time/process data used to seed state.
2. Build an affected artifact with a test seam that injects a fixed synthetic seed. Run fresh processes with the same seed and compare verifier bytes and derived challenges.
3. Run different fixed seeds and confirm the harness is actually controlling the source rather than replaying cached authorization state.
4. Inspect the distribution's fixed patch and repeat with an instrumented CSPRNG wrapper that returns tagged synthetic bytes. Confirm verifier output follows the injected CSPRNG bytes and no `GRand` call occurs on the PKCE path.
5. Stop at deterministic synthetic output. Do not observe authorization traffic, narrow real seed windows, reconstruct a user verifier, or redeem any code.

A safe positive result is **same synthetic PRNG state -> same verifier/challenge on the affected path**, paired with source evidence that production uses that non-CSPRNG. Determinism from a deliberately seeded test generator alone is not enough; document the production call graph and fixed-source difference.

## Reporting checklist

Include:

- exact versions, package hashes, runtime versions, and source commits;
- route, origin, redirect representation, and entropy-source decision tables;
- fake credential/event identifiers and proof that no production secret entered the fixture;
- baseline, one-variable mutation, negative controls, and fixed-build results;
- the application precondition that gives an attacker control over a custom route, webhook call, redirect response, or OAuth provider; and
- narrow impact language separating handler invocation, bearer forwarding, signed-request dispatch, and predictable synthetic PKCE output.

Exclude complete tokens, OAuth signatures, consumer secrets, real webhook bodies, authorization codes, account identifiers, and internal network targets.

## SuperPlane workflow-object and webhook-to-email follow-up

Two sparse July 28 records add adjacent automation checks:

- [GHSA-hg7x-q6w3-jcf5 / CVE-2026-57510](https://github.com/advisories/GHSA-hg7x-q6w3-jcf5) covers SuperPlane before 0.27.0, where viewer-level users could supply canvas or queue UUIDs from another organization to CanvasService gRPC handlers without organization scoping.
- [GHSA-c3mp-rj38-mpvh / CVE-2026-57511](https://github.com/advisories/GHSA-c3mp-rj38-mpvh) covers SuperPlane before 0.30.0, where unauthenticated webhook event titles could cross CR/LF boundaries when rendered into SMTP DATA headers.

For CanvasService, create two lab organizations with viewer A and owner B, plus separate canary canvases, queues, events, and execution-history markers. Replay the normal gRPC-Web or gRPC request while replacing only the object UUID. Test read, append, and delete handlers separately, but route write/delete proofs to disposable marker objects. A positive result is user A reading or changing B's synthetic object while an unrelated/random UUID rejects. Never retrieve secrets from event payloads or disrupt real workflows.

For email rendering, connect SuperPlane to a local SMTP recorder and submit a synthetic webhook event whose title contains CR, LF, and CRLF canaries separately. Record the webhook status and raw SMTP envelope/header/body boundaries, but use only reserved `.invalid` addresses and never relay mail. The finding is a title-controlled extra header or body-boundary change in the recorder, not delivery, SPF/DKIM bypass, phishing, or exfiltration. Repeat on 0.30.0 with normal Unicode and folded-title controls.

Name the edges **cross-organization UUID to unscoped workflow object** and **unauthenticated webhook title to SMTP header structure**. Preserve caller role, organization, method, object owner, webhook route, title encoding, mail library normalization, and fixed-version results.

## October 21 follow-up: Slack Morphism verifier errors log the valid HMAC — signature verification as a chosen-message MAC oracle ([GHSA-26w4-8w32-4x3v / CVE-2026-113799](https://github.com/advisories/GHSA-26w4-8w32-4x3v), medium, ≤2.27.0 → 2.28.0)

`SlackEventSignatureVerifier::verify` computes the expected HMAC **before** comparing against the attacker's `X-Slack-Signature`, and on mismatch stores the *correct signature* in `SlackEventWrongSignatureError.generated_hash` — a public field printed by the type's `Debug`/`Display`, which the default Axum/Hyper listener error handlers log at error level. An attacker who can reach the callback endpoint and read app/service logs (log aggregation UI, crashed-container stderr, CI log capture, debug endpoint) uses the verifier as a **chosen-message HMAC oracle**: send any forged event with a bogus signature, recover the valid signature from the log line, resend within the five-minute freshness window — passes verification without the signing secret. Reproduced end-to-end on 2.26.0/2.27.0.

Durable rules for webhook-auth assessments (this page's family):
- **Error objects are a sink.** On MAC/signature mismatch, the expected value must never reach the error struct, `Debug`/`Display`, logs, or response. Grep verifier error types for computed-expected fields (`generated_hash`, `expected`, `computed`) and trace what the framework's default error handler logs.
- **Log-read = partial secret-read.** The two-capability precondition (endpoint reach + log read) degrades to one whenever logs are aggregated to a wider audience than the secret — check log destination ACLs as part of webhook signing assessment.
- Probe shape: lab webhook listener with a synthetic secret; send invalid-signature request, confirm whether the correct signature appears in captured log output; prove resubmission acceptance with an inert event payload. Never forge signatures against production Slack/app integrations, and never pull real service logs beyond authorized scope.
