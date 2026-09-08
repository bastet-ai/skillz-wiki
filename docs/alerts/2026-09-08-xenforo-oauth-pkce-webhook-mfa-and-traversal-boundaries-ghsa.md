# XenForo before 2.3.13: OAuth2/PKCE token-lifecycle breaks, PayPal-webhook trust, MFA bypass, and archive traversal (14 GHSAs)

Source: hourly offensive-security scan, 2026-09-08 late GitHub `unreviewed` advisory wave (published 2026-09-08 15:31 UTC, XenForo cluster). This is a new operator page because the fourteen advisories expose a **repeatable forum/CMS trust-boundary audit axis** that is durable well beyond the individual records: a single product whose token-issuance path treats single-use tokens as reusable, whose outbound webhook handler trusts an external payment provider's envelope before verifying it, whose MFA gate has a bypass, and whose admin file-import path can write outside its root. The reusable question for any identity- or payment-integrated web app is: **which caller-controlled value crosses into (a) a token that should be single-use, (b) an unverified external signature, (c) a step-up auth gate, or (d) an archive-extraction path?**

Primary entries (all before 2.3.13): [GHSA-pr5w-fh2v-7c9q](https://github.com/advisories/GHSA-pr5w-fh2v-7c9q) (critical, CWE-697, token-endpoint auth bypass), [GHSA-mrq5-6m75-wpj5](https://github.com/advisories/GHSA-mrq5-6m75-wpj5) (critical, CWE-294, authz-code reuse), [GHSA-5x52-2mc2-4jqr](https://github.com/advisories/GHSA-5x52-2mc2-4jqr) (critical, CWE-294, refresh-token replay), [GHSA-3hj9-69jw-9xx6](https://github.com/advisories/GHSA-3hj9-69jw-9xx6) (high, CWE-863, redirect-URI binding), [GHSA-rqwm-9m4j-f7g3](https://github.com/advisories/GHSA-rqwm-9m4j-f7g3) (high, CWE-754, webhook signature fail-open), [GHSA-xc22-88fm-2h5f](https://github.com/advisories/GHSA-xc22-88fm-2h5f) (high, CWE-345, payment replay), [GHSA-x4fx-w4wf-c38c](https://github.com/advisories/GHSA-x4fx-w4wf-c38c) (high, CWE-918, webhook SSRF), [GHSA-wwh4-p7r6-v97f](https://github.com/advisories/GHSA-wwh4-p7r6-v97f) (high, CWE-863, MFA bypass), [GHSA-fxw8-p3x8-7xqx](https://github.com/advisories/GHSA-fxw8-p3x8-7xqx) (high, CWE-22, style-archive traversal), [GHSA-vv8x-44ww-j3wh](https://github.com/advisories/GHSA-vv8x-44ww-j3wh) (high, CWE-674, BBCode recursion), [GHSA-vggm-cwh9-fm3v](https://github.com/advisories/GHSA-vggm-cwh9-fm3v) (medium, CWE-79, dynamic-redirect XSS), [GHSA-gw9m-qhxg-fr69](https://github.com/advisories/GHSA-gw9m-qhxg-fr69) (medium, CWE-863, force-agreement missing authz), [GHSA-9j29-fqp6-x79p](https://github.com/advisories/GHSA-9j29-fqp6-x79p) (medium, CWE-863, ACP cache-rebuild missing authz), and [GHSA-5j56-975f-v5v8](https://github.com/advisories/GHSA-5j56-975f-v5v8) (medium, CWE-639, unauth info disclosure).

!!! warning "Authorized validation only"
    Keep proofs to a disposable XenForo < 2.3.13 lab instance with synthetic users, synthetic OAuth clients, a synthetic PayPal-style webhook peer you own, and a denied payment-authorization sink. Use a marker authorization code, a marker refresh token, an inert webhook payload, and a canary file just outside the style-archive root. Do not mint live OAuth tokens against a real identity provider, do not complete real payments or subscribe real accounts, do not target internal services or cloud metadata through the webhook SSRF, and do not write a live PHP/webshell payload to the public web root. Prove each boundary at the decision point (token re-issued, signature accepted, MFA skipped, file written outside root) and stop there.

## Why this is worth an operator page

XenForo ships a first-party OAuth2/PKCE provider and a PayPal REST payment webhook. Both are standing, reusable surfaces for any forum/BB platform that adds SSO or monetization: the OAuth stack is a **token-lifecycle** surface, and the payment webhook is an **external-trust** surface. This wave shows each surface failing in the classic ways:

- **OAuth2 token lifecycle:** single-use tokens (authorization codes, refresh tokens, PKCE verifiers, client secrets) that are not actually single-use.
- **External payment webhook:** an envelope whose signature is verified only when the header maps to a known algorithm, and whose transaction ID is not deduplicated.
- **Step-up auth (MFA):** a passkey/2FA gate that can be skipped.
- **Admin file import:** a ZIP importer whose path validation is slash-only and misses backslashes on Windows.

Each leg is a standing, reusable check for any identity- or payment-integrated web app.

## The four boundary classes

### 1. OAuth2/PKCE token-lifecycle breaks (5 GHSAs)

The reusable axis: **a token that the OAuth2 spec marks single-use is treated as reusable because the application never marks it consumed.**

| GHSA | Severity / CWE | Defect | Reusable check |
| --- | --- | --- | --- |
| [GHSA-pr5w-fh2v-7c9q](https://github.com/advisories/GHSA-pr5w-fh2v-7c9q) | critical / CWE-697 | Empty `client_secret` and `code_verifier` are treated as falsy in PHP, so the client-secret and PKCE-checker validation is **skipped** — an unauthenticated attacker exchanges a valid authorization code for a token pair without proving client identity or holding the PKCE commitment. | Confirm whether the token endpoint treats an *absent/empty* secret or verifier as "skip validation" vs. "reject." A positive is a token issued with empty `client_secret`/`code_verifier`. |
| [GHSA-mrq5-6m75-wpj5](https://github.com/advisories/GHSA-mrq5-6m75-wpj5) | critical / CWE-294 | Authorization codes are not invalidated after first use; a previously-used code yields a **second, independent** token pair for the same user and scopes. | Replay a consumed authorization code; a positive is a second token pair minted for the same code. |
| [GHSA-5x52-2mc2-4jqr](https://github.com/advisories/GHSA-5x52-2mc2-4jqr) | critical / CWE-294 | Refresh tokens are not marked consumed when the parent access token has expired; the same refresh token can be replayed to mint additional independent pairs for the token's full lifetime. | Replay a refresh token; a positive is an additional token pair minted from the same refresh token. |
| [GHSA-3hj9-69jw-9xx6](https://github.com/advisories/GHSA-3hj9-69jw-9xx6) | high / CWE-863 | The token endpoint does not bind the exchanged code to the redirect URI recorded at authorization time; an attacker holding a code can exchange it using a *different* allowlisted redirect URI. | Exchange a code with a mismatched (but allowlisted) redirect URI; a positive is a token issued against the wrong redirect. |

The standing audit for any OAuth2 implementation: **enumerate every "single-use" artifact (authz code, refresh token, PKCE verifier, client secret) and confirm the code path marks it consumed on first use and rejects it on second use.** PHP truthiness on optional auth fields (the `pr5w` root cause) is a specific, recurring subclass: an empty string is `false`, so an `if ($secret) { validate }` branch silently skips validation when the attacker omits or blanks the field.

### 2. PayPal REST webhook: unverified external trust (3 GHSAs)

The reusable axis: **an external payment provider's webhook is treated as authoritative before its signature and transaction identity are verified.**

| GHSA | Severity / CWE | Defect | Reusable check |
| --- | --- | --- | --- |
| [GHSA-rqwm-9m4j-f7g3](https://github.com/advisories/GHSA-rqwm-9m4j-f7g3) | high / CWE-754 | The signature-verification function returns `true` when the `auth_algo` header maps to an unsupported hash, so a fabricated webhook is treated as verified. | Submit a webhook with an unsupported `auth_algo`; a positive is the handler treating it as verified. |
| [GHSA-xc22-88fm-2h5f](https://github.com/advisories/GHSA-xc22-88fm-2h5f) | high / CWE-345 | No duplicate transaction-ID check; a valid webhook payload can be replayed to trigger repeated subscription activations/account upgrades. | Replay a valid (lab) webhook payload; a positive is a second payment event processed for the same transaction ID. |
| [GHSA-x4fx-w4wf-c38c](https://github.com/advisories/GHSA-x4fx-w4wf-c38c) | high / CWE-918 | The handler follows an attacker-supplied certificate URL in the webhook headers with no scheme/hostname/allowlist validation, enabling SSRF to internal resources incl. cloud metadata. | Point the webhook cert-URL field at an owned no-content peer; a positive is an outbound request to that peer. **Never** point it at metadata or internal services. |

The standing audit for any payment/external-webhook integration: **verify the signature with an explicit allowlist of algorithms (fail closed on unknown), deduplicate by transaction ID, and treat every URL/URL-bearing field in the envelope as untrusted (no internal/metadata destinations).** These three are the three classic webhook-trust failures, and they are independent: fixing the signature does not fix replay or SSRF.

### 3. Step-up auth (MFA) bypass (1 GHSA)

[GHSA-wwh4-p7r6-v97f](https://github.com/advisories/GHSA-wwh4-p7r6-v97f) (high, CWE-863): a multi-factor-authentication bypass in the passkey flow. The reusable check: confirm the second factor is enforced on the login *and* on any alternate credential path (passkey, recovery code, device grant). A positive is reaching an authenticated session while the MFA step was skipped.

### 4. Admin archive-import path traversal (1 GHSA)

[GHSA-fxw8-p3x8-7xqx](https://github.com/advisories/GHSA-fxw8-p3x8-7xqx) (high, CWE-22): the style-archive importer on Windows deployments validates member names against forward slashes only; backslash traversal sequences escape the intended extraction directory and write arbitrary bytes to any web-server-writable path (including the public web root). The reusable check: when an admin ZIP importer validates archive member paths, confirm it normalizes **both** `/` and `\` (and URL-encoded variants) *and* re-checks the result after normalization stays inside the root. A positive is a canary file written outside the extraction root. This is the Windows backslash variant of the standard archive-extraction traversal — track it alongside the [archive-extraction page](2026-08-27-file-write-and-install-path-escape-batch-ghsa.md).

## Secondary records (tracked, lower priority)

- [GHSA-vv8x-44ww-j3wh](https://github.com/advisories/GHSA-vv8x-44ww-j3wh) (high, CWE-674): uncontrolled recursion in the BBCode parser — resource-exhaustion DoS on crafted BBCode.
- [GHSA-vggm-cwh9-fm3v](https://github.com/advisories/GHSA-vggm-cwh9-fm3v) (medium, CWE-79): dynamic-redirect handler reflects a `javascript:` URI that evades host validation via percent-encoded newlines, executing JS in the board origin.
- [GHSA-gw9m-qhxg-fr69](https://github.com/advisories/GHSA-gw9m-qhxg-fr69) (medium, CWE-863): missing authorization in the force-agreement flow.
- [GHSA-9j29-fqp6-x79p](https://github.com/advisories/GHSA-9j29-fqp6-x79p) (medium, CWE-863): missing authorization in the ACP cache-rebuild endpoint.
- [GHSA-5j56-975f-v5v8](https://github.com/advisories/GHSA-5j56-975f-v5v8) (medium, CWE-639): unauthenticated information disclosure.

## Cross-cutting operator lessons

1. **Single-use tokens are the OAuth2 audit axis.** Authz codes, refresh tokens, PKCE verifiers, and client secrets are all "consume-once" artifacts. Enumerate each and confirm the consume-once logic actually fires. PHP truthiness on optional auth fields is a recurring root cause (empty string → `false` → validation branch skipped).
2. **External payment webhooks need three independent checks.** Signature (algorithm-allowlisted, fail-closed), transaction-ID deduplication, and URL-field untrust (no SSRF to internal/metadata). Fixing one does not fix the others.
3. **MFA must be enforced on every credential path.** A passkey/recovery/device grant that skips the second factor is a full MFA bypass; confirm the gate sits on the session-issuing path, not just the primary login form.
4. **Archive-import path validation must normalize both slash types.** Slash-only validation is a Windows backslash traversal; re-check the normalized result stays inside the root.
5. **Version line is the unit of reporting.** All fourteen are "before 2.3.13." Confirm the exact build and patched boundary before reporting.

## Replayable validation boundaries

### OAuth2 token replay / authz-code reuse

1. On a disposable XenForo < 2.3.13 instance, create a **synthetic** OAuth client and a **synthetic** user.
2. Obtain a marker authorization code, exchange it for a token pair, then exchange the *same* code again. A positive is a second, independent token pair for the same code.
3. Repeat with a marker refresh token: use it, let the access token expire, and reuse the refresh token. A positive is an additional pair minted from the same refresh token.
4. Exchange a code with a mismatched (but allowlisted) redirect URI; a positive is a token issued against the wrong redirect.

**Stop at the lab minted pairs.** Do not use these tokens against a real identity provider, a real user account, or a production OAuth flow.

### Webhook signature / replay / SSRF

1. Stand up an owned no-content peer that can record inbound requests.
2. **Signature:** submit a lab webhook with an unsupported `auth_algo`; a positive is the handler treating it as verified.
3. **Replay:** submit a lab (non-monetary) webhook payload twice with the same transaction ID; a positive is two processed payment events.
4. **SSRF:** set the webhook cert-URL field to the owned peer; a positive is an outbound request to that peer. **Do not** point it at cloud metadata, loopback admin routes, or internal services.

No real payment is completed; no real subscription is activated; the "payment events" are lab-synthesized.

### MFA bypass

1. On the disposable instance, create a synthetic MFA-enrolled user.
2. Attempt to authenticate via the passkey path and confirm whether the second factor is enforced. A positive is a session issued with the MFA step skipped.

### Archive-import traversal

1. On a disposable instance (Windows path semantics), craft a marker ZIP whose member name uses backslash traversal to land just **outside** the style-archive root but inside a web-server-writable path.
2. Import it; a positive is the canary file present at the traversal target. **Do not** write an executable PHP payload to the public web root; prove the path-escape with an inert canary only.

## Safety

- **Disposable lab instance only.** One < 2.3.13 build, synthetic users/clients, an owned webhook peer, and a denied payment-authorization sink. Never point these proofs at a production forum.
- **No live token use.** OAuth proofs mint lab tokens against synthetic clients/users only; no real identity provider, user, or access token is touched.
- **No real payments.** Webhook proofs use lab-synthesized, non-monetary payloads; no real payment, subscription, or account upgrade is completed.
- **No internal/metadata SSRF.** The webhook SSRF is proven against the owned no-content peer only; never against cloud metadata, loopback admin routes, or internal services.
- **No live webshell.** The archive-traversal proof writes an inert canary, never an executable payload, to the public web root.

## Sources

- https://github.com/advisories/GHSA-pr5w-fh2v-7c9q
- https://github.com/advisories/GHSA-mrq5-6m75-wpj5
- https://github.com/advisories/GHSA-5x52-2mc2-4jqr
- https://github.com/advisories/GHSA-3hj9-69jw-9xx6
- https://github.com/advisories/GHSA-rqwm-9m4j-f7g3
- https://github.com/advisories/GHSA-xc22-88fm-2h5f
- https://github.com/advisories/GHSA-x4fx-w4wf-c38c
- https://github.com/advisories/GHSA-wwh4-p7r6-v97f
- https://github.com/advisories/GHSA-fxw8-p3x8-7xqx
- https://github.com/advisories/GHSA-vv8x-44ww-j3wh
- https://github.com/advisories/GHSA-vggm-cwh9-fm3v
- https://github.com/advisories/GHSA-gw9m-qhxg-fr69
- https://github.com/advisories/GHSA-9j29-fqp6-x79p
- https://github.com/advisories/GHSA-5j56-975f-v5v8
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

*Source: hourly offensive-security scan, 2026-09-08 late GitHub `unreviewed` advisory wave. All fourteen `XenForo` advisories tracked in the [source index](../notes/source-index.md).*
