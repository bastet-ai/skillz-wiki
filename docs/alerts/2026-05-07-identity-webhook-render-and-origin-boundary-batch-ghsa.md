# Identity, webhook, render, and origin-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where identity flows, webhook signatures, Markdown/HTML rendering, and forwarded-origin handling crossed trust boundaries.

## Advisories covered

- **Keycloak forced browsing** — [GHSA-hm32-hfmw-rhvg](https://github.com/advisories/GHSA-hm32-hfmw-rhvg): direct URL access could reach flows that should require explicit authorization state.
- **Spring Cloud AWS SNS signature verification gap** — [GHSA-r4w4-wv68-qv85](https://github.com/advisories/GHSA-r4w4-wv68-qv85): HTTP/HTTPS SNS endpoint notifications could be spoofed when signatures were not verified.
- **Weblate XSS and private translation enumeration** — [GHSA-5cmv-3rc4-7279](https://github.com/advisories/GHSA-5cmv-3rc4-7279), [GHSA-gcg5-86jr-f7jg](https://github.com/advisories/GHSA-gcg5-86jr-f7jg): Markdown rendering and screenshot APIs need both output encoding and object-visibility checks.
- **Angular SSR forwarded-prefix steering** — [GHSA-69xr-m8h6-h664](https://github.com/advisories/GHSA-69xr-m8h6-h664): encoded `X-Forwarded-Prefix` values can become redirect or request-steering inputs.
- **Lemmy registered-email enumeration** — [GHSA-qxrw-f6fh-34r7](https://github.com/advisories/GHSA-qxrw-f6fh-34r7): resend-verification flows can leak account existence if responses or side effects differ.
- **django-mdeditor missing critical auth** — [GHSA-qp2c-xqv6-phh6](https://github.com/advisories/GHSA-qp2c-xqv6-phh6): editor upload/management endpoints need explicit authentication and authorization.
- **Axonflow Java/TypeScript webhook SDK gaps** — [GHSA-248h-974q-xrc2](https://github.com/advisories/GHSA-248h-974q-xrc2), [GHSA-mph8-9v29-pm42](https://github.com/advisories/GHSA-mph8-9v29-pm42): SDKs must expose HMAC material and verification primitives, not make verification optional by omission.

## Why this is durable

Identity and rendering bugs often come from treating helper routes, proxy headers, and SDK ergonomics as lower-risk than primary business logic. They are still security boundaries when they can create sessions, leak account existence, render attacker content, or authenticate external messages.

## Immediate triage

1. Patch affected identity, webhook, editor, SSR, and rendering components.
2. Verify SNS/webhook consumers reject unsigned, stale, replayed, or wrong-key deliveries before parsing the body deeply.
3. Re-test forced-browsing and direct-route access across password reset, verification, enrollment, and admin helper flows.
4. Normalize forwarded headers once at the trusted edge; reject encoded separators and protocol-relative redirect targets.
5. Confirm Markdown, screenshot, editor-upload, and translation APIs enforce object visibility before rendering or returning metadata.

## Durable controls

- Make webhook signature verification a mandatory SDK path with test vectors, timestamp windows, replay IDs, and key rotation.
- Use indistinguishable responses for account-existence workflows and rate-limit them per account and source.
- Treat proxy-supplied origin/path headers as privileged inputs accepted only from trusted hops.
- Pair every renderer with an authorization check on the source object and context-aware output encoding on the sink.
