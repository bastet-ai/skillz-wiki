# Webhook Secrets Need Brute-Force Resistance

**Date**: 2026-03-28  
**Status**: Durable guidance

Webhook handlers that authenticate requests with a shared secret need more than secrecy. If the secret is short, guessable, or accepted without rate limits, attackers can brute-force the endpoint and trigger privileged actions.

## What to enforce

- Use high-entropy secrets generated server-side.
- Reject requests before any expensive processing.
- Rate limit by source IP, token prefix, and endpoint.
- Add lockouts or backoff after repeated failures.
- Log failed auth attempts with enough context to detect guessing.
- Prefer HMAC-signed requests over bare shared tokens when possible.

## What not to assume

- A secret in a header is not safe just because it is hidden from the UI.
- HTTPS does not stop credential guessing.
- A webhook endpoint is not safe just because it is “internal.”

## Validation checklist

- Can an unauthenticated client trigger the action?
- Can repeated invalid attempts be made without throttling?
- Is there an audit trail for failed verification?
- Does the handler fail closed on malformed or missing signatures?

## Typical failure mode

A webhook path accepts a bearer-style secret, but the secret space is small enough to brute-force and there is no request throttling. The fix is not only changing the secret; the endpoint must enforce rate limiting and stronger request authentication.
