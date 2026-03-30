# 2026-03-29 — OpenClaw Feishu webhook reads and parses unauthenticated request bodies before signature validation (GHSA-3h52-cx59-c456)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** The Feishu webhook path parsed request bodies before signature validation, creating an unauthenticated processing surface.

## Why this matters
Auth must happen before side effects. If a webhook parses and processes attacker-controlled body data before checking the signature, the parser and any downstream logic become part of the attack surface.

## Recommended actions
- **Patch/upgrade** to the fixed OpenClaw release.
- **Validate the signature before parsing or acting on the body**.
- **Keep unauthenticated handling minimal** and fail closed on malformed requests.
- **Add tests** proving no body processing occurs before auth succeeds.

## Detection / hunting ideas
- Inspect webhook handlers for any parsing, routing, or logging before signature verification.
- Add regression tests that send invalid signatures and confirm no downstream work happens.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-3h52-cx59-c456>
