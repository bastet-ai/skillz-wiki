# 2026-03-27 — OpenClaw BlueBubbles webhook missing rate limiting (GHSA-xq8g-hgh6-87hv)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** BlueBubbles webhook auth rejected wrong passwords without throttling repeated guesses, allowing brute-force attempts against weak webhook passwords.

## Why this matters
If an integration uses a shared password instead of a stronger message-auth scheme, missing rate limits turn that password into a remotely guessable control surface.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.25** or later.
- **Harden authentication:**
  - Use high-entropy passwords or signed requests.
  - Rate limit and back off repeated failures.
  - Consider IP-based allowlists where appropriate.
- **Separate concerns:** keep webhook auth and downstream side effects isolated so failed auth cannot trigger work.

## Detection / hunting ideas
- Review logs for repeated invalid password attempts.
- Alert on sustained 401/403 bursts against webhook endpoints.
- Check whether any automation depends on secrets that are human-generated or reused elsewhere.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-xq8g-hgh6-87hv>
