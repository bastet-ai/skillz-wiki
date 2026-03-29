# 2026-03-27 — OpenClaw Telegram webhook missing guess rate limiting (GHSA-vcx4-4qxg-mfp4)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** The Telegram webhook auth path accepted bad secrets but did not throttle repeated guesses, making brute-force attempts against weak webhook secrets practical.

## Why this matters
A webhook secret is only as strong as its entropy and the endpoint’s ability to slow guessing. If an attacker can hammer the endpoint without backoff, even a “private” integration can become remotely triggerable.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.25** or later.
- **Harden the webhook path:**
  - Require high-entropy secrets.
  - Rate limit failed auth attempts.
  - Add exponential backoff or temporary lockouts.
  - Log and alert on repeated failures.
- **Review exposure:** confirm the Telegram webhook is not reachable from unexpected networks or proxies.

## Detection / hunting ideas
- Review logs for repeated invalid webhook secret attempts from the same source.
- Look for bursts of 401/403 responses followed by a successful webhook auth.
- Audit any automation that rotates or stores webhook secrets.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-vcx4-4qxg-mfp4>
