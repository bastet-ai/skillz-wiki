# 2026-03-29 — OpenClaw Synology Chat webhook pre-auth rate-limit bypass enables brute-force guessing of webhook token (GHSA-mf5g-6r6f-ghhm)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** A Synology Chat webhook path allowed pre-auth token guessing without sufficient throttling, making weak webhook tokens practical to brute force.

## Why this matters
A webhook token is a bearer secret. If an endpoint allows repeated guesses without backoff, secrecy alone is not enough; the endpoint itself becomes an online guessing target.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.28** or later.
- **Require high-entropy webhook secrets**.
- **Throttle failures** with rate limiting, backoff, and temporary lockouts.
- **Keep webhook endpoints off the public internet** where possible.

## Detection / hunting ideas
- Alert on bursts of 401/403s against webhook endpoints.
- Correlate repeated failures with a later success from the same origin.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-mf5g-6r6f-ghhm>
