# 2026-03-29 — OpenClaw Synology Chat webhook token brute-force exposure (GHSA-mf5g-6r6f-ghhm)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** A Synology Chat webhook path allowed pre-auth token guessing without sufficient throttling, making brute-force discovery of weak webhook tokens practical.

## Why this matters
Webhook tokens are bearer secrets. If they are short, predictable, or accepted without rate limiting, the endpoint becomes an online guessing target. The right fix is not just secret rotation; the endpoint must slow down repeated failures.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.28** or later.
- **Require strong webhook tokens:** use high-entropy random secrets only.
- **Throttle auth failures:** add rate limiting, backoff, and temporary lockouts for repeated invalid attempts.
- **Monitor for guessing patterns:** repeated failures from one IP/user agent pair are a strong indicator.
- **Reduce exposure:** keep webhook endpoints off the public internet when practical.

## Detection / hunting ideas
- Alert on bursts of 401/403 responses against webhook endpoints.
- Correlate repeated invalid requests with a later successful auth from the same origin.
- Review whether any health checks, proxies, or automation are bypassing auth controls.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-mf5g-6r6f-ghhm>
