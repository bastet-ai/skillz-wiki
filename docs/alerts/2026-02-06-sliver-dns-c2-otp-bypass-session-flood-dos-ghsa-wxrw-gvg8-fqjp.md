# 2026-02-06 — Sliver DNS C2 OTP bypass → unauthenticated session flooding / DoS (GHSA-wxrw-gvg8-fqjp)

GitHub published an advisory for **Sliver** (Bishop Fox) describing a **denial-of-service** issue in the **DNS C2 listener**: the server accepts unauthenticated “bootstrap” (`TOTP`) messages and allocates server-side session state **without validating OTP values**, even when `EnforceOTP` is enabled.

- Advisory: <https://github.com/advisories/GHSA-wxrw-gvg8-fqjp>

## Why this matters (durable guidance)

This is a common (and dangerous) class of failures:

- **“Security control is configurable”** (`EnforceOTP`) but the **critical code path** doesn’t actually enforce it.
- **Unauthenticated requests create durable server-side state**, and that state has **no lifecycle control** (expiry/cleanup) in the vulnerable flow.

Even when the only impact is “just DoS”, DoS against security tooling (C2 frameworks, scanners, logging, CI/CD, etc.) can become a *tactical enabler* for attackers.

## Impact (per advisory)

- Unauthenticated remote actor can repeatedly create DNS sessions.
- Server memory grows until performance degradation or **memory exhaustion**.

## Triage

1. Identify any Sliver servers with **DNS C2** enabled and **internet exposure**.
2. Look for indicators of session flooding:
   - unusual DNS query volume to the listener
   - many short-lived or never-completing “hello/bootstrap” events
   - rising RSS / heap usage in the Sliver server process

## Mitigation

- **Upgrade Sliver** to the fixed version (per advisory, **1.6.12**).
- Reduce blast radius:
  - don’t expose DNS C2 publicly unless you must
  - add network-level rate limiting / filtering in front of the listener
  - monitor and alert on memory growth + anomalous DNS traffic

## Defensive engineering notes (applies broadly)

When designing “bootstrap” or “session establishment” endpoints:

- enforce auth controls on *every* ingress path (including “pre-auth”/bootstrap)
- don’t allocate unbounded state based on unauthenticated inputs
- add explicit lifecycle controls (TTL, max sessions, LRU eviction)
- apply rate limits close to the edge (before expensive parsing/allocations)

## References

- <https://github.com/advisories/GHSA-wxrw-gvg8-fqjp>
- <https://github.com/BishopFox/sliver/security/advisories/GHSA-wxrw-gvg8-fqjp>
