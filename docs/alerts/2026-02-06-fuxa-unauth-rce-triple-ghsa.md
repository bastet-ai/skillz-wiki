# 2026-02-06 — FUXA unauthenticated RCE (multiple issues; fixed in 1.2.10)

**Upstream advisories:**
- https://github.com/advisories/GHSA-vwcg-c828-9822 (auth bypass via heartbeat refresh → admin JWT minting → RCE)
- https://github.com/advisories/GHSA-32cc-x95p-fxcg (hardcoded JWT secret / insecure default → admin access → RCE)
- https://github.com/advisories/GHSA-88qh-cphv-996c (path traversal → arbitrary file write → likely RCE)

## What happened
FUXA (ICS/SCADA HMI) had **multiple vulnerabilities** that can enable **unauthenticated remote compromise** of the server:
- **Authentication bypass** paths that result in **admin JWT minting / forged tokens**, even when `runtime.settings.secureEnabled` is set to `true`.
- A **path traversal** that enables **arbitrary file write** to attacker-chosen filesystem locations.

In practice, these issues can be chained (or exploited independently) to achieve **remote code execution** and potentially **pivot into connected OT/ICS environments**.

## Who is affected
You are at risk if you run **FUXA <= 1.2.9**, including deployments that believe they are “secured” because authentication is enabled.

## Defender guidance
1. **Upgrade immediately** to **FUXA 1.2.10** (or newer).
2. Until upgraded (or if you cannot upgrade promptly):
   - **Remove internet exposure** (block inbound at perimeter; allowlist only management networks/VPN).
   - Put FUXA behind a **reverse proxy** with strong auth (and ideally mTLS) and strict IP allowlists.
   - Run the service as a **non-root** user with tight filesystem permissions (reduce impact of file-write primitives).
3. **Assume compromise is possible** if the instance was reachable:
   - review logs for suspicious API use (especially upload/heartbeat/admin endpoints)
   - look for unexpected new/modified files in the FUXA install path and writable directories
   - rotate secrets (JWT secrets, API keys) after upgrading

## Durable lesson
“**Auth enabled**” is not the same as “**secure**” when:
- defaults are fail-open (hardcoded secrets), and/or
- unauth endpoints can mint/refresh tokens.

For ICS/OT-adjacent web apps, treat the HMI as a **high-value pivot point**:
- no direct internet exposure
- defense-in-depth controls (VPN/mTLS, allowlists)
- least-privilege service accounts + filesystem hardening

## References
- GHSA-vwcg-c828-9822: https://github.com/advisories/GHSA-vwcg-c828-9822
- GHSA-32cc-x95p-fxcg: https://github.com/advisories/GHSA-32cc-x95p-fxcg
- GHSA-88qh-cphv-996c: https://github.com/advisories/GHSA-88qh-cphv-996c
