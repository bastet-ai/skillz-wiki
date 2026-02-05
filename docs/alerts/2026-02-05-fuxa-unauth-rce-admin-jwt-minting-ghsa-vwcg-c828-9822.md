# 2026-02-05 — FUXA unauthenticated RCE via admin JWT minting (GHSA-vwcg-c828-9822)

**Product:** FUXA (SCADA/HMI) — advisory references npm package `fuxa-server`

**Impact (per advisory):** If **authentication is enabled**, an unauthenticated attacker can mint **administrator JWTs** via a “heartbeat refresh” endpoint, gain admin access, and then use administrative/script APIs to achieve **remote code execution**.

**Severity:** Critical (CVSS 10.0 in GHSA)

**Affected:** FUXA `<= 1.2.9` when `runtime.settings.secureEnabled=true`

**Fixed:** FUXA `1.2.10`

---

## Why this matters
In an ICS/SCADA context, a web-admin compromise isn’t “just another web app bug”:

- **Admin control** can enable configuration changes that affect process visibility/control.
- **RCE** in the HMI/SCADA layer can be a stepping stone to:
  - pivoting into OT networks,
  - tampering with historian/telemetry,
  - persistence (webshells, cron, service changes),
  - credential theft (secrets, configs, PLC creds if present).

---

## What to do now (defender checklist)
1. **Upgrade to FUXA 1.2.10 or later**.
2. **Do not expose FUXA to the public internet.**
   - Put it behind VPN / private access.
   - Restrict by IP allowlist.
   - If possible, require mutual TLS or SSO in front of it.
3. **Segment network paths**:
   - FUXA should not have broad reachability to OT assets unless explicitly required.
4. **Assume compromise if exposure existed**:
   - Review access logs around the affected endpoints (look for unusual auth/refresh calls).
   - Rotate secrets used by the service (JWT secrets/keys, API keys, DB creds) from a clean host.
   - Hunt for persistence (new users, startup scripts, modified configs).

---

## Engineering lesson (durable guidance)
**“Heartbeat” / “refresh” endpoints often become authentication bypasses.**

Common failure modes:
- issuing tokens without verifying an existing authenticated session,
- accepting unsigned/weakly signed tokens,
- trusting client-supplied identities/roles,
- using refresh endpoints as implicit “login”.

**Hardening pattern:**
- Require a valid, non-expired session to request refresh.
- Bind refresh tokens to device/session + rotate on use.
- Enforce strict audience/issuer/expiry validation.
- Log refresh/token-mint events at high signal (include client IP, user-agent, subject, and result).

---

## References
- GitHub advisory: https://github.com/advisories/GHSA-vwcg-c828-9822
- Vendor advisory: https://github.com/frangoteam/FUXA/security/advisories/GHSA-vwcg-c828-9822
- Fix commit (per GHSA): https://github.com/frangoteam/FUXA/commit/fe82348d160904d0013b9a3e267d50158f5c7afb
