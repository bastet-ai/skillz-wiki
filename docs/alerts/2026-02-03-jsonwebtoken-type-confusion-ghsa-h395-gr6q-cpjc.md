# 2026-02-03 — jsonwebtoken type confusion → potential authz bypass (GHSA-h395-gr6q-cpjc)

**What happened:** The `jsonwebtoken` library had a type confusion issue that could lead to a **potential authorization bypass** in some integration patterns.

**Why it matters:** JWT vulnerabilities are often “sharp edges”:
- a small parsing/typing bug can become **auth bypass** depending on how claims are interpreted
- the impact depends heavily on application logic (roles, audiences, issuers)

## Durable guidance (defensive)

1. **Upgrade immediately**
   - Treat auth libraries as high-risk dependencies.

2. **Validate claims defensively**
   - Enforce types and presence for required claims (`sub`, `aud`, `iss`, expiry).
   - Reject unexpected types (arrays/objects where you expect a string).

3. **Pin and enforce algorithms**
   - Do not accept `alg` from the token as policy.
   - Explicitly allowlist expected algorithms.

4. **Separate “verification” from “authorization”**
   - Verification proves the token is valid.
   - Authorization must be done against a strict, app-defined schema.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-h395-gr6q-cpjc>
