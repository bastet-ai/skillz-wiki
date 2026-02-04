# 2026-02-04 — FUXA unauthenticated file upload leading to overwrite / RCE (GHSA-7g56-fwxj-cm23)

**Product:** **FUXA** (advisory notes npm package `fuxa-server`)

**Impact (per advisory):** `FUXA v1.2.7` reportedly exposes an **unauthenticated** `/api/upload` endpoint, enabling arbitrary file upload. This may be used to overwrite critical files (e.g., SQLite user DB) to obtain admin access and potentially achieve code execution (depending on deployment).

## Recommended actions
- Identify whether you run FUXA / `fuxa-server` (especially ≤ **1.2.7**).
- If exposed, **remove from the internet** until patched/mitigated.
- Apply vendor fixes/updates when available; otherwise implement compensating controls:
  - Require authentication/authorization on upload endpoints.
  - Put behind an authenticated reverse proxy.
  - Restrict filesystem permissions for the service user.

## References
- GitHub advisory entry: <https://github.com/advisories/GHSA-7g56-fwxj-cm23>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-69981>
