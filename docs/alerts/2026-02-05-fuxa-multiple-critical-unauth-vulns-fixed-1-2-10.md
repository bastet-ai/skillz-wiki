# 2026-02-05 — FUXA: multiple critical unauth vulnerabilities (RCE / auth bypass / secrets exposure) fixed in 1.2.10

**Product:** **FUXA** (npm package: `fuxa-server`) — industrial HMI/SCADA web application

## Summary
GitHub advisories report multiple **critical** issues affecting **FUXA <= 1.2.9**, including:
- **Unauthenticated RCE / admin takeover** via JWT minting/auth bypass paths
- **Arbitrary file write / path traversal** leading to likely RCE
- **Hardcoded / insecure JWT secret defaults** (forgery)
- **Unauthenticated disclosure** of sensitive configuration (including **database credentials**)

**Fixed:** **FUXA 1.2.10**

## Why this matters
FUXA is often deployed close to operational environments (ICS/OT). A remote unauthenticated compromise can translate into:
- Manipulation of device tags / drivers (process integrity)
- Credential theft (InfluxDB / other backend services)
- Full host takeover and lateral movement

## Recommended actions
1. **Upgrade immediately** to **FUXA 1.2.10+**.
2. Treat all **internet-exposed** FUXA instances as high-risk:
   - Remove public exposure where possible (VPN / allowlist / mTLS).
   - Place behind a reverse proxy with strong auth.
3. **Rotate secrets** (JWT keys, database credentials, API keys) **after patching**.
4. Add monitoring:
   - Alert on unexpected admin/API actions, file writes/uploads, and driver/tag changes.

## References
- GHSA (FUXA unauth RCE via hardcoded JWT secret / default config): <https://github.com/advisories/GHSA-32cc-x95p-fxcg>
- GHSA (FUXA unauth file write / upload API): <https://github.com/advisories/GHSA-88qh-cphv-996c>
- GHSA (FUXA unauth RCE via admin JWT minting): <https://github.com/advisories/GHSA-vwcg-c828-9822>
- GHSA (FUXA unauth secrets/config exposure): <https://github.com/advisories/GHSA-c5gq-4h56-4mmx>

## Consolidation note
<!-- consolidation-note: wiki-redundancy-2026-05-22 -->

This is the canonical page for this topic. During the 2026-05-22 redundancy pass, overlapping pages were reduced to compatibility pointers:

- `alerts/2026-02-04-fuxa-multiple-unauth-rce-credential-exposure-ghsa.md`
- `alerts/2026-02-06-fuxa-unauth-rce-triple-ghsa.md`
