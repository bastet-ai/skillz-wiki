# 2026-02-04 — Alist disables TLS certificate verification by default (GHSA-8jmm-3xwx-w974)

**Product:** Alist (go module: `github.com/alist-org/alist/v3`)

## Summary
A GitHub Security Advisory reports that **Alist** had an insecure default: **TLS certificate verification disabled** for outgoing storage-driver communications.

- Advisory: <https://github.com/advisories/GHSA-8jmm-3xwx-w974>
- CVE: CVE-2026-25160
- CWE: CWE-295 (Improper Certificate Validation)

## Why this matters
This is the classic **MitM-by-configuration** failure mode.

If the product talks to upstream storage providers (WebDAV/S3-like APIs/other HTTPS backends) and skips certificate verification, an attacker who can influence routing/DNS/Wi‑Fi/LAN can:
- intercept credentials (cookies, tokens)
- read/modify uploaded or downloaded files
- silently redirect storage operations to attacker endpoints

## Durable guidance (what to do in your own systems)
1. **Never ship `InsecureSkipVerify=true` as a default**
   - If you need to support broken enterprise PKI, solve it with **proper trust** (CA bundle, intermediates, hostname/SNI) not by disabling verification.

2. **Make insecure modes loud and expensive**
   - must be opt-in
   - must warn loudly
   - must be scoped (per-endpoint)
   - should be time-bombed (auto-expire)

3. **Add regression tests**
   - tests that fail if TLS verification is disabled in default config

## References
- GitHub Advisory: <https://github.com/advisories/GHSA-8jmm-3xwx-w974>
