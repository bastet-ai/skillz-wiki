# 2026-02-05 — webpack buildHttp `allowedUris` allowlist bypass via URL userinfo (`@`) → build-time SSRF (GHSA-8fgc-7cc6-rx7x)

**Summary:** When `experiments.buildHttp` is enabled, webpack’s `allowedUris` checks can be bypassed using crafted URLs containing **userinfo** (the `username:password@host` portion). If the allowlist is enforced with a **raw string prefix check** instead of parsing/canonicalizing the URL, an attacker can make a URL *look* allowlisted while the actual request is sent to a different host.

**Why it matters:** This is a common class of bug: **URL parsing discrepancies** (string checks vs. real URL parsing) leading to **SSRF / policy bypass**.

## Impact
- **Build-time SSRF**: outbound requests from CI/build machines to internal endpoints (metadata services, internal registries, intranet hosts), depending on network reachability.
- **Untrusted content inclusion**: fetched content may be treated as source and bundled/cached.

## Affected
- webpack **when** `experiments.buildHttp` is enabled and `allowedUris` restrictions are relied upon.

## Mitigations / Guidance
- **Upgrade webpack** to a fixed version (per advisory).
- If you must keep an allowlist:
  - **Parse URLs first** (use a real URL parser) and compare on **scheme/host/port** after normalization.
  - **Disallow userinfo** entirely (reject any URL containing `@` in the authority component).
  - Avoid `startsWith()`/substring checks on raw URLs.
  - Consider a **default-deny egress policy** for builds (only allow artifact buckets/registries).

## References
- GitHub Advisory: https://github.com/advisories/GHSA-8fgc-7cc6-rx7x
