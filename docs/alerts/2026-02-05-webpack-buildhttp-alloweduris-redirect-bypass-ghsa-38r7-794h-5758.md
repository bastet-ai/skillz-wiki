# 2026-02-05 — webpack buildHttp `allowedUris` bypass via HTTP redirects → build-time SSRF + cache persistence (GHSA-38r7-794h-5758)

**Summary:** When `experiments.buildHttp` is enabled, webpack’s HTTP resolver can enforce `allowedUris` on the **initial** URL but fail to re-check the allowlist after following **HTTP 30x redirects**. If an allowlisted endpoint can redirect (intentionally, via open redirect, or via attacker control), the build can be tricked into fetching content from **non-allowlisted** destinations.

## Impact
- **Build-time SSRF**: CI/build machines may be induced to fetch internal URLs (metadata services, internal APIs) depending on network reachability.
- **Untrusted content inclusion**: redirected responses may be treated as module source and bundled.
- **Persistence risk**: fetched responses may be retained in build artifacts and/or buildHttp cache.

## Affected
- webpack **when** `experiments.buildHttp` is enabled and `allowedUris` is relied upon as a security boundary.

## Mitigations / Guidance
- **Upgrade webpack** to a fixed version (per advisory).
- Treat URL allowlists as a **parsing + policy** problem, not string matching:
  - After any redirect, **re-validate** the final URL against policy.
  - Canonicalize (scheme/host/port) and **reject redirects** to non-allowlisted origins.
- Prefer **default-deny egress** in CI/build environments.

## References
- GitHub Advisory: https://github.com/advisories/GHSA-38r7-794h-5758
- Related (userinfo `@` bypass): https://github.com/advisories/GHSA-8fgc-7cc6-rx7x
