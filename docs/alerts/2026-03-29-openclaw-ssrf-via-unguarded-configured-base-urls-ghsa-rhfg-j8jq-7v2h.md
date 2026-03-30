# 2026-03-29 — OpenClaw SSRF via unguarded configured base URLs in multiple channel extensions (Incomplete Fix for CVE-2026-28476) (GHSA-rhfg-j8jq-7v2h)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** Multiple channel extensions used configured base URLs without sufficient guarding, enabling SSRF. The advisory notes this is an incomplete fix for CVE-2026-28476.

## Why this matters
Any feature that accepts a configured URL and later fetches or posts to it can become an SSRF primitive if parsing, normalization, or allowlisting is weak.

## Recommended actions
- **Patch/upgrade** to the latest OpenClaw release containing the complete fix.
- **Parse URLs structurally** and reject userinfo, internal hosts, and unsafe schemes.
- **Apply egress controls** for any worker that can reach arbitrary URLs.
- **Review related extensions** for the same trust mistake.

## Detection / hunting ideas
- Search for URL-allowlist checks that use string matching instead of parsed hostname/scheme checks.
- Add tests for userinfo tricks, redirect tricks, and RFC1918/metadata targets.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-rhfg-j8jq-7v2h>
