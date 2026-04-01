# 2026-03-31 — SiYuan reflected XSS via SVG namespace-prefix bypass (GHSA-73g7-86qr-jrg3)

**Product:** **SiYuan**

**Impact (per advisory):** `SanitizeSVG` can be bypassed with namespace-prefixed element names such as `x:script`, allowing reflected XSS in the unauthenticated dynamic icon endpoint.

## Why this matters
Tag-blocking logic that compares raw parser node names can miss namespace-prefixed variants. In SVG/XML contexts, the browser parser may interpret the same markup differently than the sanitizer did.

## Recommended actions
- **Patch/upgrade** SiYuan to the fixed release.
- Normalize tag names before policy checks:
  - strip namespace prefixes
  - compare on local name, not raw qualified name
- Treat any SVG or XML that is rendered in a browser as active content.
- Add a restrictive CSP where browser-delivered SVG is unavoidable.

## Detection / hunting ideas
- Search for browser-delivered SVG endpoints that accept user-controlled content.
- Add tests for prefixed variants such as `x:script`, `x:iframe`, and `x:foreignObject`.
- Review any sanitizer that uses a static denylist against parsed tag names.

## Related durable guidance
- [/best-practices/untrusted-xml-parsing-hardening](../best-practices/untrusted-xml-parsing-hardening.md)

## References
- GitHub advisory: <https://github.com/advisories/GHSA-73g7-86qr-jrg3>
- Vendor advisory: <https://github.com/siyuan-note/siyuan/security/advisories/GHSA-73g7-86qr-jrg3>
