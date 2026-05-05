# SSRF, redirect, and render-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because it shows the same URL trust failure across link previews, SSRF hardening libraries, wikis, game integrations, commerce redirects, and video plugins: user-provided URLs and rendered parameters need canonicalization, egress policy, and inert rendering at the sink.

## Advisories covered

- **link-preview-js** — [GHSA-4gp8-rjrq-ch6q](https://github.com/advisories/GHSA-4gp8-rjrq-ch6q): IPv6 and internal loopback SSRF bypasses.
- **requests-hardened** — [GHSA-vh75-fwv3-pqrh](https://github.com/advisories/GHSA-vh75-fwv3-pqrh): SSRF protection bypass.
- **Admidio SSRF incomplete fix** — [GHSA-hcjj-chvw-fmw9](https://github.com/advisories/GHSA-hcjj-chvw-fmw9): incomplete mitigation for CVE-2026-32812.
- **Geyser player head texture URL** — [GHSA-xcfg-fcr5-gw9r](https://github.com/advisories/GHSA-xcfg-fcr5-gw9r): SSRF through texture URL fetching.
- **XWiki PlantUML macro** — [GHSA-42fc-7w97-8vrc](https://github.com/advisories/GHSA-42fc-7w97-8vrc): SSRF through the `server` parameter.
- **Magento LTS `uenc` redirect** — [GHSA-qpgq-5g92-j5q8](https://github.com/advisories/GHSA-qpgq-5g92-j5q8): open redirect through unvalidated `uenc` in `stockAction()`.
- **Video Meet iframe** — [GHSA-mm5f-8q57-4fc4](https://github.com/advisories/GHSA-mm5f-8q57-4fc4): reflected XSS through unescaped `user` and `pass` parameters in a JavaScript string literal.
- **Fiber AutoFormat** — [GHSA-qjv7-627w-8qjv](https://github.com/advisories/GHSA-qjv7-627w-8qjv): XSS through content negotiation/rendering behavior.

## Operator triage

1. Identify link-preview, webhook, wiki macro, avatar/texture, document-rendering, and commerce redirect paths that fetch or reflect attacker-provided URLs.
2. Block metadata, loopback, link-local, private, multicast, IPv4-mapped IPv6, IPv6 aliases, and internal DNS results before and after redirects.
3. Re-test incomplete SSRF fixes with encoded IPs, DNS rebinding, redirects, alternate schemes, absolute-form URLs, and mixed IPv4/IPv6 forms.
4. Replace URL-in-state redirects with opaque server-side redirect IDs or strict relative-path allowlists.
5. Escape values at the JavaScript/HTML/CSS/URL context where they are rendered; do not rely on earlier generic sanitization.

## Durable controls

- URL validation belongs in the fetch primitive, not in scattered callers.
- Network clients need post-resolution and post-redirect policy checks on every hop.
- SSRF hardening libraries should ship with regression fixtures for loopback aliases, IPv6 forms, redirects, and DNS rebinding.
- Redirect parameters should never be trusted as absolute URLs unless they match an explicit origin allowlist after canonicalization.
- Renderers should default to inert output for user-controlled values, especially inside JavaScript string literals and negotiated response formats.
