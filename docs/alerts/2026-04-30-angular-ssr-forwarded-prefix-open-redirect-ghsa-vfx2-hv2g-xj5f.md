# Angular SSR forwarded-prefix open redirect and cache poisoning (GHSA-vfx2-hv2g-xj5f)

**Signal:** GitHub Security Advisory updated **2026-04-30**. `@angular/ssr` can turn a single-backslash `X-Forwarded-Prefix` value into a browser-interpreted protocol-relative redirect.

## What it is
Angular SSR's forwarded-prefix validation missed a single leading backslash. In deployments where a proxy passes `X-Forwarded-Prefix` through to the Angular SSR app, an attacker can send a prefix such as `\evil.com`. Angular prepends a leading slash and emits a `Location` header like `/\evil.com`; modern browsers interpret the `/\` sequence as `//`, producing a protocol-relative redirect to an attacker-controlled domain.

The advisory also notes missing `Vary: X-Forwarded-Prefix`, which can let intermediaries cache the malicious redirect and turn a single request into web-cache poisoning.

Affected package: `@angular/ssr` in vulnerable 20.x, 21.x, and 22.0.0-next ranges. Fixed versions: **20.3.21**, **21.2.3**, and **22.0.0-next.2**.

References:
- GitHub advisory: <https://github.com/angular/angular-cli/security/advisories/GHSA-vfx2-hv2g-xj5f>
- GitHub advisory mirror: <https://github.com/advisories/GHSA-vfx2-hv2g-xj5f>
- Fix PR: <https://github.com/angular/angular-cli/pull/32771>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-33397>

## Triage
1. Inventory Angular SSR applications using `@angular/ssr` 20.x, 21.x, or 22.0.0-next.
2. Identify deployments behind CDNs, reverse proxies, ingress controllers, or edge middleware that forward `X-Forwarded-Prefix`.
3. Test whether unauthenticated requests can influence redirect responses through that header.
4. Check CDN/proxy cache rules for routes that cache 3xx responses without varying on forwarded-prefix headers.

## Mitigation
- Upgrade `@angular/ssr` to **20.3.21**, **21.2.3**, **22.0.0-next.2**, or later.
- At the edge, strip `X-Forwarded-Prefix` unless a trusted proxy explicitly sets it.
- If the header is required, normalize it before Angular SSR sees it: reject or remove leading `/` and `\` runs, and allow only expected path prefixes.
- Add/verify cache controls so redirects influenced by forwarded headers are not shared across users; include `Vary: X-Forwarded-Prefix` where the header is legitimately consumed.
- Purge CDN/proxy caches after patching if exploitation is plausible.

## Detection ideas
Look for:

- inbound requests with `X-Forwarded-Prefix` beginning with `\`, `/\`, `%5c`, `%2f%5c`, or mixed slash/backslash encodings
- 301/302/307/308 responses whose `Location` header starts with `/\`, `//`, or an unexpected external hostname
- cache hits serving redirects from high-traffic application routes
- referrer, SEO, or phishing reports where the first hop is a trusted Angular SSR domain

## Operator note
Treat forwarded headers as **trusted-hop metadata**, not user input. Normalize or strip them at the first trusted boundary, and make cache keys vary on any header that can affect routing or redirects.
