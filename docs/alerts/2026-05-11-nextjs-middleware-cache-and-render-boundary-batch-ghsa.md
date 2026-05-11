# Next.js middleware, cache, and render-boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11.

This batch is durable because it shows one framework lesson from several angles: internal routing headers, data routes, Server Component variants, image optimization, WebSocket upgrades, and CSP/script serialization are all trust boundaries when an app is self-hosted or sits behind shared caches.

## Advisories covered

- **Middleware/proxy redirects can be cache-poisoned** — [GHSA-3g8h-86w9-wvmq](https://github.com/advisories/GHSA-3g8h-86w9-wvmq): external `x-nextjs-data` requests could transform redirect handling into non-browser `x-nextjs-redirect` responses that shared caches might store. Affects `next >=12.2.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **App Router CSP nonce XSS** — [GHSA-ffhc-5mcf-pf4q](https://github.com/advisories/GHSA-ffhc-5mcf-pf4q): malformed request-derived nonce values could be reflected into cached HTML. Affects `next >=13.4.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **RSC cache-busting collision** — [GHSA-vfv6-92ff-j949](https://github.com/advisories/GHSA-vfv6-92ff-j949): `_rsc` cache-busting collisions could poison shared cache variants. Affects `next >=13.4.6,<15.5.16` and `>=16.0.0,<16.2.5`.
- **`beforeInteractive` script XSS** — [GHSA-gx5p-jg67-6x7h](https://github.com/advisories/GHSA-gx5p-jg67-6x7h): untrusted serialized script content could break out of the intended script context. Affects `next >=13.0.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **Cache Components connection exhaustion** — [GHSA-mg66-mrh9-m8jx](https://github.com/advisories/GHSA-mg66-mrh9-m8jx): crafted POST requests could deadlock request-body handling and exhaust open connections. Affects `next >=15.0.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **Image Optimization API local-image OOM** — [GHSA-h64f-5h5j-jqjh](https://github.com/advisories/GHSA-h64f-5h5j-jqjh): self-hosted default image loader could fetch local assets into memory without a maximum size. Affects `next >=10.0.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **WebSocket upgrade SSRF** — [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r): self-hosted built-in Node.js server could proxy crafted upgrade requests to arbitrary targets. Affects `next >=13.4.13,<15.5.16` and `>=16.0.0,<16.2.5`; Vercel-hosted deployments are reported unaffected.
- **Dynamic route parameter middleware bypass** — [GHSA-492v-c6pp-mqqv](https://github.com/advisories/GHSA-492v-c6pp-mqqv): external parameters could alter the dynamic route value seen by the page while middleware saw the visible path. Affects `next >=15.4.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **RSC response cache poisoning** — [GHSA-wfc6-r584-vfw7](https://github.com/advisories/GHSA-wfc6-r584-vfw7): shared caches could serve component payload variants from the original URL. Affects `next >=14.2.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **App Router segment-prefetch middleware bypass** — [GHSA-267c-6grr-h53f](https://github.com/advisories/GHSA-267c-6grr-h53f): `.rsc` and segment-prefetch route variants could miss intended middleware rules. Affects `next >=15.2.0,<15.5.16` and `>=16.0.0,<16.2.5`.
- **Turbopack middleware/proxy incomplete-fix follow-up** — [GHSA-26hh-7cqf-hhc6](https://github.com/advisories/GHSA-26hh-7cqf-hhc6) / CVE-2026-45109: the CVE-2026-44575 fix did not cover `middleware.ts` with Turbopack, so App Router segment-prefetch bypasses still require newer patches. Affects `next >=15.2.0,<15.5.18` and `>=16.0.0,<16.2.6`.
- **Pages Router i18n data-route middleware bypass** — [GHSA-36qx-fr4f-26g5](https://github.com/advisories/GHSA-36qx-fr4f-26g5): locale-less `/_next/data/<buildId>/<page>.json` requests could retrieve protected SSR JSON without the expected middleware check. Affects `next >=12.2.0,<15.5.16` and `>=16.0.0,<16.2.5`.

## Operator triage

1. Upgrade all affected Next.js applications to **15.5.18** or **16.2.6** or later; earlier 15.5.16/16.2.5 builds did not fully cover Turbopack `middleware.ts` for the segment-prefetch bypass.
2. For self-hosted deployments, place explicit deny/allow rules in front of `/_next/data/`, `/_next/image`, `.rsc`, segment-prefetch URLs, WebSocket upgrades, and internal-only Next.js headers.
3. Review CDN and reverse-proxy cache keys. Include `RSC`, `_rsc`, data-route classification, relevant locale, authorization state, and response type, or bypass shared caching for authenticated pages.
4. Audit middleware/proxy authorization assumptions: verify protected content cannot be fetched through JSON data routes, RSC route variants, prefetch paths, or dynamic-route parameter confusion.
5. Set request body, response size, local-image size, header count, and connection-timeout limits at the edge while app upgrades roll out.

## Durable controls

- Treat framework-internal headers as untrusted unless injected by a trusted hop and stripped from the public edge.
- Authorization belongs at the final data/render handler too; middleware is a routing optimization, not the only policy boundary.
- Shared caches must partition on representation and identity, not just URL.
- Server-side WebSocket upgrade paths need the same SSRF canonicalization as normal HTTP fetch/proxy paths.
- Script, CSP nonce, and server-component serialization must escape untrusted values before any cacheable HTML or component payload is produced.
