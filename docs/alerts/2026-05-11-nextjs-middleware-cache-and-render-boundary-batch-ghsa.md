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

## July 22 Server Action, rewrite, cache, and middleware follow-up

The next wave fixes in Next.js 15.5.21 and 16.2.11 add six operator-relevant boundaries. The affected ranges and prerequisites differ, so prove the named feature and deployment mode rather than reporting a version alone.

| Advisory | Required path | Durable test |
| --- | --- | --- |
| [GHSA-89xv-2m56-2m9x](https://github.com/advisories/GHSA-89xv-2m56-2m9x) / CVE-2026-64649 | Server Actions on a custom server or deployment where clients control the host identity received by Next.js | Compare `Host` and `X-Forwarded-Host` variants during a harmless Server Action redirect/forward and observe the final owned callback destination. |
| [GHSA-p9j2-gv94-2wf4](https://github.com/advisories/GHSA-p9j2-gv94-2wf4) / CVE-2026-64645 | `rewrites()` or `redirects()` interpolates a request capture into an external destination hostname | Prove whether hostname metacharacters escape an intended suffix by routing only to an owned callback. |
| [GHSA-68g3-v927-f742](https://github.com/advisories/GHSA-68g3-v927-f742) / CVE-2026-64648 | App Router server-side `fetch(new Request(init), differentInit)` with request bodies | Two synthetic body values to one URL receive the wrong cached response marker. |
| [GHSA-4633-3j49-mh5q](https://github.com/advisories/GHSA-4633-3j49-mh5q) / CVE-2026-64647 | App Router server-side fetch accepts non-UTF-8 bodies | Distinct byte sequences that normalize or collide receive another request's synthetic response marker. |
| [GHSA-955p-x3mx-jcvp](https://github.com/advisories/GHSA-955p-x3mx-jcvp) / CVE-2026-64643 | App Router uses Server Actions or `use cache` | Public client artifacts disclose internal Server Function identifiers even when the page UI is authenticated. Treat this as recon unless a separate function lacks its own authorization. |
| [GHSA-6gpp-xcg3-4w24](https://github.com/advisories/GHSA-6gpp-xcg3-4w24) / CVE-2026-64642 | Next.js 16 App Router, Turbopack build, and exactly one configured i18n locale | Crafted route variants bypass middleware/proxy while the final handler remains reachable. |

Build an owned fixture with an external rewrite, one Server Action, two marker-only POST responses, one protected App Router page, and an owned callback. Log raw target, host-associated headers, selected destination, body hash/charset, cache key, middleware marker, handler marker, and response marker. Permit egress only to the owned callback and a synthetic loopback service; never request cloud metadata, internal production services, or customer endpoints.

For cache confusion, use two disposable users and non-sensitive response strings. Compare same URL/different body, same body/different user, equal versus differing `Request` init, UTF-8 versus alternate charset, sequential versus concurrent requests, and Pages Router as a negative control. For Server Function discovery, save only action identifiers and the client artifact exposing them; invoke at most a harmless function returning a fixed marker. For middleware bypass, compare normal, locale-prefixed, encoded, data, RSC, and prefetch forms and prove only that middleware is absent while a marker handler runs.

Keep claims distinct: host steering and dynamic-host rewrites are outbound-routing bugs; body collisions are cross-request response confusion; action-ID exposure is a recon primitive; and the single-locale Turbopack issue is a routing-to-authorization differential. Adjacent unbounded-payload, Server Action, and SVG image issues were tracked but not promoted because they add availability-only workflows.

## October 7 20:3xZ follow-up: SSG/ISR cache substitution pair, `use cache` draft-mode fill leak, dev-server MCP endpoint, and Image Optimization allow-listed-host SSRF

New Next.js wave (published 20:30–20:32Z), fixed 16.3.8 (+15.5.27 for the cache legs). Four legs add axes beyond this page's middleware/variant family:

- **Shared response-cache substitution via root catch-all** ([GHSA-mcj8-r9mp-w47p](https://github.com/advisories/GHSA-mcj8-r9mp-w47p) / [CVE-2026-94484](https://nvd.nist.gov/vuln/detail/CVE-2026-94484), 4.8) and **SSG/ISR entry replacement across routes** ([GHSA-4jqv-mc3x-m676](https://github.com/advisories/GHSA-4jqv-mc3x-m676) / [CVE-2026-94543](https://nvd.nist.gov/vuln/detail/CVE-2026-94543), self-hosted Pages Router): a single unauthenticated crafted request makes a *different route's* content serve for a victim page until revalidation — cross-user content substitution plus persistent DoS. Unlike the May `_rsc`/header-variant poisoning legs, these need **no shared front-end cache**: the framework's own on-disk/in-memory SSG-ISR cache is the confusion surface, so Vercel-exempt notices do not protect self-hosters. Probe rule: on self-hosted Next, request a crafted URL against any root-level `catch-all` route and check whether another page's served body changes hash; prove with two marker pages you control and revalidate immediately.
- **`use cache` fill shared across Draft Mode boundary** ([GHSA-3w37-wq28-93x7](https://github.com/advisories/GHSA-3w37-wq28-93x7) / [CVE-2026-94544](https://nvd.nist.gov/vuln/detail/CVE-2026-94544)): pending fills keyed without distinguishing draft vs regular requests — an unauthenticated request overlapping an editor's draft request receives the *unpublished content*, and an on-demand prerender can persist it. Timing-race disclosure of draft content with zero credentials. Rule: any key-value cache-fill that omits a request-attribute dimension (auth state, draft flag, locale, tenant) is a cross-boundary leak once requests overlap — hammer the endpoint concurrently with a draft view open in your own lab CMS and diff bodies for unpublished marker text.
- **`next dev` MCP endpoint trusts any origin** ([GHSA-39w2-rjm5-chcv](https://github.com/advisories/GHSA-39w2-rjm5-chcv) / [CVE-2026-94486](https://nvd.nist.gov/vuln/detail/CVE-2026-94486)): the dev server's Model Context Protocol endpoint does origin-check, so a malicious site the *developer* visits reads project disk paths, error-report source snippets, route inventory, dev logs. Browser-pivoted recon primitive against developer workstations — same desktop-bridge class as the Sept 23 desktop page; for red-team workstation recon, probe `http://localhost:3000` MCP/dev routes from a driven browser before hunting tokens.
- **Image Optimization SSRF via allow-listed remote host** ([GHSA-cjq9-62q9-8jv4](https://github.com/advisories/GHSA-cjq9-62q9-8jv4) / [CVE-2026-94483](https://nvd.nist.gov/vuln/detail/CVE-2026-94483), 6.5): an `images.remotePatterns`-allowed host whose DNS you control sends the optimizer to private IPs. `remotePatterns` allow-lists validate the *hostname pattern*, not the resolved address — check-listed-but-yours DNS is the bypass (pair with the Oct 7 Docling DNS-rebinding leg below and the Sept 20 media page's fetcher rules). Operator checklist on any Next target using remote images: enumerate allowed hosts for ones on registrar- or subdomain-takeover-attainable domains; the optimizer request comes from the server with no auth needed beyond the URL.
- Smaller leg worth the probe list: metadata image routes (`opengraph-image`, `twitter-image`) **ignore `dynamicParams: false`** ([GHSA-f87g-xv8r-7p7x](https://github.com/advisories/GHSA-f87g-xv8r-7p7x) / [CVE-2026-94485](https://nvd.nist.gov/vuln/detail/CVE-2026-94485)) — segments deliberately excluded from `generateStaticParams()` still render dynamically, a per-segment-option drift between sibling route families.
