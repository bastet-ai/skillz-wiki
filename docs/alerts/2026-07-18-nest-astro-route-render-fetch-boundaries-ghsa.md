# NestJS and Astro route, render, and image-fetch boundary checks

Sources: hourly offensive-security scan, 2026-07-18 GitHub Security Advisory updates. Primary entries: NestJS [GHSA-6v32-fjc9-9qf6](https://github.com/advisories/GHSA-6v32-fjc9-9qf6) / CVE-2026-54281, Astro [GHSA-jrpj-wcv7-9fh9](https://github.com/advisories/GHSA-jrpj-wcv7-9fh9) / CVE-2026-54298, and `@astrojs/netlify` [GHSA-529g-xq4f-cw38](https://github.com/advisories/GHSA-529g-xq4f-cw38) / CVE-2026-54300.

This batch is durable for operators because it exposes three reusable framework-integration boundaries: middleware matching a different route representation than the application handler, attacker-controlled object keys becoming server-rendered HTML attribute names, and deployment adapters translating host/path allowlists into broader regular expressions.

!!! warning "Authorized validation only"
    Use disposable NestJS/Astro applications, synthetic users and records, owned image origins, and harmless DOM/callback markers. Do not bypass authentication on production routes, collect sessions or user data, target internal services, or deliver executable browser payloads to real users.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-6v32-fjc9-9qf6](https://github.com/advisories/GHSA-6v32-fjc9-9qf6) / CVE-2026-54281 | `@nestjs/platform-fastify` middleware registered with `MiddlewareConsumer.forRoutes()` | The default Fastify adapter can route `/resource/` to an application handler while Nest middleware registered for `/resource` does not run | Add trailing-slash and canonical-path variants to authentication/authorization middleware matrices. |
| [GHSA-jrpj-wcv7-9fh9](https://github.com/advisories/GHSA-jrpj-wcv7-9fh9) / CVE-2026-54298 | Astro `spreadAttributes()` / `addAttribute()` | Spread-object values are escaped, but untrusted object keys can cross into unvalidated HTML attribute names during SSR, SSG, or hybrid rendering | Trace both keys and values from API/CMS/URL data into spread props; prove the key-to-markup transition with inert attributes. |
| [GHSA-529g-xq4f-cw38](https://github.com/advisories/GHSA-529g-xq4f-cw38) / CVE-2026-54300 | `@astrojs/netlify` conversion of `image.remotePatterns` | Adapter-generated Netlify Image CDN regexes can make a single-subdomain wildcard include the apex host and make a single-segment path wildcard match deeper paths | Compare source-framework allowlist decisions with built deployment artifacts and the live CDN fetch decision. |

Affected ranges in the advisory records are `@nestjs/platform-fastify <= 11.1.23`, `astro < 6.4.6`, and `@astrojs/netlify < 7.0.13`. Confirm the deployed package and adapter versions before testing; do not infer exposure from a framework banner alone.

## Replayable validation boundaries

### NestJS trailing-slash middleware matrix

1. Build a disposable NestJS application with the Fastify adapter, one synthetic protected resource, and middleware registered through `MiddlewareConsumer.forRoutes()` for the normal CRUD route shape.
2. Make the middleware add a harmless response header or append a nonce to a lab-only log before it applies the synthetic authentication decision.
3. Send equivalent requests to `/resource`, `/resource/`, `/resource/canary`, and `/resource/canary/`. Keep method, headers, query, and body constant.
4. Record the application handler reached, middleware marker present or absent, authentication result, status, and response-body canary for each representation.
5. Repeat against the fixed package and with route-level guards as negative controls. Distinguish a middleware omission from an ordinary router 404 or redirect.

Report this as **request path representation -> framework middleware matcher -> application router -> protected handler**. Strong evidence is a decision table showing that only a canonicalization variant reaches the same handler without the middleware marker.

### Astro spread-key rendering checks

1. Identify Astro templates that spread an object onto native HTML, for example `<div {...record}>`, and trace whether an API, CMS field map, database JSON object, or URL-derived object can control its keys.
2. In a local SSR or build harness, supply a benign unusual key such as `data-skillz-canary` and confirm it becomes an attribute. This proves key control without script execution.
3. Use a quote-containing inert key that attempts to introduce only a second `data-*` attribute. Compare source data, raw rendered HTML, and the browser-parsed DOM.
4. Test value-only control separately. A safely escaped value does not disprove attribute-name injection when the object key follows another path.
5. Repeat on the fixed Astro release and with a static allowlist of permitted prop names.

Report this as **untrusted object key -> spread props -> server-rendered attribute name -> browser DOM marker**. Do not use cookie access, credential forms, keyloggers, or executable event handlers in wiki or customer-facing evidence.

### Astro-to-Netlify image allowlist differential

1. Create an Astro/Netlify lab with one owned apex origin, one owned single-level subdomain, and canary image paths at `/ok/a.svg`, `/ok/a/b.svg`, and `/nope/a.svg`.
2. Configure `image.remotePatterns` with a single-level host wildcard and a single-segment path wildcard. Record Astro's canonical helper decision for every host/path pair.
3. Build the deployment and inspect `.netlify/v1/config.json`. Save the generated `images.remote_images` expression as evidence; do not rely only on source configuration.
4. Request each encoded canary URL through the lab Netlify Image CDN route and correlate responses with owned-origin callback logs.
5. Positive evidence is a mismatch such as apex-host or deeper-path rejection by Astro's matcher but acceptance by the generated CDN policy. Include patched-adapter output as a negative control.

Report this as **framework allowlist -> adapter regex translation -> deployment CDN matcher -> owned origin fetched**. Keep all hosts under researcher control; do not probe loopback, metadata, private networks, or third-party origins.

## Operator checklist

- [ ] Did route testing hold method, body, query, and identity constant while varying only path representation?
- [ ] Did middleware evidence distinguish handler execution from redirects and 404s?
- [ ] Did spread-prop testing trace object keys separately from object values and use inert DOM markers?
- [ ] Did image testing compare source matcher, generated deployment config, live CDN decision, and callback logs?
- [ ] Did every proof remain inside disposable apps and owned origins?

## Not promoted from the same updated wave

[GHSA-c43c-rf7g-5xpg](https://github.com/advisories/GHSA-c43c-rf7g-5xpg) (Katello cross-product content-existence disclosure) and [GHSA-j4h6-gcj7-7v9v](https://github.com/advisories/GHSA-j4h6-gcj7-7v9v) (an older Decidim meeting-embed XSS record) were marked processed without standalone guidance. The available details did not add a stronger reusable workflow beyond existing object-authorization and trusted-render boundary pages.