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

## July 20 follow-up: View Transition values crossing CSS and HTML contexts

[GHSA-4g3v-8h47-v7g6](https://github.com/advisories/GHSA-4g3v-8h47-v7g6) adds a separate Astro rendering boundary. In affected Astro releases before `7.1.0`, server-generated View Transition styles can place string animation properties into a raw `<style>` element without making them safe for both CSS serialization and the HTML raw-text context. An application is not exposed merely because it uses View Transitions: attacker-controlled data must reach a property such as `duration`, `easing`, `direction`, `delay`, `fillMode`, or `name` in an SSR/on-demand render path.

### Replayable transition-style check

1. Find `transition:animate` use and trace every animation property back through URL parameters, CMS fields, API objects, database values, and frontmatter. Record whether the page is server-rendered, hybrid, or prerendered.
2. In a disposable Astro app, pass an ordinary canary string through one property and capture the raw response. Confirm which generated style declaration contains it before testing context boundaries.
3. Use a non-executable delimiter canary containing a closing-style sequence followed only by a harmless custom element or `data-*` marker. Compare the response bytes with the browser-parsed DOM; do not use script, event handlers, cookie access, or credential forms.
4. Hold route and template constant while testing numeric values, normal CSS time strings, delimiter canaries, and the same inputs on Astro `7.1.0` or later.
5. Positive evidence is attacker-controlled data terminating the generated style element and creating the inert sibling marker. A value merely appearing inside a valid CSS declaration is not enough.

Report this as **untrusted animation property -> CSS builder -> raw HTML style element -> browser parser context break**. Keep it distinct from the earlier spread-key issue: one controls object keys serialized as HTML attributes; this one controls animation values serialized through CSS into an HTML raw-text element.

## Not promoted from the same updated wave

[GHSA-c43c-rf7g-5xpg](https://github.com/advisories/GHSA-c43c-rf7g-5xpg) (Katello cross-product content-existence disclosure) and [GHSA-j4h6-gcj7-7v9v](https://github.com/advisories/GHSA-j4h6-gcj7-7v9v) (an older Decidim meeting-embed XSS record) were marked processed without standalone guidance. The available details did not add a stronger reusable workflow beyond existing object-authorization and trusted-render boundary pages.

## July 20 follow-up: decode-depth authorization mismatch

[GHSA-vj59-8hwv-xxmv](https://github.com/advisories/GHSA-vj59-8hwv-xxmv) adds a second Astro route representation bug, narrowly affecting `astro >=6.4.7,<6.4.8`. An iterative path decoder stops after ten passes and returns a partially decoded pathname to middleware; a later rewrite/router decode can still resolve that value to the protected canonical route. The exploitable application pattern is path-based authorization followed by `next(context.url)` or an equivalent rewrite path—not every Astro deployment.

Add an encoding-depth matrix to the route workflow:

1. Use a disposable protected route and make middleware emit the pathname it authorized plus a harmless decision nonce.
2. Generate nested percent-encoding depths around one character in that route, from zero through at least one step beyond the framework cap. Generate these locally rather than copying a production path.
3. For each request, record the raw request target, middleware pathname, final matched route, auth decision, and response canary. Hold identity, method, query, and body constant.
4. Include direct canonical, malformed-escape, no-rewrite, and Astro `6.4.8+` controls. Stop once the middleware and router disagree; do not retrieve protected data.

Positive evidence is **raw nested encoding -> middleware sees a partially decoded non-protected path -> later rewrite performs another decode -> the protected canary handler runs**. Distinguish this decode-depth issue from the trailing-slash NestJS case and from ordinary proxy normalization. Capture every representation at each hop so the report identifies where the extra decode occurs.

## July 20 late follow-up: adapter regex, path, spread-key, RSS, and transition contexts

Six newly published Astro records extend the same representation-first workflow:

| Advisory | Boundary to add |
| --- | --- |
| [GHSA-hp3v-mfqw-h74c](https://github.com/advisories/GHSA-hp3v-mfqw-h74c) | `@astrojs/netlify` failed to escape pathname regex metacharacters while generating the Netlify Image CDN allowlist. Add owned paths containing literal regex-significant characters and compare source matcher, generated config, and live fetch. |
| [GHSA-r557-wffq-wvrc](https://github.com/advisories/GHSA-r557-wffq-wvrc) | `@astrojs/node` trailing-slash redirect logic did not classify backslash-prefixed paths like the final router. Add raw slash/backslash and encoded-separator variants to redirect-before-middleware/auth decision tables. |
| [GHSA-f48w-9m4c-m7f5](https://github.com/advisories/GHSA-f48w-9m4c-m7f5) | `renderHTMLElement` retained an unescaped spread-attribute-name path after the earlier Astro fix. Exercise framework/component rendering paths separately; a patched helper elsewhere is not a negative control for this sink. |
| [GHSA-8j5q-mfj2-5q9q](https://github.com/advisories/GHSA-8j5q-mfj2-5q9q) | `@astrojs/rss` fields crossed into generated XML without context-safe escaping. Compare source value, raw feed bytes, strict XML parse tree, and consuming browser/feed-reader DOM with inert elements only. |
| [GHSA-7pw4-f3q4-r2p2](https://github.com/advisories/GHSA-7pw4-f3q4-r2p2) | `transition:*` directive values on hydrated islands crossed into generated HTML attributes. Keep this separate from raw `<style>` transition properties and prove only an inert parsed-DOM marker. |
| [GHSA-8mv7-9c27-98vc](https://github.com/advisories/GHSA-8mv7-9c27-98vc) | A composable `astro/hono` pipeline could omit or misorder middleware that enforces `security.checkOrigin`. Compare state-changing canary routes with middleware present, absent, and ordered around the handler. |

For the Node adapter case, use a lab route where redirect and authorization behavior are visible through nonces; test the raw request target through the same proxy topology as the deployment. Stop when a backslash representation makes the redirect layer and router disagree—do not retrieve protected content. For RSS, use a disposable feed and harmless namespaced/custom-element markers; XML text appearing verbatim is not impact unless it changes the parsed tree or the actual consumer's DOM. For both spread-key variants, trace attacker control of the **key**, not merely the value.

Report each sink precisely: **source path pattern -> generated CDN regex**, **raw separator form -> adapter redirect/auth order -> router**, **object key -> specific renderer -> HTML attribute grammar**, **feed field -> XML grammar -> consumer DOM**, **transition directive value -> island attribute -> browser DOM**, or **pipeline composition/order -> origin-check middleware absent -> inert state change accepted**. For the Hono integration, use fake sessions and a marker-only state transition from an owned foreign origin; distinguish browser request delivery from response readability. Do not merge these into a generic Astro XSS/auth-bypass claim.