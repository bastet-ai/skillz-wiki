# Svelte SSR spread and DOM-clobbering boundary checks

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-pr6f-5x2q-rwfp](https://github.com/advisories/GHSA-pr6f-5x2q-rwfp) / CVE-2026-42599 and [GHSA-rcqx-6q8c-2c42](https://github.com/advisories/GHSA-rcqx-6q8c-2c42) / CVE-2026-42573 for Svelte.

This page is durable because it captures a recurring front-end trust boundary: framework attribute spreading turns object keys into HTML/DOM behavior. Bug hunters should look for places where user-shaped objects become element attributes, form names, or dynamic tag names before hydration or client-side state initialization is complete.

## What changed

- **SSR spread attributes can render event handlers** — Svelte `<= 5.55.6` can include event-handler properties in server-rendered HTML when an application spreads user-controlled or external data as element attributes. The advisory notes the browser must have JavaScript enabled and the event must fire before hydration reaches the vulnerable element.
- **DOM clobbering can corrupt Svelte internal state** — Svelte `<= 5.55.6` is affected when a form element uses attribute spreading, an input or button inside that form has a spread or dynamic `name` attribute, and both values are user-controllable.
- **Adjacent parser issues are useful triage signals** — Svelte `5.51.5` through `5.55.6` also has a ReDoS issue in `<svelte:element this={tag}>` when tag names are unconstrained, and `devalue` `5.6.3` through `5.8.0` has sparse-array memory pressure during `devalue.parse`. Treat these as supporting review leads, not standalone production stress tests.
- **Fixed versions** — Svelte fixes the spread, DOM-clobbering, and dynamic-tag validation issues in `5.55.7`; `devalue` fixes sparse-array parsing in `5.8.1`.

## Operator triage

1. **Find SvelteKit/Svelte SSR surfaces:** identify apps that render Svelte on the server and accept profile fields, CMS blocks, personalization config, theme settings, form-builder schemas, or component props from tenants or users.
2. **Search for attribute spreading:** review `*.svelte` files for `{...`, especially on `<form>`, `<input>`, `<button>`, `<a>`, rich-content components, design-system wrappers, and components that pass `$$restProps` or external prop bags to DOM elements.
3. **Trace object-key control:** determine whether attackers can control attribute names, not only values. Keys such as event-handler attributes, `name`, `id`, `form`, `slot`, and ARIA/data attributes often reveal whether a spread is structurally trusted.
4. **Prioritize pre-hydration interactions:** event-handler spread findings are strongest when the injected element is visible and can be clicked, focused, errored, loaded, or otherwise triggered before hydration replaces or sanitizes it.
5. **Check form clobbering preconditions together:** the DOM-clobbering path needs both a controllable form spread and a controllable nested input/button `name` or spread. A single controllable value is weaker than a matched parent/child chain.
6. **Review dynamic element tags separately:** flag `<svelte:element this={tag}>` only when untrusted tag strings can be long or unconstrained; an allowlisted tag set is not the same finding.

## Replayable validation boundaries

- Use a local or staging Svelte fixture. Do not inject JavaScript into production users' pages or rely on real victim interaction.
- For SSR spread validation, capture the rendered HTML response and show that an attacker-controlled object key becomes an event-handler attribute. Use an inert marker such as `data-skillz-canary` plus a harmless handler in a lab page; avoid callbacks to third-party collectors.
- For pre-hydration validation, slow or pause hydration in the lab fixture and show the event can fire before the client runtime removes or normalizes the attribute. Keep the proof to a local browser console marker.
- For DOM clobbering, build a minimal form/input fixture and demonstrate that attacker-controlled `name` or spread keys alter the framework state path described by the advisory. Do not attempt account takeover or data theft on live applications.
- For dynamic-tag ReDoS or `devalue.parse`, validate only with bounded, synthetic payloads under local resource limits. Do not run memory or CPU pressure tests against shared services.

## Reporting heuristics

- Lead with the **object-to-attribute trust boundary**: user-controlled object keys are rendered as executable or state-changing DOM attributes.
- Include the exact component path, Svelte version, SSR/hydration behavior, the object source, and the final rendered HTML or DOM snapshot.
- State all preconditions: Svelte `<= 5.55.6`, SSR or vulnerable DOM state, user-controlled spread keys, and whether interaction before hydration is required.
- Separate XSS evidence from availability-only parser evidence. A strong report proves controllable attribute rendering or DOM clobbering without stressing production resources.
- Recommend allowlisting attribute names at the component boundary and mapping user data to typed props before spreading into DOM elements.

## October 7 follow-up: Quasar SSR `getHead()` meta serializer interpolates raw template strings — the client path auto-escapes, the SSR path escapes nothing (CVE-2026-106102 / [GHSA-pq96-jpmf-w254](https://github.com/advisories/GHSA-pq96-jpmf-w254), critical, fixed quasar 2.22.0)

Quasar's SSR-only serializer `getHead()` (Meta plugin) turns every `useMeta()` call into a literal HTML string with plain template-literal interpolation — zero entity escaping, zero attribute-quote escaping — and `injectServerMeta()` concatenates it verbatim into the raw HTTP `<head>`. The browser-side twin `apply()` builds the same tags with `document.createElement` + `setAttribute`, which the DOM escapes automatically. Any app-supplied meta/title/link data that is user-shaped (page title from a record, OG tags from user content) becomes **pre-hydration stored/reflected XSS in the raw response head**.

Durable axes for every SSR framework, not just Quasar:

1. **Two renderers, one trust assumption.** XSS escaping in an SSR product is a *per-render-path* property: the hydration/client path inherits DOM escaping for free, the string-concatenation SSR path has to re-implement it and frequently doesn't. This is the exact shape of this page's core lesson (spread attributes rendered raw server-side, DOM API safe client-side) reappearing in a different framework — audit every head/meta/OG serializer separately from the body renderer.
2. **Fingerprint externally:** request a page whose title/meta derives from user content, and read the **raw HTTP response** (curl, not DevTools post-hydration DOM) looking for unescaped `"`/`<` in `<title>`/`<meta>` — the pre-hydration markup is the evidence; the post-hydration DOM will look clean because `apply()` rebuilds the tags safely.
3. Same wave, adjacent SSR axes worth triage not promotion: `Platform.parseSSR()` feeds the raw unbounded `User-Agent` header through a cubic-backtracking regex chain on **every** SSR render (auto-installed plugin, one 16 KB header ≈ 35 s event-loop stall — one-request-per-connection DoS shape, DoS class per repo precedent but the *auto-installed-plugin-parses-header* reachability note is the reusable bit); Icon Genie `--profile` JSON `folder`/`name` joined into write paths with only `Joi.string().min(1)` (config-file traversal, trusted-input class); SSG `getSsgPages()` custom `dir`/`filename` written without dist-dir containment + `build.distDir` removed recursively unchecked pre-build (build-config destructive-safety class).

## October 7 second Quasar wave: dev error page dumps `process.env` on a 0.0.0.0 bind, and its `</script>` guard is spelling-based (CVE-2026-106106 / [GHSA-r5mf-4r5x-q78f](https://github.com/advisories/GHSA-r5mf-4r5x-q78f), plus 106105/106107/106108/106109/106104; dev-server legs fixed app-vite 3.3.0)

The `getHead()` fold above covered production SSR escaping. The second wave hits the **dev** render path with two compounding mistakes worth a standing probe:

1. **Dev error page = unauthenticated env dump.** `renderSSRError()` splices `{Request, Headers, Cookies, 'Shell environment variables': process.env}` as a JSON blob into the page on *any* SSR/SSG render exception, and Quasar overrides Vite's `localhost` default with `devServer.host = '0.0.0.0'` — one unauthenticated GET from any reachable host yields cloud keys, registry tokens, DB URLs. Operator rule: for any dev-server product, **force a render exception (garbage route param, malformed data) from an external interface and check whether the error page serializes env/headers/cookies**; treat every exposed dev port on a scan as a credential target, not a fingerprint toy. Fingerprint: GET the dev port with a request shape that throws, grep response for `Shell environment variables` / `AWS_`/`DATABASE_URL` keys.
2. **Spelling-based rawtext guard loses to the tokenizer.** The escape is `JSON.stringify(data).replaceAll('</script>', '<\\/script>')` — exact-string, case-sensitive, requires literal `>`. The HTML tokenizer closes script rawtext on `</` + case-insensitive `script` + any of tab/LF/FF/space/`/`/`>`, so `</SCRIPT>`, `</script >`, `</script/>` all break out and execute in the dev-server origin; cookies are additionally `decodeURIComponent`-ed first, so percent-encoded payloads decode into working markup. This is the same tokenizer-vs-string-match asymmetry as the Oct 6 Joomla data-URI whitespace-injection leg: **`replaceAll` with a string pattern is a deny-list of spellings; the browser parser accepts a grammar.** The codebase's own `Meta.js protectRawText()` already uses the correct case-insensitive `</tagname`-prefix regex — grep-hardened-sibling rule applies: when the fix pattern exists elsewhere in the repo, the vulnerable path skipped it. Probe battery for any rawtext injection point: `</SCRIPT>`, `</ScRiPt>`, `</script >`, `</script/>`, percent-encoded forms.
3. Remaining wave legs triage-class only: dev TLS keys cached world-readable (106105, local-file class), SSR/SSG nonce attributes unconstrained (106107, CSP-attr class), SSG output paths escaping dist dir + unchecked recursive `distDir` cleanup (106108/106109, build-config destructive class, same shape as the 106103 Icon Genie note above), and the `User-Agent` cubic-backtracking SSR stall (106104) already noted in the prior section.
