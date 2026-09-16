# Angular hydration TransferState cache-poisoning boundary validation

Source: hourly offensive-security scan, 2026-06-15. Primary entry: GitHub advisory [GHSA-rgjc-h3x7-9mwg / CVE-2026-54267](https://github.com/advisories/GHSA-rgjc-h3x7-9mwg), with upstream references to the Angular advisory [GHSA-rgjc-h3x7-9mwg](https://github.com/angular/angular/security/advisories/GHSA-rgjc-h3x7-9mwg), the Angular pull request [#69064](https://github.com/angular/angular/pull/69064), and commit [`6bde84fa8e6a5770b54040fbbc9bf10d5d0386fa`](https://github.com/angular/angular/commit/6bde84fa8e6a5770b54040fbbc9bf10d5d0386fa).

This is durable for operators because it exposes a reusable browser trust boundary: predictable SSR hydration state identifiers can let attacker-controlled markup win a `document.getElementById()` race and feed forged JSON into Angular's client-side `TransferState` / HTTP transfer cache.

## What changed

| Advisory | Package | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-rgjc-h3x7-9mwg / CVE-2026-54267 | `@angular/core` | Server-rendered hydration state is recovered from a predictable DOM id such as `ng-state`; user-controlled elements with the same id can clobber the real state container before client bootstrap | Test SSR Angular apps for user-controlled `id` attributes, CMS HTML, or rich-content slots that can poison cached API responses during hydration. |

Affected ranges listed by the advisory include `@angular/core` 20.x before 20.3.25, 21.x before 21.2.17, 22.x before 22.0.1, and older lines with no patched version listed.

## Operator triage

1. **Confirm SSR plus hydration.** This workflow applies when the app uses Angular SSR and client hydration, commonly via `provideClientHydration()`. A client-only Angular SPA without serialized transfer state is not the same target.
2. **Find the state id.** Look for a JSON script element such as `<script type="application/json" id="ng-state">`. If a custom `APP_ID` is present, the state id may change to an app-specific `*-state` value.
3. **Map attacker-controlled markup before bootstrap.** Prioritize profile/CMS/rich-text/product-description/comment fields that render before Angular reads transfer state. Simple reflected text after hydration is lower signal.
4. **Target cacheable API responses, not secrets.** The proof should poison a synthetic endpoint response or lab-only API value. Do not attempt to read or forge live user secrets, tokens, payments, or private records.
5. **Require a render sink for impact.** Cache poisoning is strongest when the forged response crosses into UI trust: unsafe HTML rendering, role/config display, redirect targets, feature flags, or privileged UI decisions.

## Safe validation workflow

### Goal

Prove whether attacker-controlled DOM can replace Angular's hydration state container and cause the client to consume forged transfer-cache data.

### Preconditions

- Written authorization for the target app or a faithful lab reproduction.
- Evidence that Angular SSR hydration and transfer-state caching are enabled.
- A user-controlled markup or attribute path that can render an element before the legitimate state script is parsed or before client bootstrap reads it.
- A harmless API response key and canary payload agreed with the application owner.

### Steps

1. **Baseline the hydration state.** Capture the SSR HTML around the transfer-state script and record the exact id, script type, and representative cache keys. Redact real response bodies.
2. **Identify clobberable render points.** Search templates and rendered pages for dynamic ids such as `[id]="..."`, CMS-provided HTML attributes, markdown/rich-text HTML passthrough, or user profile fields rendered near the top of the document.
3. **Create an inert clobber element.** In the approved field, render an element with the transfer-state id and text content that is valid JSON for a disposable cache key. Keep the payload visibly synthetic, for example a `skillz_hydration_canary` string.
4. **Load a fresh SSR page.** Use a clean browser profile or disable cache. Record whether `document.getElementById('<state-id>')` resolves to the attacker-controlled element before Angular bootstrap completes.
5. **Observe transfer-cache behavior.** Trigger the client path that reads the selected API endpoint through Angular `HttpClient`. The proof is sufficient if the UI consumes the forged canary response without issuing the genuine backend request for that endpoint.
6. **Run negative controls.** Remove the clobber element, change the id, or move the element after bootstrap and confirm the real API response returns.

### Evidence to collect

- Angular package version and SSR/hydration configuration evidence.
- Redacted SSR HTML showing the legitimate transfer-state id.
- The exact synthetic clobber element and JSON canary used.
- Browser/network evidence showing cache hit versus backend request behavior.
- UI or console evidence showing only the canary value, not sensitive data.
- Negative-control evidence showing the issue disappears when the id cannot clobber the state container.

## Reporting heuristics

- Lead with the crossed boundary: **user-controlled markup/id attribute to Angular hydration state cache**.
- Separate clobberability from impact. A duplicate id is the primitive; the report needs to show what cached response or UI decision can be influenced.
- Keep claims narrow to Angular SSR hydration and `TransferState` / HTTP transfer cache behavior. Do not describe it as a generic Angular XSS unless the forged response reaches an executable sink.
- Include ordering details. The exploit depends on the attacker-controlled element being reachable by `getElementById()` when Angular reads the state.
- Use canary endpoints, canary roles, or synthetic config values. Never forge real privileges, production session details, or payment/account data.

## August 3 follow-up: raw-content serialization and transfer-cache key ambiguity

Two later Angular advisories extend this page from DOM-id clobbering to two adjacent SSR representation boundaries:

- [GHSA-vpx6-8pjr-4g3v / CVE-2026-69149](https://github.com/advisories/GHSA-vpx6-8pjr-4g3v) describes fallback raw-content elements such as `iframe`, `noembed`, `noframes`, and `noscript` whose dynamically bound text was not escaped when Angular's server-side DOM was serialized. A closing-tag sequence can therefore leave the intended text node and be reparsed as HTML by the browser.
- [GHSA-jhpw-976m-542j / CVE-2026-68945](https://github.com/advisories/GHSA-jhpw-976m-542j) describes ambiguous `HttpTransferCache` key material. A scalar parameter containing a comma and a repeated parameter whose values are joined with commas can serialize identically even though the backend treats them differently.

The listed corrected releases are `@angular/platform-server` 20.3.27, 21.2.19, and 22.0.7 for the raw-content issue, and `@angular/common` 20.3.27, 21.2.19, and 22.0.2 for the cache-key issue. Confirm the exact affected range in the advisory before testing another release line.

### Fallback raw-content serialization matrix

Use a disposable SSR application whose bound value is a synthetic marker. Block browser networking and do not use executable event handlers or scripts.

1. Render the same dynamic text inside an ordinary text element and each applicable fallback raw-content element.
2. Test plain text, a harmless closing-tag-shaped marker, encoded delimiters, mixed case, and a missing-closing-delimiter control. Change one representation at a time.
3. Capture the template value, server-side DOM text node, serialized response bytes, and browser-parsed DOM as four separate artifacts.
4. Use an inert sibling element such as `<span data-skillz-canary>` after the closing-tag marker. The bounded positive is that the sibling becomes a real DOM node only in the affected SSR serialization path.
5. Repeat on the fixed package and in a client-only render. The fixed SSR output should preserve the entire value as text, and the client-only control establishes that the issue is the server serializer rather than the template binding itself.

Do not report a literal marker in response source as XSS. Show the parser transition: **bound text -> unescaped SSR serialization -> browser reparses a harmless sibling marker outside the raw-content element**. Stop before script execution, navigation, cookie access, or privileged UI action.

### `HttpTransferCache` collision harness

The useful proof is a semantic collision, not merely two equal debug strings.

1. In a local Angular SSR fixture, create a synthetic endpoint that distinguishes a scalar comma value from repeated values and returns different non-sensitive markers.
2. Issue request A with one parameter value containing a comma and request B with two repeated values. Keep method, URL, headers, credentials mode, and every unrelated option identical.
3. Instrument the cache-key builder and backend transport. Record the structured parameter multimap, generated key, insertion order, backend request count, and response marker consumed by each caller.
4. Reverse A/B order, vary empty values and comma placement, and repeat equivalent checks for every header or option collection included in the key. Include unambiguous ordinary-value controls.
5. Require the affected build to show equal key material plus response reuse across semantically distinct requests in one SSR render. Repeat on the fixed build and require distinct keys and two backend calls.

Use only canary responses. Never place sessions, authorization headers, customer records, or role/payment data in the fixture. Report **structured request A and B -> identical transfer-cache key -> B consumes A's synthetic response**; do not infer cross-user leakage unless the application independently shares the cache across users or renders and that scope is safely proven.

## August 3 follow-up: translation metadata reaches event-handler attributes

[GHSA-jj27-h5hq-8x99 / CVE-2026-69151](https://github.com/advisories/GHSA-jj27-h5hq-8x99) adds a separate Angular compiler boundary. Standard template validation rejects bindings to event-handler attributes such as `onclick` and `onerror`, but affected i18n metadata collection accepted `i18n-on*`. A lower-trust translation artifact could then replace a benign static handler during localized compilation. The advisory lists corrected releases `@angular/compiler` / `@angular/core` 20.3.27, 21.2.19, and 22.0.1; older branches may have no patched release listed.

### Translation-to-template validation harness

Use a disposable localized application and inspect compiler output without executing browser JavaScript.

1. Inventory templates for static `on*` attributes and corresponding `i18n-on*` metadata. Also search generated translation catalogs for event-handler attribute units.
2. Build a baseline locale whose translation preserves a harmless non-executable marker such as `void 0`.
3. In a synthetic translation file, replace only that unit with a distinct inert string. Do not use script, navigation, cookie, network, or DOM-mutation payloads.
4. Capture the source template, extracted translation-unit identity, translated template/compiler intermediate form, and final generated attribute value.
5. Run controls with an ordinary translated attribute such as `title`, a static `on*` attribute without i18n metadata, a rejected standard binding to the same event property, and a corrected Angular release.
6. If browser parsing must be confirmed, use a patched DOM/event recorder that records attribute installation while suppressing handler evaluation. Stop before dispatching the event.

The bounded positive signal is **lower-trust translation unit -> `i18n-on*` metadata path -> generated event-handler attribute differs from the trusted template**. Do not call a suspicious catalog entry exploitable unless the application imports that catalog into an affected localized build, and do not execute a handler merely to prove a compiler data-flow that output inspection already establishes.

Report translation provenance explicitly: who can submit or modify catalogs, whether review/signing exists, which locales are built, and whether the resulting bundle is deployed under the application's origin. This is a build-time content-supply-chain boundary, not ordinary reflected input.

## September 16 follow-up: SSR URL-resolution trim divergence, template-boundary escaping gap, host-binding sanitizer context miss, and parent-delegated cache leak

Four September 10 `@angular/*` advisories extend the same SSR/hydration trust surface with three new reusable divergence patterns. All proofs stay lab-only with synthetic canaries; never collect real credentials, cached user responses, or production HTML.

| Advisory | Package | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-f6mr-pjwc-34m4](https://github.com/advisories/GHSA-f6mr-pjwc-34m4) / CVE-2026-88056 (high) | `@angular/platform-server` | App-level same-origin check parses with WHATWG `new URL(input, trustedOrigin)`, which keeps Unicode whitespace (`U+00A0`, `U+FEFF`) inside the path; SSR `resolveUrl` then applies `String.prototype.trim()`, which strips it, turning `%C2%A0//attacker/collect` into a cross-origin protocol-relative URL fetched server-side with the app's `Authorization`/API-key headers attached | Classic validator-vs-consumer parser differential: identical string, two parsers, different origin verdict. Test any SSR framework that trims or normalizes URLs after validation. Proof = owned no-content listener receives the request with the fake credential marker; never target internal services or relay real tokens. |
| [GHSA-v3p8-whq6-r5jg](https://github.com/advisories/GHSA-v3p8-whq6-r5jg) / CVE-2026-88060 (high) | `@angular/platform-server` | SSR serializer's ancestor walk stops at the `<template>` `DocumentFragment` boundary (`parentNode == null`), so matching fallback raw-content closing tags (`</noscript>`, `</iframe>`, `</noembed>`) inside `<template>` content inside `<noscript>`/`<iframe>` fallbacks are emitted unescaped and break out as active DOM | Interpolation the framework guarantees as safe is unsafe only in a narrow container nest. When fuzzing SSR escaping, include template-inside-fallback-raw-text positions as a distinct fixture class; harmless delimiter markers only. |
| [GHSA-hh8m-fm6v-7cvg](https://github.com/advisories/GHSA-hh8m-fm6v-7cvg) / CVE-2026-88057 (medium) | `@angular/core`, `@angular/compiler` | Security context for directive host bindings (`host: {'[attr.href]': ...}`, `@HostBinding('attr.href')`) is chosen from the declaring directive's selector, not the concrete host element; via `hostDirectives` composition, inheritance, `createComponent` custom `hostElement`, SVG/MathML namespaces, or `:not(...)` tag-neutral selectors, the sanitizer is skipped or wrong, letting `javascript:` reach the attribute | Sanitizer coverage is per compile-time selector — audit any directive applied to alternate concrete hosts (composer APIs, icon/system directives). XSS proof requires a user-controlled value reaching the affected host binding; stop at inert marker attributes. |
| [GHSA-p297-fm68-3q8c](https://github.com/advisories/GHSA-p297-fm68-3q8c) / CVE-2026-88059 (medium) | `@angular/common` | With `withRequestsMadeViaParent()`, the child `TransferCache` decides cacheability before the parent interceptor chain injects credentials; the authenticated response body is still stored into `TransferState` and can be served to anonymous visitors via CDN/proxy-shared pages | Hierarchical-delegation cache-eligibility check evaluated on the pre-auth view of the request. Two-user SSR lab with a shared cache layer; prove with a synthetic per-user canary value landing in an anonymous page's `ng-state` script, then redact. |

Affected lines: `platform-server` 22.x < 22.1.4, 21.x < 21.2.22, 20.x < 20.3.30 (88056/88060); `core`/`compiler` 22.x < 22.1.0, 21.x < 21.2.20, 20.x < 20.3.28 (88057); `common` 22.x < 22.1.1, 21.x < 21.2.20, 20.x < 20.3.28 (88059); ≤ 19.2.25 lines have no patched version for 88056/88059/88060.

Durable heuristics to reuse:

1. **Unicode-whitespace URL differential.** Any pipeline where a WHATWG parser validates and a JS `trim()`-based resolver later consumes the same string admits `U+00A0`/`U+FEFF` prefix confusion into protocol-relative URLs. Add a NBSP-prefix fixture to every SSR URL-validation matrix.
2. **Serializer ancestor-walk boundaries.** DOM features that sever parent chains (`<template>.content`, shadow roots, adopted nodes) are exactly where escaping loops stop. Fuzz each severance point against every context-sensitive closing tag.
3. **Sanitizer context ≠ declared selector.** For framework auto-sanitizers, verify the security context is resolved against the runtime host element, not the compile-time declaration; composition/inheritance APIs are the reachability lever.
4. **Cache eligibility must be evaluated post-decoration.** Any request cache that decides before interceptors mutate the request can leak authenticated bodies; test delegation chains with a parent-injected fake credential and a shared cache.

## Historical source disposition

The original June 15 scan rechecked Disclosed, PortSwigger research, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. At that time, no non-GitHub source added a higher-signal workflow. The August 3 sections above record later Angular follow-ups separately.
