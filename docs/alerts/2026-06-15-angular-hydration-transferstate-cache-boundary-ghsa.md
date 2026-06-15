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

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger research, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. No CISA, PortSwigger, Trail of Bits, ProjectDiscovery, or Disclosed update added a new higher-signal operator workflow in this run. This page promotes the newly published Angular advisory because it turns a framework-specific hydration bug into a reusable SSR cache-poisoning and DOM-clobbering validation pattern.
