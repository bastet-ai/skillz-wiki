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
