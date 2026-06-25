# Tenant graph, i18n missing-key, and Markdown render boundary checks

Source: hourly offensive-security scan, 2026-06-25. Primary entries: GitHub Advisory Database [GHSA-wrr4-782v-jhwh](https://github.com/advisories/GHSA-wrr4-782v-jhwh), [GHSA-f49m-vf83-692w](https://github.com/advisories/GHSA-f49m-vf83-692w) / CVE-2026-48714, [GHSA-2933-q333-qg83](https://github.com/advisories/GHSA-2933-q333-qg83) / CVE-2026-48713, and [GHSA-jf6w-2mvx-633j](https://github.com/advisories/GHSA-jf6w-2mvx-633j).

These advisories are durable for operators because they expose reusable bug-hunting boundaries: authenticated tenant identity being checked but not applied to relationship queries, localization missing-key routes crossing into prototype mutation, and sanitized HTML text crossing into Markdown block parsing as trusted raw HTML.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-wrr4-782v-jhwh](https://github.com/advisories/GHSA-wrr4-782v-jhwh) | Neotoma `list_relationships` and `retrieve_graph_neighborhood` | handlers required a valid session but did not scope Supabase relationship queries with `.eq("user_id", userId)` | Test graph, relationship, activity-feed, and neighborhood APIs for **auth-present but tenant-filter-missing** patterns with two-user canaries. |
| [GHSA-f49m-vf83-692w](https://github.com/advisories/GHSA-f49m-vf83-692w) / CVE-2026-48714 | `i18next-http-middleware` `missingKeyHandler` | literal unsafe-key checks missed dotted segments such as `__proto__.polluted` before forwarding the key to a backend | Treat public missing-translation capture endpoints as write sinks into nested object paths, not harmless telemetry. |
| [GHSA-2933-q333-qg83](https://github.com/advisories/GHSA-2933-q333-qg83) / CVE-2026-48713 | `i18next-fs-backend` missing-key persistence | backend split missing-key strings on `keySeparator` and walked into `__proto__`, `constructor`, or `prototype` segments | Hunt for translation save-missing flows where user-controlled keys are persisted through nested path setters. |
| [GHSA-jf6w-2mvx-633j](https://github.com/advisories/GHSA-jf6w-2mvx-633j) | `justhtml.to_markdown()` | `<code>` text and linked `<pre>` text became inline Markdown code spans; blank lines break inline spans and let following raw HTML/Markdown be re-parsed | Add HTML-to-Markdown-to-HTML round-trip tests for code, preformatted, link, and block-boundary content. |

## Operator triage

1. **Auth checks are not tenant checks.** If a handler calls `getAuthenticatedUserId`, `current_user`, `session.user`, or equivalent but the resulting ID is not applied to every data query, prioritize two-account read proofs.
2. **Known IDs change severity.** For graph APIs, brute-forcing high-entropy entity IDs may be impractical, but leaks become reportable when IDs appear in shared links, exports, logs, notifications, browser state, or collaborator workflows.
3. **Localization endpoints are often unaudited write APIs.** Routes named `missingKey`, `saveMissing`, `locales/add`, or `i18next` may accept attacker-controlled object keys even when the visible feature is only translation fallback.
4. **Dotted keys are path traversal for objects.** Validate literal `__proto__` denial and segmented variants such as `a.__proto__.x`, `constructor.prototype.x`, custom separators, array syntax, and URL/body parser normalization.
5. **Sanitized HTML can become unsafe after format conversion.** A value that is safe as HTML text may become active markup after an HTML-to-Markdown converter emits inline constructs that a downstream Markdown renderer reparses.

## Replayable validation boundaries

### Tenant graph and relationship APIs

- Preconditions: explicit authorization, a lab or disposable tenant pair, two users, synthetic graph/entity records, and no production customer data.
- Create user A and user B. Seed each with distinct relationship edges and marker entity IDs.
- As user A, call relationship/neighborhood endpoints using only user A markers first, then a known user B marker obtained through a permitted sharing path or lab setup.
- Evidence should show request auth state, endpoint, supplied entity ID, response marker ownership, and a patched or correctly scoped negative control.
- Do not brute-force entity IDs, enumerate real tenants, or access non-synthetic relationship data.

### i18next missing-key prototype-pollution harness

- Preconditions: lab application using affected `i18next-http-middleware` and `i18next-fs-backend`, `saveMissing` or missing-key persistence enabled, and a reachable missing-key route.
- Send only inert marker keys that demonstrate nested unsafe segment handling, for example `__proto__.skillz_canary` or `constructor.prototype.skillz_canary`, and verify impact inside the same disposable process.
- Test the configured `keySeparator`; if it is not `.`, adapt the canary to the actual separator and include a benign dotted-key control such as `header.title`.
- Evidence should include package versions, handler route, backend type, request body shape, configured key separator, marker property observation, and fixed-version negative control.
- Do not poison production processes, target security-sensitive property names, crash shared services, or use prototype pollution to bypass real authorization.

### HTML-to-Markdown render round-trip harness

- Preconditions: lab renderer or explicit scope where untrusted/sanitized HTML is converted to Markdown and later rendered back to HTML.
- Seed a harmless code/preformatted value containing a blank line followed by a DOM marker such as a non-executing `<span data-skillz-canary="1">x</span>`.
- Convert through the same `to_markdown()` path and render with the target Markdown engine. Confirm whether the marker remains text or becomes raw HTML in the output DOM.
- Exercise code spans, `<pre>` inside links, nested links, and renderer configurations that allow raw HTML.
- Avoid persistent script payloads, credential-grabbing markup, or tests against real user-generated content.

## Reporting notes

- Lead with the boundary: **authenticated graph query missing tenant filter**, **missing translation key to prototype mutation**, or **sanitized code text to raw Markdown/HTML reparse**.
- Include role/auth state, affected package and version, route/function, canary values, and negative controls.
- Keep artifacts synthetic: disposable users, marker graph records, inert prototype properties, and harmless DOM markers.
