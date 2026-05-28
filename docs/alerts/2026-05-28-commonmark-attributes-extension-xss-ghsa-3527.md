# league/commonmark Attributes extension XSS boundary

Source: GitHub Security Advisories REST fallback, updated 2026-05-28.

This advisory is durable because Markdown renderers are common bug-bounty surfaces, and this case shows a reusable sanitizer-order bypass: raw HTML can be stripped and unsafe links blocked, but a post-parse attributes extension can still add executable event-handler attributes to otherwise safe elements.

## What changed

- **league/commonmark Attributes extension XSS** — [GHSA-3527-qv2q-pfvx](https://github.com/advisories/GHSA-3527-qv2q-pfvx) / CVE-2025-46734: vulnerable Composer package `league/commonmark >=1.5.0 <2.7.0` lets Markdown authors attach arbitrary HTML attributes with curly-brace syntax when `AttributesExtension` is enabled. Even with `html_input: 'strip'` and `allow_unsafe_links: false`, payloads such as `![](){onerror=alert(1)}` can render as an `<img>` with an executable `onerror` handler. Version `2.7.0` blocks `on*` attributes by default, adds an explicit attribute allowlist, and makes manually added `href`/`src` attributes respect `allow_unsafe_links`.

## Operator triage

1. Search PHP/Composer inventories for `league/commonmark` versions before `2.7.0`.
2. Confirm whether `League\CommonMark\Extension\Attributes\AttributesExtension` is registered directly, through framework bundles, CMS plugins, documentation portals, ticketing/comment systems, knowledge bases, or static-site/editor preview features.
3. Identify low-trust Markdown inputs: comments, profiles, descriptions, README/import previews, support tickets, docs contributions, email templates, AI-generated reports, CMS blocks, and file uploads rendered as Markdown.
4. Record the renderer configuration: `html_input`, `allow_unsafe_links`, enabled extensions, post-render sanitizer, CSP, output origin, cache behavior, and victim roles that view rendered content.
5. Treat configurations that strip raw HTML as still testable when attributes syntax is enabled; the bypass lands after the normal raw-HTML stripping decision.

## Replayable validation boundaries

- **Safe event-attribute marker:** in an authorized test field, submit an inert image attribute payload such as `![](){onerror="console.log('skillz-commonmark-marker')"}` or a non-exfiltrating callback to a tester-owned endpoint. Expected safe result: the `onerror` attribute is removed/escaped, the element is rendered inert, or the content is isolated on a no-credential origin. Vulnerable result: the rendered HTML contains an executable `onerror` attribute in the application origin.
- **Link and source policy drift:** test whether manually added attributes can override renderer policy with benign `href`/`src` variants, including `javascript:`, `data:`, protocol-relative, empty, and mixed-case schemes. Do not use credential-stealing payloads; the proof is the policy-bypassing rendered attribute.
- **Surface propagation check:** if Markdown is cached or re-rendered asynchronously, verify whether the dangerous attribute persists into previews, public pages, notification emails, exports, search snippets, RSS feeds, or mobile/webview clients.
- **Victim-role boundary:** demonstrate impact with a disposable viewer account matching the weakest role needed to trigger rendering. For admin-only views, prove script execution with a harmless marker rather than reading privileged data.

## Reporting heuristics

- Include the affected package version, extension registration path, renderer configuration, input location, rendered HTML, output origin, CSP posture, and required victim role.
- Explain why standard Markdown hardening was insufficient: raw HTML stripping and unsafe-link blocking did not constrain attributes introduced by the Attributes extension.
- Show whether the same primitive reaches stored views, previews, exports, notifications, or third-party embeds.
- If impact depends on same-origin application APIs, describe the reachable authenticated actions or data classes without harvesting real user data.
- Keep validation scoped to authorized content and accounts; use inert markers, tester-owned callbacks, and disposable objects only.

## Notes on skipped items from this scan

- SpiceDB datastore DSN leakage in startup logs (`GHSA-jf4f-rr2c-9m58` / CVE-2026-40091) remained processed from the prior pass as credential-log hygiene already represented by existing secret-logging guidance, not a standalone Skillz operator playbook.
