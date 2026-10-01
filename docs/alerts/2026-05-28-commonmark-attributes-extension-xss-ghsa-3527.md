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

## October 1 follow-up: DisallowedRawHtml end-of-line tag bypass

[GHSA-97jj-33gv-5xf9](https://github.com/advisories/GHSA-97jj-33gv-5xf9) hits the *other* commonmark raw-HTML control: the `DisallowedRawHtml` extension (auto-enabled by the GFM set) escapes dangerous tag names with a regex that requires one character after the tag name (`[\s\/>]`). The block parser's `PARTIAL_HTMLBLOCKOPEN` accepts end-of-input right after the tag name, so a Markdown line ending in `<script` (no trailing character) passes through unescaped — and the next block supplies the attributes. Shipped GFM example: `<div>\n<script\n\n<span src="/evil.js">` renders so the browser reassembles `<script src="/evil.js">` with a junk `<span` attribute. `<iframe` + `<span onload="...">` works the same and needs no later `</script>`. Affected `>=1.3.0 <=2.10.1`, fixed in **2.10.2**; preconditions are `html_input: allow` (default) plus untrusted Markdown.

The durable axis, and the second time this exact filter regressed (GHSA-4v6x-c7xx-hw9f widened the same character class in 2.8.1 and still required one character): **an escape regex and a parser grammar disagree at their boundary conditions.** The parser's accept-set includes end-of-line; the escaper's match-set does not. When auditing any deny-list HTML escaper (commonmark, CMS Markdown pipelines, comment renderers):

1. Feed bare tag-prefix forms with nothing after the name: `<script`, `<iframe`, `<style`, `<textarea`, `<plaintext` as the final line, and as continuation lines inside an open HTML block.
2. Follow with a separate block that supplies event-handler or `src` attributes to complete the browser-side reassembly.
3. Confirm the browser parser terminates the tag name on newline — the newline surviving into rendered HTML is what turns the leaked `<script` into an attribute-taking open tag.
4. Diff which characters the *parser* accepts after a token versus which the *escaper's regex* accepts; every mismatch (EOF, newline, `/`, case variants) is a candidate.

Proof stays inert: tester-owned `src` callback or `console.log` marker, disposable viewer account, and a patched-version (`2.10.2`) negative control that escapes the same input.

## Reporting heuristics

- Include the affected package version, extension registration path, renderer configuration, input location, rendered HTML, output origin, CSP posture, and required victim role.
- Explain why standard Markdown hardening was insufficient: raw HTML stripping and unsafe-link blocking did not constrain attributes introduced by the Attributes extension.
- Show whether the same primitive reaches stored views, previews, exports, notifications, or third-party embeds.
- If impact depends on same-origin application APIs, describe the reachable authenticated actions or data classes without harvesting real user data.
- Keep validation scoped to authorized content and accounts; use inert markers, tester-owned callbacks, and disposable objects only.

## Notes on skipped items from this scan

- SpiceDB datastore DSN leakage in startup logs (`GHSA-jf4f-rr2c-9m58` / CVE-2026-40091) remained processed from the prior pass as credential-log hygiene already represented by existing secret-logging guidance, not a standalone Skillz operator playbook.
