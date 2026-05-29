# HaxCMS saveNode event-handler sanitizer bypass

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-g2g8-95qg-v35h](https://github.com/advisories/GHSA-g2g8-95qg-v35h) / CVE-2026-48527.

This advisory is durable because it gives a reusable rich-text/CMS sanitizer bypass pattern: regex-based HTML filters that only match event-handler attributes after whitespace can miss browser-valid attributes joined directly to the previous attribute, turning normal page-edit privileges into stored same-origin script execution.

## What changed

- **HaxCMS `saveNode` stored XSS bypass** — vulnerable npm package `@haxtheweb/haxcms-nodejs <=26.0.0` accepts edited page body content through `POST /system/api/saveNode?site_token=...`. An authenticated page editor can place an event handler attribute directly after another attribute, such as `href="#"onclick="..."`, and bypass sanitizer logic that expects whitespace before `on*` attributes. Browsers still parse the joined attribute as executable JavaScript, and the payload is stored into generated page files such as `index.html`. Version `26.0.1` patches the issue.

## Operator triage

1. Search scope inventories for HaxCMS / HAX sites and npm installs of `@haxtheweb/haxcms-nodejs` at `26.0.0` or earlier.
2. Identify roles that can edit page body content, import pages, modify rich-text blocks, or reach `saveNode` with a valid `site_token`.
3. Capture how edited content is transformed: client editor normalization, `saveNode` request JSON, server-side sanitizer output, generated static files, CDN/cache layers, and final browser DOM.
4. Prioritize same-origin CMS pages viewed by admins, instructors, maintainers, or other higher-privilege users; stored XSS becomes more valuable when page editors are less privileged than page viewers.
5. Reuse the pattern against adjacent rich-text sanitizers: attributes concatenated after `href`, `src`, `title`, `class`, or custom attributes; mixed-case `on*`; entity-encoded separators; parser-normalized quotes; and component wrappers that reserialize HTML.

## Replayable validation boundaries

- **Non-destructive marker payload:** with authorization and a disposable page, modify only `node.body` to include an inert marker link such as `<a href="#"onclick="console.log('skillz-haxcms-marker')">marker</a>`. Expected safe result: the event handler is removed, escaped, or isolated away from the application origin. Vulnerable result: the generated page or live DOM preserves an executable `onclick` attribute.
- **Stored-output proof:** verify whether the payload lands in generated files, preview pages, published pages, search snippets, RSS/export output, or static deploy artifacts. The durable proof is stored HTML plus same-origin execution, not a destructive action.
- **Whitespace-differential check:** compare `href="#" onclick="..."` with `href="#"onclick="..."` to show the sanitizer/parser disagreement. Include the sanitized output for both variants in the report.
- **Viewer-role boundary:** trigger the payload only in a disposable viewer session. If the page is admin-viewed, prove code execution with `console.log`, a harmless DOM marker, or a tester-owned callback; do not read real tokens or user data.
- **Variant sweep:** test joined event handlers after other common attributes (`src`, `alt`, `title`, `class`) and across allowed elements (`a`, `img`, media/embed wrappers) to determine whether the fix needs a generic attribute parser rather than a one-off `onclick` rule.

## Reporting heuristics

- Include the package/version, affected endpoint, required editor permission, `site_token` handling context, exact `node.body` diff, sanitized server output, generated file path, and final DOM evidence.
- Explain the boundary failure as regex sanitizer drift from browser HTML parsing: the filter required whitespace before event handlers, while the browser accepted the attribute without it.
- Document whether exploitability is preview-only, published-page stored, static-file persisted, or reachable through exports/CDN caches.
- Describe the highest-impact authorized viewer role without accessing secrets. If same-origin APIs are reachable from the page, list the classes of actions/data exposed rather than harvesting them.
- Recommend a real HTML sanitizer/parser allowlist and regression tests for joined attributes, not just a narrow string replacement.

## Notes on skipped items from this scan

- CISA KEV stayed on catalog `2026.05.28`; its newest Nx Console, TanStack, Daemon Tools Lite, LiteSpeed, Drupal, Langflow, and Trend Micro entries were already reflected or previously triaged for Skillz operator value.
- PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits, and Disclosed had no new promotable offensive-operator deltas in this pass; Disclosed DNS still failed and Trail of Bits `/feed.xml` returned 404 while the previously used blog feed content remained already covered.
