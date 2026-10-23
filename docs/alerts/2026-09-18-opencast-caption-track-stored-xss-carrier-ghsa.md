# Media client-side render sinks as stored-XSS carriers (Opencast captions, Semantic MediaWiki data-attributes)

Sources: GitHub Security Advisories published waves, 2026-09-18T13:11Z and 16:07Z.

- [GHSA-m6c8-jcw2-5r25 / CVE-2026-77615: Opencast stored XSS in the Paella player via WebVTT/DFXP caption cue text](https://github.com/advisories/GHSA-m6c8-jcw2-5r25)
- [GHSA-hg8h-557g-q8pp / CVE-2025-61682: Semantic MediaWiki stored XSS — non-reserved `data-*` wikitext attributes JSON-parsed into `innerHTML` by `ext.smw.js` (CVSS 8.6)](https://github.com/advisories/GHSA-hg8h-557g-q8pp)

The durable axis: **a media platform's "accessory" file format — captions, subtitles, transcripts, chapters — is an input channel that standard form/parameter fuzzers never touch, yet it is fetched, parsed, and rendered into the page of every viewer.** In Opencast the Paella player clears its captions container and then appends each active cue with `innerHTML += cue`, so HTML inside a WebVTT or DFXP cue becomes live DOM executing in the Opencast origin. The delivery chain is entirely default-config:

- Any media-package element with a `captions/*` flavor is served to **anonymous** viewers through the `/search/episode.json` manifest — the caption file itself is a static file returned raw.
- The "Subtitles" upload option (`captions/source`, `.vtt`) is active by default, the WebVTT/DFXP caption plugins are `enabled: true` in the default player config, and the `fast` workflow publishes caption flavors to the engage player.
- The processing step (`fast` workflow's caption processing) cuts and tags the file but **never sanitizes** cue text. No CSP, no `X-Content-Type-Options`.
- Minimal author role required: `ROLE_API_EVENTS_CREATE` + `ROLE_API_EVENTS_TRACK_EDIT` + `ROLE_UI_TASKS_CREATE` — no `ROLE_ADMIN`. Every viewer who enables captions (anonymous or authenticated staff) executes the payload.

## Why this is worth an operator pattern

- **Auxiliary-asset formats are first-class XSS surfaces.** WebVTT/DFXP cues, SRT, transcript text, chapter markers, playlist metadata, cover-art EXIF, and player config JSON all flow "upload → workflow → CDN/static serve → client-side render." None of them appear when you fuzz HTML form fields, comment boxes, or URL parameters. When inventorying a media/CMS/LMS/telehealth-video target, enumerate every upload flavor or attachment type (not just the obvious document/image slots) and ask separately for each: *is the parsed output HTML-escaped before the render sink?*
- **The "renderer, not parser" bug class.** A server-side validator never sees the payload; the client-side plugin pastes raw parsed text into `innerHTML`. Client-side renderers in bundled player JS (`/paellaN/ui/paella-player.js`-style chunks) are readable, reviewable attack surface — fetch them and grep for `innerHTML +=`, `document.write`, and template sinks fed by track parsers.
- **Default-config proof raises severity.** The advisory's evidence shape is the one to reproduce: default config + non-admin role + anonymous execution. "No non-default flag required" is what turns a niche XSS report into a platform-wide finding.
- **The manifest is the recon primitive.** `/search/episode.json` exposes media-package element flavors and static file URLs anonymously — a free index of every publishable asset channel on the instance.

## Semantic MediaWiki: wikitext-authored `data-*` attributes as a client-side JSON→innerHTML sink

The 16:07Z advisory adds the second carrier shape: **front-end JS that reads `element.dataset.*`, `JSON.parse`s the value, and concatenates the result into `innerHTML` turns any markup syntax that allows arbitrary attributes into an XSS channel — even when the markup sanitizer itself is perfect.**

In Semantic MediaWiki, `res/smw/ext.smw.js` iterates every element with class `smw-subtab` and does `element.innerHTML += JSON.parse(element.dataset.subtab)` (lines ~37–42 of the linked blob). The wikitext sanitizer escapes `data-` attributes for its own *reserved* names only — everything else (`data-subtab` and any unregistered name) survives into the rendered page. The payload needs no angle brackets in the stored markup at all:

```html
{{#tag:div|
|class=smw-subtab
|data-subtab=""<img src='' onerror=alert(1)>""
}}
```

`&quot;` entities are re-decoded by `.dataset`, the attribute value is valid JSON (a quoted string), and `innerHTML +=` of that string executes. Any user with the plain `edit` right gets stored execution against every reader of the page.

Operator generalization (applies to any wiki, CMS, or forum with a markup-to-HTML pipeline plus bundled JS):

1. **Grep the front-end bundle for the `dataset` → parse → `innerHTML` chain.** Fetch the site's own JS and search for `.dataset`, `getAttribute("data-`, `JSON.parse(`, and `innerHTML`. Each hit is a candidate sink whose *input* is any attacker-writable attribute in the markup layer.
2. **Enumerate the sanitizer's reserved-attribute allowlist.** Sanitizers commonly strip only the names they themselves use (`data-mw-*`, `data-smw-*`, etc.). Test an *unregistered* `data-` name on an element the markup syntax lets you annotate (here `{{#tag:div}}`; equivalently raw-HTML extensions, macros, or `{: ...}` attribute syntaxes). The positive control: your unregistered attribute appears verbatim in the served HTML.
3. **Quote-state craft for JSON-parsed attributes.** wikitext/Markdown will HTML-encode `"` on the way out; `.dataset` decodes it back, so a value that *looks* entity-mangled in view-source is still attacker-controlled JSON. Double-quote wrapping (`""<img …>""`) keeps the outer quotes as JSON string delimiters after decoding.
4. **Class boundary:** this is low-privilege editor → all-readers stored XSS in the wiki origin, same escalation shape as the Opencast author→viewer chain; report the minimum edit right, not "any user."


## Validation workflow (authorized scope only)

!!! warning "Lab instance, disposable event, inert canary"
    Use a dedicated Opencast lab you are authorized to test. Payload only an inert structural canary (e.g., `<img src=x onerror=...>` that sets `document.title` to a canary constant, or better a pure DOM marker with no network callback). Never run against a production lecture archive, and never collect real viewer sessions.

1. **Fingerprint + channel inventory (no write):** request `/search/episode.json` for a public event; record the media-package flavors present (`captions/*`, `presenter/*`, etc.) and the static URL scheme. Fetch the player bundle and grep for `innerHTML` sinks in caption/subtitle plugins.
2. **Author-tier check:** confirm the lowest role that can create an event, upload an asset with flavor `captions/source`, and publish via the `fast` workflow. Record the exact roles.
3. **Stored canary (lab event only):** upload a minimal WebVTT whose cue text is an inert marker (`<img src=x onerror="window.__canary=1">`), publish, then fetch `/search/episode.json` for that event and confirm the caption URL is listed and served verbatim to an **unauthenticated** client.
4. **Execution proof:** as an anonymous viewer, open the event, enable the caption track, and record the DOM node rendered (screenshot/DOM dump) plus the marker. Evidence = submitted bytes → stored file bytes → served bytes → live DOM node (four-stage fidelity table).
5. **Version control:** verify fixed line (19.7+ / patched paella-core) reproduces the negative control.

Wiki-side variant (SMW or any markup platform, lab wiki only):

1. Fetch the site's bundled JS and grep for `dataset`/`JSON.parse`/`innerHTML` chains fed by `data-*` attributes; note the trigger class names.
2. With the lowest edit right, create a disposable page using the platform's attribute-annotating syntax (`{{#tag:...}}`, raw-HTML extension, or macro) with an **unregistered** `data-` name carrying an inert JSON-encoded DOM marker.
3. Verify the attribute survives in the served HTML verbatim (sanitizer miss), then verify the marker node appears in the rendered DOM without any admin action (client-side sink confirmed).
4. Negative control: the reserved `data-` names the sanitizer strips, plus a patched-version render.

## Reporting checklist

- Exact Opencast release line + paella-core version, player config path proving the caption plugins are default-enabled, and the workflow that published the flavor.
- The minimum role set for the upload leg, stated explicitly (this is a low-privilege author → all-viewers escalation, not an unauthenticated XSS).
- Whether CSP / `X-Content-Type-Options` are set on the engage/player origin.
- Four-stage fidelity evidence (submitted → stored → served → DOM) with inert marker only.
- Generalize the sweep in the report body: every upload flavor and every client-side parser on the platform, not just WebVTT.

## October 23 follow-up: VertiGIS WebOrderSystem — "self-XSS" that a business workflow relays to privileged victims

Three VertiGIS advisories published 2026-10-23T09:31Z (all v7.0.8.6, vendor silent on earlier bands) add the relay shape to this page's carrier theme:

- [GHSA-636r-rhx8-pwmx / CVE-2026-4952: the ASMobile "business reference" free-text field is self-XSS in isolation — but the value is copied into order details and executed in the OrderAdministration portal (AuftragsManager) the moment a highly privileged user opens the order](https://github.com/advisories/GHSA-636r-rhx8-pwmx)
- [GHSA-4jx9-cq4x-76w5 / CVE-2026-4951: `searchValue` URL parameter reflected XSS in the CustomerAdministration portal; because admin users can change any other user's password **without entering the old one**, one click from a privileged session = account takeover/lockout of any account including admins](https://github.com/advisories/GHSA-4jx9-cq4x-76w5)
- [GHSA-g5vv-w6m9-qrh6 / CVE-2026-4950: stored XSS via the `secondName` user property rendered in other privileged users' portals](https://github.com/advisories/GHSA-g5vv-w6m9-qrh6)

Operator rules:

1. **Downgrade "self-XSS" only after tracing the field through every downstream render.** The triage-reflex dismissal ("only affects the entering user") dies the moment a workflow copies the field into a view a *different* role opens. Sweep: for every free-text field a low-privilege portal accepts, enumerate which reports, order/queue views, admin consoles, or notification emails render it. The trigger is passive (victim opens the record), so no lure beyond normal business volume is needed.
2. **Price the XSS by the victim portal's worst capability, not by the script tag.** Here the admin portal's old-password-free password change turns reflected XSS into full ATO — map the victim's session capabilities (password reset, role edit, export) before writing severity into the report.
3. **URL-carried reflected sinks in admin portals are phishing-ready primitives** (`searchValue` executes on page open); pair with the URL structure published in the advisory itself.

## October 23 follow-up 2: CGM CLININET medical-platform wave — see the dedicated page

The same 09:31Z sweep carried the twelve-GHSA CGM CLININET wave, promoted as its own page: [CGM CLININET coordinated wave — dynamic module-import RCE, root HL7 listeners, adjacent-network trust map](2026-10-23-cgm-clininet-coordinated-wave-dynamic-module-import-root-listeners-and-adjacent-network-trust-map-ghsa.md).

Related pages: [Opencast caption-track stored XSS and the SMW `data-*` sink](#media-client-side-render-sinks-as-stored-xss-carriers-opencast-captions-semantic-mediawiki-data-attributes) (top of this page), the [Sept 17 Vendure `innerHTML`-vs-`textContent` fake sanitizer](2026-09-17-request-derived-identity-vendure-guard-composition-and-blind-ssrf-oracle-ghsa.md) (server renders attacker bytes into DOM), the [Sept 16 @nuxtjs/mdc sanitizer-miss page](2026-09-16-rmcp-oauth-resource-spoofing-mdc-sanitizer-gaps-and-vllm-route-guard-parity-ghsa.md) (sibling: attribute-name and scheme-check misses in client-side sanitizers), and the [Aug 4 Ghost fetch/upload/import boundary page](2026-08-04-ghost-fetch-upload-import-offer-boundaries-ghsa.md) (import-asset channels as sinks).
