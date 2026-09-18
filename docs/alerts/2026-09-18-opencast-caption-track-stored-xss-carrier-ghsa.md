# Media caption/subtitle tracks as a stored-XSS carrier (Opencast Paella player)

Source: GitHub Security Advisories published wave, 2026-09-18T13:11Z.

- [GHSA-m6c8-jcw2-5r25 / CVE-2026-77615: Opencast stored XSS in the Paella player via WebVTT/DFXP caption cue text](https://github.com/advisories/GHSA-m6c8-jcw2-5r25)

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

## Validation workflow (authorized scope only)

!!! warning "Lab instance, disposable event, inert canary"
    Use a dedicated Opencast lab you are authorized to test. Payload only an inert structural canary (e.g., `<img src=x onerror=...>` that sets `document.title` to a canary constant, or better a pure DOM marker with no network callback). Never run against a production lecture archive, and never collect real viewer sessions.

1. **Fingerprint + channel inventory (no write):** request `/search/episode.json` for a public event; record the media-package flavors present (`captions/*`, `presenter/*`, etc.) and the static URL scheme. Fetch the player bundle and grep for `innerHTML` sinks in caption/subtitle plugins.
2. **Author-tier check:** confirm the lowest role that can create an event, upload an asset with flavor `captions/source`, and publish via the `fast` workflow. Record the exact roles.
3. **Stored canary (lab event only):** upload a minimal WebVTT whose cue text is an inert marker (`<img src=x onerror="window.__canary=1">`), publish, then fetch `/search/episode.json` for that event and confirm the caption URL is listed and served verbatim to an **unauthenticated** client.
4. **Execution proof:** as an anonymous viewer, open the event, enable the caption track, and record the DOM node rendered (screenshot/DOM dump) plus the marker. Evidence = submitted bytes → stored file bytes → served bytes → live DOM node (four-stage fidelity table).
5. **Version control:** verify fixed line (19.7+ / patched paella-core) reproduces the negative control.

## Reporting checklist

- Exact Opencast release line + paella-core version, player config path proving the caption plugins are default-enabled, and the workflow that published the flavor.
- The minimum role set for the upload leg, stated explicitly (this is a low-privilege author → all-viewers escalation, not an unauthenticated XSS).
- Whether CSP / `X-Content-Type-Options` are set on the engage/player origin.
- Four-stage fidelity evidence (submitted → stored → served → DOM) with inert marker only.
- Generalize the sweep in the report body: every upload flavor and every client-side parser on the platform, not just WebVTT.

Related pages: the [Sept 17 Vendure `innerHTML`-vs-`textContent` fake sanitizer](2026-09-17-request-derived-identity-vendure-guard-composition-and-blind-ssrf-oracle-ghsa.md) (server renders attacker bytes into DOM), the [Sept 16 @nuxtjs/mdc sanitizer-miss page](2026-09-16-rmcp-oauth-resource-spoofing-mdc-sanitizer-gaps-and-vllm-route-guard-parity-ghsa.md) (sibling: attribute-name and scheme-check misses in client-side sanitizers), and the [Aug 4 Ghost fetch/upload/import boundary page](2026-08-04-ghost-fetch-upload-import-offer-boundaries-ghsa.md) (import-asset channels as sinks).
