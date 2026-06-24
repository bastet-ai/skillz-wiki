# beets metadata-to-web-UI DOM boundary checks

Source: GitHub Advisory Database [GHSA-3gxm-wfjx-m847](https://github.com/advisories/GHSA-3gxm-wfjx-m847) / CVE-2026-42052, originally published 2026-04-29 and refreshed during the 2026-06-24 hourly offensive-security scan.

This beets advisory is durable for operators because it captures a reusable pattern: attacker-controlled media metadata crosses from local library ingestion into a browser-based admin UI through raw client-side template interpolation and `.html(...)` DOM insertion. Validate only in owned labs or explicitly scoped desktop/server deployments; keep proofs to harmless metadata canaries.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-3gxm-wfjx-m847](https://github.com/advisories/GHSA-3gxm-wfjx-m847) / CVE-2026-42052 | `beetsplug/web` templates and JavaScript view rendering | Metadata fields such as title, lyrics, or comments are rendered through raw Underscore interpolation and inserted into the web UI with `.html(...)` | Add media/tag metadata to the list of user-controlled render sources when testing local web UIs, library managers, and self-hosted admin dashboards. |

Affected package: PyPI `beets` before `2.10.0`.

## Operator triage

1. **Confirm the web UI is in scope.** Identify whether `beetsplug.web` or an equivalent library-management web front end is enabled, reachable, and used by a privileged operator.
2. **Map metadata ingestion paths.** Prioritize imports from shared folders, uploaded music, automated downloaders, podcast feeds, or any workflow where another user can influence tags.
3. **Trace source to sink.** Look for metadata fields reaching template expressions, Markdown/render helpers, preview cards, search results, playlist views, or detail panes.
4. **Differentiate text rendering from HTML insertion.** A safe page may render metadata with text nodes; a risky page combines raw interpolation with `.html()`, `innerHTML`, or HTML-capable component props.
5. **Use canary-only evidence.** Prove DOM execution or markup insertion with inert markers under a disposable album/track, not with credential theft, filesystem access, or persistence payloads.

## Replayable validation boundary

### Media metadata to DOM

- Preconditions: disposable beets library, affected or lab-pinned version, enabled web plugin, and a test browser session dedicated to the assessment.
- Create or import a synthetic media file whose metadata fields contain a benign HTML marker, for example an unmistakable `<b data-skillz="metadata-canary">...` style canary or a non-exfiltrating alert marker if explicitly allowed.
- Browse to views that render track, album, lyrics, comments, or search-result metadata.
- Positive evidence: screenshot or response capture showing the canary interpreted as markup/script in the web UI, plus the exact metadata field and UI route that rendered it.
- Negative control: repeat on a patched build or with escaping enabled and show the canary rendered as literal text.
- Do not target real operator libraries, collect browser storage, read local files, or use payloads that persist beyond the synthetic test item.

## Hunt expansion

Apply the same workflow to adjacent products:

- music, photo, ebook, document, and media-server dashboards that preview imported metadata;
- admin UIs that use Underscore/Lodash/Mustache-like client templates;
- search/autocomplete views that render titles and comments differently from detail pages;
- plugin ecosystems where importers normalize metadata but web plugins render raw fields later.

Look especially for parser mismatches: one component treats tags as plain text, while a later UI treats them as trusted HTML.

## Reporting notes

- Lead with the exact boundary: **imported media metadata reaches raw client-side template output and HTML insertion**.
- Include product/version, web-plugin exposure, import path, affected metadata field, rendered UI route, source-to-sink evidence, and patched/escaped negative control if available.
- Keep all artifacts synthetic: disposable media files, harmless metadata markers, and lab-only browser sessions.
