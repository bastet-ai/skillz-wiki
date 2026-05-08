# App file, render, and permission-boundary batch

**Signal:** The **2026-05-08 23:15 UTC** scan added application advisories where upload endpoints, renderers, and permission APIs crossed trust boundaries in Snipe-IT, Open WebUI, Kimai, and Langchain-Chatchat.

## Advisory cluster

- **Snipe-IT upload and permission boundaries** — [GHSA-xg82-2hrv-hf64](https://github.com/advisories/GHSA-xg82-2hrv-hf64), [GHSA-hq28-crg7-95pr](https://github.com/advisories/GHSA-hq28-crg7-95pr), and [GHSA-r42m-953q-6vjx](https://github.com/advisories/GHSA-r42m-953q-6vjx): view-level users could upload files, `users.edit` could set broader permission keys, and component checkout notes rendered stored XSS. Patch to **8.4.1+**.
- **Open WebUI file, authz, and preview boundaries** — [GHSA-9pgh-j74g-qj6m](https://github.com/advisories/GHSA-9pgh-j74g-qj6m), [GHSA-4vg5-rp28-gvjf](https://github.com/advisories/GHSA-4vg5-rp28-gvjf), [GHSA-jwf8-pv5p-vhmc](https://github.com/advisories/GHSA-jwf8-pv5p-vhmc), and [GHSA-fq3v-xjjx-95rc](https://github.com/advisories/GHSA-fq3v-xjjx-95rc): older file-upload/path traversal and authorization flaws were joined by Excel preview XSS and pending-user overlay sanitizer-order XSS. Patch Open WebUI to the listed fixed releases, including **0.1.124+**, **0.8.0+**, and **0.9.0+** depending on train.
- **Kimai PDF renderer file read** — [GHSA-h5fh-7hwr-97mw](https://github.com/advisories/GHSA-h5fh-7hwr-97mw): invoice PDF templates could pass `associated_files` through Twig/mPDF and embed local worker-readable files. Patch to **2.56+**.
- **Langchain-Chatchat local-network edge cases** — [GHSA-wmvv-fhm6-w34x](https://github.com/advisories/GHSA-wmvv-fhm6-w34x) and [GHSA-x229-w2j4-h748](https://github.com/advisories/GHSA-x229-w2j4-h748): weak image hashing and TOCTOU file-upload behavior affect local-network attackers on `langchain-chatchat <=0.3.1.3`.

## Why this matters

These bugs have the same shape: UI-visible roles, sanitizer calls, and upload widgets are not the boundary. The boundary is the server-side authorization decision, final storage path, renderer sink, and exact bytes emitted into the DOM or PDF.

## Triage

1. Patch Snipe-IT, Open WebUI, and Kimai instances that expose file upload, user-admin, component checkout, invoice template, or attachment preview features.
2. Review upload APIs for “view” permissions being accepted on write endpoints, and test direct API calls rather than only UI workflows.
3. Search logs for Snipe-IT `/api/v1/*/files`, `/api/v1/users/{id}` permission changes, Open WebUI attachment uploads/previews, and Kimai invoice-template uploads by admin accounts.
4. Inspect stored HTML/Markdown/Excel-preview data for payloads that pass through `@html`, `marked`, SheetJS `sheet_to_html`, or equivalent unsafe sinks.
5. For PDF renderers, block template-controlled local file inclusion and run rendering workers with minimal filesystem read scope.

## Durable controls

- Tie every upload/write route to explicit write permission; never infer write from object visibility.
- Canonicalize and constrain final storage paths after all framework decoding.
- Sanitize after Markdown/HTML conversion, not before, and add regression tests for sanitizer order.
- Treat document preview and PDF rendering as untrusted code/data interpretation behind a sandbox and least-readable worker account.
