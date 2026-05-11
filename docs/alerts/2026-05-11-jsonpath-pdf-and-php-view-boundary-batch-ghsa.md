# JSON path, PDF export, and PHP view-boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11 20:15 UTC.

These advisories are durable because they all involve small helper APIs that look like data plumbing but cross into interpreters: JSON path builders synthesize query syntax, Markdown-to-PDF export synthesizes HTML, and PHP view resolution maps names to include files. The safe pattern is to validate path segments, render through context-aware encoders, and keep template/file resolution on fixed server-side allowlists.

## Advisories covered

- **Kysely: JSON-path traversal injection via unsanitized path-leg metacharacters in `JSONPathBuilder.key()` / `.at()`** — [GHSA-pv5w-4p9q-p3v2](https://github.com/advisories/GHSA-pv5w-4p9q-p3v2), CVE-2026-44635 (High): npm `kysely` >= 0.26.0, < 0.28.17; fixed in `0.28.17`.
- **local-deep-research is Vulnerable to HTML Injection via Unescaped User Input in PDF Export (`pdf_service.py:_markdown_to_html`)** — [GHSA-fj2m-qvh9-jq4q](https://github.com/advisories/GHSA-fj2m-qvh9-jq4q), CVE-2026-43979 (Medium): pip `local-deep-research` < 1.6.0; fixed in `1.6.0`.
- **Yii 2: Local file inclusion via view parameter name collision** — [GHSA-5vpg-rj7q-qpw2](https://github.com/advisories/GHSA-5vpg-rj7q-qpw2), CVE-2026-39850 (High): composer `yiisoft/yii2` < 2.0.55; fixed in `2.0.55`.

## Operator triage

1. Upgrade Kysely to **0.28.17+** and audit code that passes user-controlled keys or array indexes into `JSONPathBuilder.key()` / `.at()`; do not assume query builders quote every sub-language safely.
2. Upgrade `local-deep-research` to **1.6.0+** before letting untrusted research text, URLs, or model output reach PDF export paths. Treat generated PDFs and intermediary HTML as potentially active content.
3. Upgrade Yii 2 to **2.0.55+**. Review custom controllers/actions that pass request parameters into `render()`, `renderPartial()`, view names, aliases, or include paths.
4. Add targeted tests for JSON-path metacharacters, HTML/script/CSS in Markdown export, absolute/relative PHP paths, stream wrappers, and name-collision cases where a request parameter can override a trusted view variable.

## Durable controls

- Query builders often contain nested languages. SQL escaping does not automatically make JSON path, regex, full-text query, or expression sub-languages safe.
- PDF export pipelines should sanitize at the HTML boundary and run renderers in a locked-down worker with no credentials, local-file access, metadata-service access, or internal network reachability.
- Framework view names should be constants or selected from allowlists. User input can select records, filters, or formats, but not template file paths.
- Treat LFI and HTML/PDF injection as SSRF-adjacent where renderers fetch images, stylesheets, fonts, or includes; block local, link-local, and private-network fetches.
- Review helper APIs during code review with the question: “what interpreter receives this string next?”

## Related Wisdom

- [Query and data-pipeline SQL-boundary batch](2026-05-08-query-and-data-pipeline-sql-boundary-batch-ghsa.md)
- [Agent file, SSRF, and render-boundary batch](2026-05-05-agent-file-ssrf-and-render-boundary-batch-ghsa.md)
- [PhpSpreadsheet IOFactory SSRF/RCE and row-index DoS batch](2026-04-29-phpspreadsheet-iofactory-ssrf-rce-and-row-dos-ghsa.md)
