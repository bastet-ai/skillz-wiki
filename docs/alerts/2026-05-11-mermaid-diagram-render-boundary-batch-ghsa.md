# Mermaid diagram render-boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11 20:15 UTC.

This batch is durable because Mermaid is often embedded in Markdown previewers, documentation sites, ticketing systems, notebooks, and AI-generated reports. Diagram source is frequently treated as plain text, but the renderer produces HTML/SVG/CSS and can therefore become a browser-code boundary or resource-exhaustion boundary.

## Advisories covered

- **Mermaid: Improper sanitization of configuration leads to CSS injection** — [GHSA-87f9-hvmw-gh4p](https://github.com/advisories/GHSA-87f9-hvmw-gh4p), CVE-2026-41159 (Medium): npm `mermaid` >= 11.0.0-alpha.1, <= 11.14.0; fixed in `11.15.0`; npm `mermaid` <= 10.9.5; fixed in `10.9.6`.
- **Mermaid Gantt Charts are vulnerable to an Infinite Loop DoS** — [GHSA-6m6c-36f7-fhxh](https://github.com/advisories/GHSA-6m6c-36f7-fhxh), CVE-2026-41150 (Medium): npm `mermaid` >= 11.0.0-alpha.1, <= 11.14.0; fixed in `11.15.0`; npm `mermaid` <= 10.9.5; fixed in `10.9.6`.
- **Mermaid: Improper sanitization of `classDef` in state diagrams leads to HTML injection** — [GHSA-ghcm-xqfw-q4vr](https://github.com/advisories/GHSA-ghcm-xqfw-q4vr), CVE-2026-41149 (Medium): npm `mermaid` >= 11.0.0-alpha.1, <= 11.14.0; fixed in `11.15.0`; npm `mermaid` <= 10.9.5; fixed in `10.9.6`.
- **Mermaid: Improper sanitization of `classDefs` in diagrams leads to CSS injection** — [GHSA-xcj9-5m2h-648r](https://github.com/advisories/GHSA-xcj9-5m2h-648r), CVE-2026-41148 (Medium): npm `mermaid` >= 11.0.0-alpha.1, <= 11.14.0; fixed in `11.15.0`; npm `mermaid` <= 10.9.5; fixed in `10.9.6`.

## Operator triage

1. Upgrade Mermaid to **11.15.0+** or **10.9.6+** depending on the maintained line used by the host application.
2. Inventory every place users can submit Mermaid diagrams: Markdown comments, README previews, docs portals, notebooks, dashboards, chat transcripts, issue trackers, and static-site build pipelines.
3. For public or multi-tenant renderers, re-render or purge cached SVG/HTML generated from untrusted diagram input before the patch; cached output may preserve injected CSS/HTML.
4. Put diagram rendering behind resource limits. The Gantt infinite-loop issue means preview services need CPU timeouts, worker isolation, and queue backpressure even after parser bugs are patched.

## Durable controls

- Treat diagram languages as active render languages. Their configuration blocks, `classDef`/`classDefs`, labels, links, styles, and directives must be sanitized before output reaches the browser.
- Prefer sandboxed rendering: isolated origin, strict CSP, no ambient cookies/tokens, `iframe sandbox`, and no direct DOM insertion into privileged application pages.
- Disable or constrain Mermaid configuration from untrusted authors. Trusted site-wide config should be separate from per-document diagram text.
- Add regression tests for CSS/HTML delimiter injection and pathological diagrams, not just ordinary diagram syntax.
- AI/documentation systems that render generated diagrams should treat model output as untrusted user content; never render it in an authenticated same-origin control plane.

## Related Wisdom

- [Lobe Chat Mermaid XSS to RCE](2026-02-05-lobe-chat-mermaid-xss-rce-ghsa-4gpc-rhpj-9443.md)
- [Render, Markdown, and preview-boundary batch](2026-05-09-render-markdown-and-preview-boundary-batch-ghsa.md)
- [Protocol, client, render, and resource-boundary batch](2026-05-08-protocol-client-render-and-resource-boundary-batch-ghsa.md)
