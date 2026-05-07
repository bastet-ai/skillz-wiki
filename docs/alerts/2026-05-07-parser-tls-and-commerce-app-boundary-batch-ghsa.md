# Parser, TLS, and commerce-app boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-07** batch where parsers, remote asset fetchers, and commerce/CRM apps crossed resource, transport, and file/render boundaries.

## Advisories covered

- **go-ipld-prime DAG-CBOR/DAG-JSON unbounded recursion** — [GHSA-w239-58x2-q8p5](https://github.com/advisories/GHSA-w239-58x2-q8p5): content-addressed parsers still need structural depth and allocation budgets.
- **CSS Parser remote CSS MITM injection via improper certificate validation** — [GHSA-ff6c-w6qf-7xqc](https://github.com/advisories/GHSA-ff6c-w6qf-7xqc): remote stylesheet fetchers must validate TLS before treating fetched content as trusted input.
- **rust-zserio unbounded memory allocation** — [GHSA-fpf5-4jw8-67x8](https://github.com/advisories/GHSA-fpf5-4jw8-67x8): binary/schema decoders need declared-size caps and streaming limits.
- **Shopizer XSS and path traversal** — [GHSA-fqcw-2xhj-p63g](https://github.com/advisories/GHSA-fqcw-2xhj-p63g), [GHSA-f5w4-7ccj-5m75](https://github.com/advisories/GHSA-f5w4-7ccj-5m75): commerce admin and storefront paths need output encoding plus canonical file containment.
- **Krayin CRM compose-email RCE** — [GHSA-32px-ccfx-cxq3](https://github.com/advisories/GHSA-32px-ccfx-cxq3): email composition/rendering features can become code execution surfaces when templates or attachments are interpreted.
- **Gotenberg file:// read under `/tmp`** — [GHSA-g924-cjx7-2rjw](https://github.com/advisories/GHSA-g924-cjx7-2rjw): Chromium conversion routes must deny local schemes and isolate temp files per job.

## Why this is durable

Untrusted content does not become safe because it is “just data,” “just CSS,” “just an email,” or “just a temporary file.” Parsers, fetchers, renderers, and converters need independent budgets and trust decisions.

## Immediate triage

1. Patch go-ipld-prime, CSS Parser, rust-zserio, Shopizer, Krayin CRM, and Gotenberg if present.
2. Add recursion, declared-length, decompression, and total-allocation tests for IPLD and zserio inputs.
3. Disable remote CSS imports or require strict TLS validation and trusted origins before fetch/use.
4. Hunt commerce/CRM logs for traversal markers, stored script payloads, suspicious email-template content, and unexpected attachment handling.
5. For Gotenberg, isolate temp directories by job and block `file://` in URL conversion routes.

## Durable controls

- Give every parser explicit max depth, max nodes, max bytes, and timeout budgets.
- Treat TLS validation failures as hard stops for remote assets that influence rendering or policy.
- Canonicalize filesystem paths after decoding and symlink resolution; enforce immutable roots.
- Render email and commerce content through sandboxed, non-code template engines with strict allowlists.
- Use per-request temp directories and deny local-file schemes in browser/conversion workers.
