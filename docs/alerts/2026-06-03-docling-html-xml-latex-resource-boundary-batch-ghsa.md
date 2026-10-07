# Docling HTML, XML, LaTeX, and resource-fetch boundaries

**Sources:** [GHSA-pj2v-ggqh-cmq2 / CVE-2026-44016](https://github.com/advisories/GHSA-pj2v-ggqh-cmq2), [GHSA-r3xg-rg9j-67fv / CVE-2026-44018](https://github.com/advisories/GHSA-r3xg-rg9j-67fv), [GHSA-m88r-rg27-5xfg / CVE-2026-44020](https://github.com/advisories/GHSA-m88r-rg27-5xfg), [GHSA-2j5p-7p5m-cvqr / CVE-2026-44022](https://github.com/advisories/GHSA-2j5p-7p5m-cvqr), [GHSA-q29v-xc37-wh5m / CVE-2026-47214](https://github.com/advisories/GHSA-q29v-xc37-wh5m), [GHSA-j5xp-7m2f-49jv / CVE-2026-44019](https://github.com/advisories/GHSA-j5xp-7m2f-49jv), [Docling EasyOCR ZIP extraction note](2026-06-03-docling-easyocr-model-zip-slip-boundary-ghsa.md)  
**Affected packages:** PyPI `docling` ranges from `>= 2.13.0` through `< 2.94.0` depending on backend, and `docling-core` `>= 2.5.0, < 2.74.1` for image reference handling.  
**Operator value:** repeatable validation of document-conversion pipelines where untrusted documents can trigger browser rendering, URI fetches, XML parsing, archive expansion, LaTeX includes, or inline image decoding.

## Why this matters

Docling is commonly used in AI, RAG, OCR, and document-ingestion pipelines. The June 3, 2026 GHSA batch shows the same durable pattern across multiple backends: document conversion is not a passive parse. It can become a browser, URI fetcher, XML parser, archive extractor, LaTeX resolver, and image decoder.

For bug bounty and red-team work, prioritize environments where untrusted users can submit documents that are converted server-side and where converted output or processing side effects are observable:

- RAG ingestion services that accept HTML, XML, LaTeX, PDF-derived assets, patent documents, or METS-GBS archives;
- internal knowledge-base importers and AI agents that call Docling against uploaded files;
- document conversion workers with network access to cloud metadata, internal admin panels, object stores, or localhost services;
- pipelines where converted Markdown/JSON/output is returned to the user or indexed into a searchable corpus;
- workers running with broad filesystem read/write permissions or without CPU, memory, and network isolation.

## Advisory-to-boundary map

| Boundary | Advisory | Affected surface | Operator test idea |
| --- | --- | --- | --- |
| Playwright HTML rendering | [GHSA-pj2v-ggqh-cmq2](https://github.com/advisories/GHSA-pj2v-ggqh-cmq2) | `docling` `>= 2.82.0, < 2.91.0` with HTML rendering explicitly enabled | In a lab, submit HTML that tries to execute an inert script canary or fetch a controlled URL; patched behavior should disable JavaScript and isolate network fetches when remote fetch is off. |
| METS-GBS archive/XML parsing | [GHSA-r3xg-rg9j-67fv](https://github.com/advisories/GHSA-r3xg-rg9j-67fv) | `docling` `>= 2.45.0, < 2.91.0` | Use a tiny controlled archive/XML canary to test XXE blocking and archive member/size limits; avoid zip bombs or large payloads. |
| USPTO patent XML XXE | [GHSA-m88r-rg27-5xfg](https://github.com/advisories/GHSA-m88r-rg27-5xfg) | `docling` `>= 2.13.0, < 2.74.0` | Submit a minimal USPTO-format XML with an external-entity canary that references a controlled URL or harmless local marker in an isolated lab. |
| LaTeX path containment | [GHSA-2j5p-7p5m-cvqr](https://github.com/advisories/GHSA-2j5p-7p5m-cvqr) | `docling` `>= 2.73.0, < 2.91.0` | Test whether `\includegraphics`, `\input`, or `\include` can traverse outside the base document directory using inert marker files. |
| HTML URI/path handling | [GHSA-q29v-xc37-wh5m](https://github.com/advisories/GHSA-q29v-xc37-wh5m) | `docling` `< 2.94.0` | Validate `file://`, `../`, absolute-path, redirect, internal-IP, remote-image, and `data:` URI handling under the application's `enable_local_fetch` and `enable_remote_fetch` settings. |
| Image reference URI handling | [GHSA-j5xp-7m2f-49jv](https://github.com/advisories/GHSA-j5xp-7m2f-49jv) | `docling-core` `>= 2.5.0, < 2.74.1` | Confirm whether image references accept local `file://` reads or unbounded inline `data:` payloads. |

## Recon workflow

### 1. Confirm dependency and backend reachability

```bash
# Dependency evidence.
grep -R 'docling\|docling-core' -n requirements*.txt pyproject.toml poetry.lock uv.lock Pipfile.lock setup.cfg setup.py 2>/dev/null
python - <<'PY'
import importlib.metadata as m
for pkg in ['docling', 'docling-core']:
    try:
        print(f'{pkg}=={m.version(pkg)}')
    except m.PackageNotFoundError:
        print(f'{pkg}: not installed')
PY

# Backend and option reachability.
grep -R 'DocumentConverter\|docling\|render_page\|enable_local_fetch\|enable_remote_fetch\|latex\|METS\|USPTO\|Html' -n . 2>/dev/null
```

A package match is a lead, not a finding. Confirm the application accepts the relevant file type and invokes the affected backend with the relevant options.

### 2. Map document-processing trust boundaries

Capture these details before sending canaries:

| Boundary | Question |
| --- | --- |
| Input source | Can an unauthenticated user, tenant user, partner integration, email parser, or agent upload the document? |
| Backend selection | Does file extension, MIME sniffing, or content detection choose HTML/XML/LaTeX/METS/USPTO handling? |
| Fetch policy | Are `enable_local_fetch` or `enable_remote_fetch` enabled? Are redirects and internal IPs blocked? |
| Network egress | Can the worker reach metadata services, localhost, intranet hosts, object buckets, or internet canary domains? |
| Filesystem | Which directories are readable by the worker, and is conversion output returned or indexed? |
| Resource limits | Are archive member count, decoded data size, CPU time, and memory bounded? |
| Observation | Can you see converted output, canary callbacks, logs provided by the owner, or timing/resource effects? |

## Safe validation patterns

Use local labs, staging workers, or explicitly approved target-owned test tenants. Keep payloads inert and small.

### HTML render / URI fetch canary

Use a controlled callback domain and non-sensitive marker paths. The goal is to prove whether network fetches or JavaScript execution are possible, not to scan internal networks.

```html
<!doctype html>
<title>docling-html-canary</title>
<img src="https://canary.example.invalid/docling-img-canary.png">
<script>fetch('https://canary.example.invalid/docling-js-canary')</script>
```

Interpretation:

- patched or safely configured workers should not execute JavaScript;
- if remote fetch is disabled, no outbound image/script requests should occur;
- if remote fetch is enabled by design, redirects to `file:`, loopback, RFC1918, link-local, and metadata IPs should be blocked before retrieval.

### XML external entity canary

Use only harmless controlled URLs or lab-local marker files. Do not attempt to read secrets.

```xml
<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY canary SYSTEM "https://canary.example.invalid/docling-xxe"> ]>
<x>&canary;</x>
```

A strong finding needs backend reachability and evidence that entity resolution happened, such as a controlled callback or the canary string appearing in converted output. For USPTO-specific testing, preserve the minimal format needed to reach the USPTO parser rather than relying on a generic XML parser result.

### LaTeX local-file containment canary

Create a lab marker inside and outside the base document directory. Use non-sensitive text only.

```tex
\documentclass{article}
\begin{document}
Safe include: \input{inside-canary.tex}
Traversal include: \input{../outside-canary.txt}
\end{document}
```

Affected behavior is traversal outside the document base being included or attempted. Patched behavior should resolve paths and reject anything outside the base directory.

### Archive and data URI resource controls

Do not use destructive zip bombs. Instead, test limits with tiny canaries and owner-approved thresholds:

- one normal archive member that should process successfully;
- one traversal-looking archive member that should be rejected or confined;
- a small `data:` image that should decode successfully if allowed;
- a larger but still safe `data:` payload in a local lab to verify decoded-size enforcement.

## Controls to avoid false positives

| Control | Expected result |
| --- | --- |
| `docling` / `docling-core` at or above the fixed versions for the tested backend | JavaScript disabled for render mode, network/local fetch controls enforced, XML entities blocked, path traversal rejected, resource sizes bounded. |
| Backend not reachable | Do not report from dependency presence alone. |
| `enable_local_fetch=False` and `enable_remote_fetch=False` for untrusted HTML | No local/remote URI retrieval from submitted HTML resources. |
| Sandboxed worker with no sensitive files and no internal egress | Impact may be limited to conversion correctness or bounded resource use. |
| Owner-provided logs only | Redact paths, tenant IDs, and internal hostnames before reporting. |

## Reporting heuristic

Frame findings around the conversion boundary:

- **Expected boundary:** untrusted documents must not trigger script execution, uncontrolled network fetches, local file reads, XML entity expansion, path traversal, archive over-expansion, or unbounded inline decoding.
- **Observed bypass:** a specific backend and option set accepted a canary document and produced a controlled callback, local marker disclosure, traversal include, unsafe extraction, or resource-limit bypass.
- **Impact:** SSRF, local file read, stored/indexed XSS-adjacent content, document-output data disclosure, resource exhaustion, or execution in the rendering environment depending on the proven primitive.
- **Evidence:** dependency versions, backend trigger, sanitized configuration, canary document hash, redacted request/response or callback logs, converted output excerpt, and fixed-version or safe-option control.

## Scope and safety notes

- Do not probe internal IP ranges through the converter without explicit SSRF authorization.
- Do not read `/etc/passwd`, cloud metadata, credentials, or tenant documents as proof; use owner-approved marker files or controlled callback URLs.
- Do not send zip bombs, decompression bombs, huge `data:` URIs, or high-volume conversion jobs to production.
- Keep testing in isolated workers when Playwright rendering or XML entity handling is involved.

## October 7 20:4xZ follow-up: Tectonic TikZ TeX file primitives, entry-point import before the plugin gate, DNS-rebinding SSRF guard gap in HTML render mode, and header relay to document-named hosts

Docling five-leg wave (published 20:40–20:42Z) with durable converter-pipeline axes:

- **Tectonic TikZ rendering = unrestricted TeX file primitives** ([GHSA-x3q2-h9hx-4r4j](https://github.com/advisories/GHSA-x3q2-h9hx-4r4j) / [CVE-2026-105744](https://nvd.nist.gov/vuln/detail/CVE-2026-105744), 7.5, fixed 2.132.0): with the opt-in `tikz_engine="tectonic"`, the TikZ body *and document preamble* from the input file compile with no restriction on TeX's file primitives → arbitrary file read/write as the process; caller-set `tikz_engine_allow_shell_escape=True` adds `\write18` command execution. Rule: "opt-in" engine flags are per-deployment attack-surface switches — on any document-conversion service, enumerate which optional engines (tectonic, pdflatex, ghostscript, shell-escape) the deployment enabled; TeX `\input`/`\openin` are file primitives, so an opted-in TeX engine turns untrusted documents into file-read primitives without any parser bug. Proof stays owner-approved marker files.
- **Entry points imported before the `allow_external_plugins` check** ([GHSA-9jxx-vjrv-h2rq](https://github.com/advisories/GHSA-9jxx-vjrv-h2rq) / [CVE-2026-105745](https://nvd.nist.gov/vuln/detail/CVE-2026-105745), fixed 2.131.0): pluggy `load_setuptools_entrypoints()` *imports every registered module first*, then docling filters non-`docling.` namespaces — import-time code of any installed third-party plugin runs even with external plugins disabled (the default). Generalized rule for every Python plugin framework (pluggy/stevedore/entry-points): the gate that "disables" plugins must run before import; where it doesn't, any package installable into the same environment is code-exec at startup — check whether a shared venv/worker install path is writable, and audit which entry-point groups the app loads. Same import-side-effect class as the Oct 6 Docling METS family and the pip-install-helper legs on the June 12 dev-tools page.
- **SSRF guard bypass in HTML render mode: DNS rebinding / multi-record resolution, no IP validation** ([GHSA-pc36-qwjq-x68c](https://github.com/advisories/GHSA-pc36-qwjq-x68c) / [CVE-2026-105743](https://nvd.nist.gov/vuln/detail/CVE-2026-105743)) — the guard exists for other paths but the HTML render mode's remote-resource fetch skips IP validation entirely, so short-TTL rebinding and round-robin A records reach internal space. Same per-backend/per-mode guard parity rule as today's PraisonAI Crawl4AI leg: test each *render mode* of a converter independently; a validated default mode says nothing about opt-in modes.
- **Configured HTTP headers relayed to every remote image host named by the document** ([GHSA-p3fw-7699-7926](https://github.com/advisories/GHSA-p3fw-7699-7926) / [CVE-2026-105742](https://nvd.nist.gov/vuln/detail/CVE-2026-105742), low but durable): headers set for an authorized image CDN (auth tokens) ship to whichever hosts the document's `<img>` tags name. Confused-deputy credential relay: attacker-authored document selects the recipient of the converter's standing credentials. Detection from outside: own callback that echoes received headers, embed `<img src=callback>` in a converted document — if your harness's config headers arrive, the token crosses a document-selected destination. Pair with the July 28 SSRF relay family.
- Smaller tracked-in-place leg: crafted DoclingDocument JSON embeds local image files into converted output (p944, local-file inclusion through the JSON intermediate format — the "intermediate format is also an input format" rule).
