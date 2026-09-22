# Render, Markdown, and preview-boundary batch

**Signal:** The **2026-05-09 00:15 UTC** scan added render-path advisories where escaping, preview dispatch, or redirect assumptions failed after the main route looked safe.

## Advisory cluster

- **Mistune math plugin escape bypass** — [GHSA-8g87-j6q8-g93x](https://github.com/advisories/GHSA-8g87-j6q8-g93x) / CVE-2026-44708: math plugin render functions emitted `$...$` and `$$...$$` content without honoring `escape=True`; `mistune <=3.2.0` is affected.
- **Mistune figure directive attribute injection** — [GHSA-58cw-g322-p94v](https://github.com/advisories/GHSA-58cw-g322-p94v) / CVE-2026-44896: `figclass` and `figwidth` options were concatenated into HTML attributes without escaping; `mistune <=3.2.0` is affected.
- **Mistune heading ID attribute injection** — [GHSA-v87v-83h2-53w7](https://github.com/advisories/GHSA-v87v-83h2-53w7) / CVE-2026-44897: caller-supplied `heading_id` callbacks could return raw heading text that breaks out of the `id=` attribute. Patch to **3.2.1+** where available.
- **ViewComponent inherited preview helper dispatch** — [GHSA-7f3r-gwc9-2995](https://github.com/advisories/GHSA-7f3r-gwc9-2995) / CVE-2026-44836: preview routes could call inherited `render_with_template` and render internal templates. Patch `view_component` to **4.9.0+**.
- **ViewComponent system-test path containment** — [GHSA-hg3h-g7xc-f7vp](https://github.com/advisories/GHSA-hg3h-g7xc-f7vp) / CVE-2026-44837: `realpath` plus raw `start_with?` allowed sibling-directory escapes in test entrypoint rendering. Patch to **4.9.0+**.
- **Snipe-IT Referer-backed open redirect** — [GHSA-mghp-5cq4-v6mg](https://github.com/advisories/GHSA-mghp-5cq4-v6mg) / CVE-2026-44833: unvalidated `Referer` stored in session could drive `redirect()->to($backUrl)`. Patch to **8.4.1+**.

## Why this matters

Render bugs often hide in “secondary” paths: Markdown plugins, figure options, generated anchor IDs, preview helpers, test routes, and redirect conveniences. The application may escape normal body text correctly while plugin attributes, helper method dispatch, or session-backed return URLs bypass the same contract.

## Triage

1. Patch `mistune`, `view_component`, and Snipe-IT where untrusted users can submit Markdown, documentation content, preview route paths, or redirect-affecting headers.
2. Search for `mistune` math/figure/TOC hooks, especially custom `heading_id` callbacks that derive IDs from raw heading text.
3. Treat Rails preview and system-test routes as internal-only; verify they are disabled in production, staging, review apps, and shared CI unless protected by strong auth.
4. Reject redirect targets unless they are relative paths or match an explicit same-origin allowlist; never trust `Referer` as an authorization boundary.
5. Add regression fixtures with quote characters in attributes, raw HTML inside plugin delimiters, sibling path prefixes, and inherited helper names.

## Durable controls

- Define one escaping contract for every renderer extension point; plugin renderers should call the same escape helper as the core renderer.
- Use path-aware containment (`relative_path_from`, resolved prefix plus separator, or equivalent), not string-prefix containment.
- Dispatch only methods explicitly declared for a route surface; inherited framework helpers should not be route-callable by default.
- Make preview/test routes fail closed outside local development and require a visible startup warning when enabled.

## August 7 follow-up: Showdown metadata and generated-attribute contexts

Two reviewed Showdown records reinforce that Markdown body escaping does not cover generated document or attribute contexts:

- [GHSA-cr32-g25g-vxjj / CVE-2026-59711](https://github.com/advisories/GHSA-cr32-g25g-vxjj) reports that frontmatter metadata entered the HTML `<title>` without context-appropriate escaping when `completeHTMLDocument` was enabled.
- [GHSA-22g5-r2x5-97cx / CVE-2026-59710](https://github.com/advisories/GHSA-22g5-r2x5-97cx) reports that table-header text entered a generated `id` attribute without quote escaping under the GitHub-flavor table path.

The reviewed records list Showdown through 2.1.0 as affected but do not identify a patched package release. The linked upstream commits are useful fixed-code controls; verify package provenance rather than assuming a later version exists.

### Parse, serialize, and host-render matrix

1. Build a local harness around the exact Showdown options and extensions used by the application. Exercise fragment output and `completeHTMLDocument`, default and GitHub flavors, tables enabled/disabled, and the application's real post-render sanitizer.
2. Use harmless context-breaking markers in frontmatter title values and table-header text. The marker may set a detached-DOM attribute or increment a local in-memory event counter; do not use credential forms, network callbacks, cookie access, or privileged actions.
3. Capture raw Markdown, parsed metadata/header text, generated title or `id` value, serialized HTML, post-sanitizer HTML, and detached-browser DOM. This separates source parsing, output encoding, sanitizer behavior, and host-browser execution.
4. Include positive controls with ordinary metadata and headers, plus negative controls built from the linked corrected commits. Require title text to remain text and generated IDs to remain one inert attribute after browser reparsing.
5. The bounded positives are **frontmatter metadata -> title raw-text context break -> harmless detached-DOM event** and **table header -> generated `id` quote break -> harmless detached-DOM event**. Do not generalize to every Showdown configuration when `completeHTMLDocument`, table parsing, or the host sink is unreachable.

Report persistence separately from browser execution. A stored Markdown record is not stored XSS until the affected render path, final same-origin DOM sink, and harmless execution marker are all demonstrated.

## September 22 follow-up: front-matter parsers with language selectors are code-execution surfaces

- **gray-matter eval() on `js`/`javascript` front matter** — [GHSA-j9gx-vjm3-jpmm](https://github.com/advisories/GHSA-j9gx-vjm3-jpmm) / CVE-2026-78847 (all versions, verified on 4.0.3): `lib/engines.js` dispatches front matter whose language marker is `js`/`javascript` (the `---js` delimiter form) straight to `eval()`. The front-matter *header itself* is attacker code: any Node pipeline that parses untrusted Markdown — docs generators, CMS/markdown import, README/preview renderers, resume or content-ingest jobs — runs arbitrary JS if the app forwards the raw document to gray-matter with default engine handling, and gray-matter is a transitive dependency of thousands of SSG and tooling packages.

Operator rules:

1. **A parser that accepts a language/engine/expression selector is not a parser.** Same shape as the OrdaSoft `method`-field dispatch and CuteNews internal-namespace deserialization: metadata fields that name a language, engine, filter, or class are remote code dispatch until an allowlist proves otherwise. Grep dependency trees for front-matter/markdown libraries and check which engine options the application enables.
2. **Untrusted document + permissive engine = pre-auth RCE candidate** wherever user content reaches Markdown parsing (issue bodies, imported posts, uploaded `.md` files, webhook payloads). Fingerprint the library and version from lockfiles/package metadata on open-source targets before theorizing.
3. **Lab-only proof:** disposable Node harness calling gray-matter on a document with a `---js` header containing a marker (write a temp file / set a global), never on shared tooling. Evidence: the marker, plus the parse-call chain showing no engine restriction. Absence of a patched release (all versions affected) makes this a "verify whether your pipeline parses hostile front matter" finding, not a version-upgrade note.
