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
