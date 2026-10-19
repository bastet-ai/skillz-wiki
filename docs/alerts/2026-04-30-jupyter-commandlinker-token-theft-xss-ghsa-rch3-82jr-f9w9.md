# Jupyter Notebook CommandLinker token-theft XSS (GHSA-rch3-82jr-f9w9 / CVE-2026-40171)

**Signal:** GitHub Security Advisories published **2026-04-30**. Jupyter Notebook / JupyterLab fixed a stored XSS path that can steal authentication tokens when a user opens and interacts with a malicious notebook.

## What it is
CommandLinker functionality in notebook/markdown UI could be abused to create controls that look legitimate. A single user click in a malicious notebook can execute attacker-controlled script in the Jupyter origin, steal authentication tokens, and use the REST API to read/write files, access kernels, execute code, or create terminals.

Affected packages include pip `notebook` `7.0.0` through `7.5.5`, pip `jupyterlab <= 4.5.6`, npm `@jupyter-notebook/help-extension <= 7.5.5`, and npm `@jupyterlab/help-extension <= 4.5.6`. Fixed versions: Notebook `7.5.6` and JupyterLab `4.5.7`.

Reference: <https://github.com/advisories/GHSA-rch3-82jr-f9w9>

## Triage
1. Inventory multi-user JupyterHub, shared notebook servers, hosted lab environments, and developer workstations that open untrusted notebooks.
2. Check for vulnerable `notebook`, `jupyterlab`, and help-extension versions.
3. Treat malicious notebooks opened before patching as possible account/session compromise.

## Mitigation
- Upgrade to Notebook `7.5.6`, JupyterLab `4.5.7`, or later.
- Disable the help extensions if immediate upgrade is not possible:
  - `jupyter labextension disable @jupyter-notebook/help-extension`
  - `jupyter labextension disable @jupyterlab/help-extension`
- Consider setting sanitizer config to disable command linker behavior (`allowCommandLinker: false`) for high-risk environments.
- Keep notebooks from untrusted sources in isolated, throwaway sessions.

## Detection ideas
- Review recent notebooks for suspicious markdown/command-link constructs and external network calls.
- Hunt Jupyter REST API logs for file reads, terminal creation, or kernel execution immediately after a notebook was opened.

## Durable lesson
Notebook files are active content. Treat UI command links and rich markdown as code-adjacent surfaces, especially where browser-origin tokens can reach filesystem and kernel APIs.

## October 19 follow-up: mljar-mercury — an anonymous-by-default Jupyter backend guarded by a deny list is unauthenticated RCE twice over (GHSA-f8c7-rwf9-fmgm / CVE-2026-111057 + GHSA-rv4m-xm3f-3ccq / CVE-2026-111058, both critical)

Mercury wraps Jupyter Server to publish notebooks as shareable web apps and, in default config, sets `--IdentityProvider.token=''` (anonymous auth) plus `--ServerApp.disable_check_xsrf=True` when no token is configured. Its only defense against Jupyter's dangerous management routes is a **regex blocklist** (`BLOCKED_PATTERNS`: `/lab`, `/api/terminals`, `/api/shutdown`, `/files`). Two independent criticals fell out of that design in one day:

- **Missing-comma blocklist merge (f8c7, ≤3.2.3):** the first two raw-string entries lacked a comma, so Python concatenated them into one pattern `/lab.../api/terminals...` — a direct `POST /api/terminals` matched nothing and reached Jupyter's terminal API: unauthenticated interactive OS shell over `/terminals/websocket/<n>` (advisory PoC shows root shell with plain `curl` + a websocket client, no auth, no session).
- **The blocklist can never cover kernels (rv4m, proven on 3.2.4 — the f8c7 fix release):** `/api/kernels` cannot be blocked (Mercury needs kernels), and the kernel websocket patch only does idle-timeout tracking with zero `execute_request` filtering. `POST /api/kernels` → 201, open the channels websocket, send `execute_request` → arbitrary code as the server user. Runtime-proven on the patched build: `/api/terminals` returns 403, `/api/kernels` returns 201.

Operator reading:

- **Fingerprint the wrapper, not just the service.** Any dashboard/notebook-app wrapper (Mercury, Voila-family, custom Jupyter/JupyterLab fronts) that runs its backend tokenless and gates routes with a *deny list* is in scope before any credential work. Cheap tells: `/api/terminals`, `/api/kernels`, `/api/sessions`, `/api/contents` answering unauthenticated — probe the whole Jupyter Server REST family, not just the wrapper's advertised URL space, and diff status codes per route (403-vs-201 asymmetry across the sibling route family is the incomplete-fix oracle).
- **Python list-literal syntax is security code.** Adjacent string entries without a comma merge silently into one pattern — every deny-list entry after the merge point silently vanishes. When auditing any Python allow/deny list of regexes, count entries as parsed (`len(LIST)`) against entries as written; same shape applies to any config parsed by juxtaposition (Nginx, YAML fold scalars).
- **Fix-differential testing beats fix-reading:** f8c7's patch added the comma and shipped as 3.2.4; re-running the sibling-route battery on the *fixed version* found the kernels leg immediately. Treat every security-fix release as a fresh route-enumeration trigger on the same product.
- Data-driven XSS sister leg (`mr.Markdown` renders python-markdown output into an `ipywidgets.HTML` `innerHTML` sink with zero sanitization, CVE-2026-111059/[GHSA-2658-85cv-9wwq](https://github.com/advisories/GHSA-2658-85cv-9wwq)): markdown-library-passes-raw-HTML + innerHTML-widget-render is the standard notebook-app stored-XSS chain when app data is untrusted — worth a DOM-marker canary in any authorized Mercury/notebook-app assessment.

Validation boundaries: local Docker deployment or owned instance only; prove with marker files and `/api/*` status-code decision tables; never spawn terminals/kernels on shared deployments, never touch other users' kernels or notebook contents.
