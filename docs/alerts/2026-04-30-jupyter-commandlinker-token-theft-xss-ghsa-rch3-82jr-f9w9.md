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
