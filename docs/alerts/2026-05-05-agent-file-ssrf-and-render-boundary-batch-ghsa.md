# Agent, file, SSRF, and render-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because it repeats a core agentic-systems pattern: generated content, helper tools, and integration endpoints become dangerous when they can write files, evaluate code, fetch URLs, or render repository content without a capability boundary.

## Advisories covered

- **PPTAgent `save_generated_slides`** — [GHSA-pxhg-7xr2-w7xg](https://github.com/advisories/GHSA-pxhg-7xr2-w7xg): arbitrary file write through generated slide save paths.
- **PPTAgent LLM-generated Python** — [GHSA-89g2-xw5c-v95p](https://github.com/advisories/GHSA-89g2-xw5c-v95p): arbitrary code execution through `eval()` of LLM-generated code with builtins in scope.
- **PPTAgent `markdown_table_to_image`** — [GHSA-hrcw-xc63-g29m](https://github.com/advisories/GHSA-hrcw-xc63-g29m): arbitrary file write and directory creation through image/table rendering paths.
- **Langflow Knowledge Bases API** — [GHSA-9whx-c884-c68q](https://github.com/advisories/GHSA-9whx-c884-c68q): path traversal in knowledge-base file operations.
- **FireFighter Raid `jira_bot`** — [GHSA-fqvv-jvhr-g5jc](https://github.com/advisories/GHSA-fqvv-jvhr-g5jc): unauthenticated SSRF that can reach cloud metadata and steal IAM credentials.
- **`@tdurieux/anonymous_github`** — [GHSA-g485-8j3v-p6x8](https://github.com/advisories/GHSA-g485-8j3v-p6x8): XSS via unsanitized repository-content rendering in an anonymous GitHub origin.

## Operator triage

1. Inventory AI/agent presentation, knowledge-base, ticketing, and repository-preview tools reachable by users or automations.
2. Disable dynamic Python `eval`, arbitrary output paths, and markdown-to-image helpers until they are constrained to a scratch directory with no secrets.
3. Search for writes outside expected workspace/cache directories, newly created executable files, and overwritten application/static files.
4. For FireFighter or similar Jira/chatbot URL fetchers, block metadata IPs and internal ranges at egress, then inspect logs for `169.254.169.254`, IPv6 metadata endpoints, localhost, RFC1918, DNS rebinding, and redirect chains.
5. For repository renderers, audit pages that display README, Markdown, SVG, HTML, issue text, or generated docs from untrusted repos.

## Durable controls

- Generated artifacts need a capability object: allowed directory, allowed extensions, max size, overwrite policy, and no symlink following.
- LLM-generated code should be treated as untrusted code. If execution is required, run it in a disposable sandbox with no builtins beyond an allowlist, no network, and no host filesystem access.
- Knowledge-base IDs and file names must resolve through canonical path checks under a fixed root after URL decoding and Unicode normalization.
- SSRF defenses belong at the fetch primitive: deny metadata, loopback, link-local, private, and internal DNS results before and after redirects.
- Repository/content previews should render untrusted content as inert text or sanitized Markdown in a no-credential origin with strict CSP.
