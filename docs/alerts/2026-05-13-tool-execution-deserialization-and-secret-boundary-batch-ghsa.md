# Tool execution, deserialization, and secret-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because helper libraries and agent-adjacent tools increasingly bridge untrusted project data into shells, local files, manifests, renderers, and privileged service calls. Treat those bridges as execution boundaries, not convenience plumbing.

## Advisories covered

- **uniget command injection** — [GHSA-qqq4-5773-pmw5](https://github.com/advisories/GHSA-qqq4-5773-pmw5): `tool.Check` could reach arbitrary command execution before `0.27.1`.
- **claude-code-cache-fix local code execution** — [GHSA-g3xq-3gmv-qq8g](https://github.com/advisories/GHSA-g3xq-3gmv-qq8g): Python triple-quote injection in `tools/quota-statusline.sh` affected `3.5.0` through `<3.5.2`.
- **Systeminformation NetworkManager command injection** — [GHSA-hvx9-hwr7-wjj9](https://github.com/advisories/GHSA-hvx9-hwr7-wjj9): unsanitized Linux connection profile names could reach shell execution in `networkInterfaces()`.
- **LangSmith public-prompt manifest deserialization** — [GHSA-3644-q5cj-c5c7](https://github.com/advisories/GHSA-3644-q5cj-c5c7): public prompt pulls deserialized untrusted manifests without a clear trust-boundary warning across affected `langsmith`, `langchain`, and `langchain-classic` versions.
- **PDF.js arbitrary JavaScript execution** — [GHSA-wgrm-67xf-hhpq](https://github.com/advisories/GHSA-wgrm-67xf-hhpq): malicious PDFs could execute JavaScript in `pdfjs-dist` before the fixed release line.
- **wireshark-mcp arbitrary file write** — [GHSA-3r68-x3xc-rxpg](https://github.com/advisories/GHSA-3r68-x3xc-rxpg): `export_objects` could write arbitrary files when `WIRESHARK_MCP_ALLOWED_DIRS` was not configured.
- **Goobi viewer unauthenticated Solr Streaming Expression proxy** — [GHSA-2rgp-f66f-4499](https://github.com/advisories/GHSA-2rgp-f66f-4499): unauthenticated access could proxy Solr streaming expressions in `viewer-core`.
- **Grav Twig sandbox secret exfiltration** — [GHSA-j274-39qw-32c9](https://github.com/advisories/GHSA-j274-39qw-32c9): editor-role users could call `Config::toArray()` and exfiltrate plugin secrets.

## Operator triage

1. Patch command-wrapper and agent-helper packages before running them in repositories, CI workers, developer laptops, or shared terminals.
2. Inventory places where project-controlled names become shell snippets: status lines, network profile names, package manager checks, PDF processing, MCP tool arguments, and export paths.
3. Treat public prompts, Solr expressions, Twig templates, and PDF content as active inputs. Quarantine newly imported prompts/templates/docs until reviewed.
4. Configure `WIRESHARK_MCP_ALLOWED_DIRS` to a narrow scratch directory and rotate secrets that may have been visible to editor-role Grav templates.

## Durable controls

- Shell helpers should use argument arrays, fixed command allowlists, and no string interpolation from project or OS metadata.
- Agent/MCP tools need path allowlists, deny-by-default filesystem writes, and explicit audit records for every tool invocation.
- Public manifests and prompts require provenance, schema validation, and a safe deserialization mode before they influence runtime behavior.
- Template sandboxes should expose purpose-built read APIs, not whole config objects that contain secrets.
