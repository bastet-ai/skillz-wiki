# Render, SSRF, filesystem, and MCP secret-boundary batch (GHSA)

Source: GitHub Security Advisories updated 2026-05-14.

This batch ties together client-side consent rendering, CMS widgets, URL metadata fetchers, virtual filesystems, and MCP wrappers around database tooling. The durable lesson is that helper paths often cross the real boundary: user-authored HTML reaches browsers, preview importers reach networks, filesystem abstractions reach host paths, and “observability” reaches raw SQL and credentials.

## Advisories covered

- **ethyca-fides DOM XSS in `fides.js` descriptions** — [GHSA-5qrq-9645-g5g2](https://github.com/advisories/GHSA-5qrq-9645-g5g2): `ethyca-fides >= 2.33.0, < 2.84.5` allowed `fides_description` override content into a DOM XSS path. Fixed in `2.84.5`.
- **Apostrophe image-widget `javascript:` URL XSS** — [GHSA-5f64-7vfc-rcx6](https://github.com/advisories/GHSA-5f64-7vfc-rcx6): `apostrophe 4.29.0` stored unsafe image-widget link URLs. No patched version was listed at scan time.
- **Apostrophe password recovery weakness/input validation** — [GHSA-gf43-24g3-5hw2](https://github.com/advisories/GHSA-gf43-24g3-5hw2): `apostrophe <= 4.29.0` exposed weak forgot-password and validation behavior. No patched version was listed at scan time.
- **Apostrophe rich-text widget import SSRF** — [GHSA-pr28-mf3q-qpg6](https://github.com/advisories/GHSA-pr28-mf3q-qpg6): `apostrophe <= 4.29.0` allowed authenticated SSRF through `@apostrophecms/area/validate-widget`. No patched version was listed at scan time.
- **`sanitize-html` default `xmp` raw-text passthrough XSS** — [GHSA-rpr9-rxv7-x643](https://github.com/advisories/GHSA-rpr9-rxv7-x643): `sanitize-html <= 2.17.3` could permit default XSS through `xmp` raw-text handling. No patched version was listed at scan time.
- **Karakeep SDK favicon metadata SSRF** — [GHSA-7rx4-c5vx-g8w3](https://github.com/advisories/GHSA-7rx4-c5vx-g8w3): `@karakeep/sdk <= 0.31.0` let `metascraper-logo-favicon` bypass `validateUrl` protections. Fixed in `0.32.0`.
- **go-billy path traversal** — [GHSA-qw64-3x98-g7q2](https://github.com/advisories/GHSA-qw64-3x98-g7q2): `github.com/go-git/go-billy/v5 < 5.9.0` and `v6 < 6.0.0-alpha.1` allowed traversal through filesystem abstraction boundaries. Fixed in `5.9.0` and `6.0.0-alpha.1`.
- **dbt MCP telemetry leaks raw tool arguments** — [GHSA-jj54-r8gm-2fcf](https://github.com/advisories/GHSA-jj54-r8gm-2fcf): `dbt-mcp <= 1.17.0` transmitted MCP tool arguments, including raw SQL and `--vars` credentials, to dbt Labs telemetry by default. Fixed in `1.17.1`.
- **dbt MCP file logging leaks raw tool arguments** — [GHSA-7xgw-6qf3-7w59](https://github.com/advisories/GHSA-7xgw-6qf3-7w59): `dbt-mcp <= 1.17.0` logged SQL queries and credentials in plaintext when file logging was enabled. Fixed in `1.17.1`.
- **dbt MCP CLI wrapper argument injection** — [GHSA-xpww-f6pm-cfhq](https://github.com/advisories/GHSA-xpww-f6pm-cfhq): `dbt-mcp <= 1.17.0` allowed argument injection through `node_selection` and `resource_type` wrapper parameters. Fixed in `1.17.1`.

## Operator triage

1. Patch fixed packages first: `ethyca-fides >= 2.84.5`, `@karakeep/sdk >= 0.32.0`, `go-billy >= 5.9.0` / `6.0.0-alpha.1`, and `dbt-mcp >= 1.17.1`.
2. For Apostrophe and `sanitize-html` deployments with no listed patch at scan time, restrict author/editor roles, disable rich-text import paths that fetch remote resources, and treat stored widget content as suspect until upstream guidance lands.
3. Search CMS content for `javascript:` image links, unexpected `xmp` blocks, rich-text widgets that reference internal URLs, and recent password-reset events.
4. Put URL preview/favicon/import workers behind egress allowlists, DNS rebinding protection, IP literal/private-range rejection after resolution, and response-size/time budgets.
5. Audit go-billy consumers that write archives, clones, or unpacked repo content; look for `../`, absolute paths, symlink escapes, and case/Unicode canonicalization mismatches in stored artifacts.
6. Rotate secrets that appeared in dbt MCP `--vars`, SQL text, file logs, or telemetry during vulnerable versions; delete or quarantine logs before broad sharing.
7. For MCP wrappers, test tool parameters as argv boundaries, not trusted strings: reject option-looking values where only selectors/types are expected.

## Durable controls

- Escape at the final browser context and validate URL schemes with allowlists; `javascript:` and raw-text HTML edge cases must be blocked even for trusted editor flows.
- SSRF defenses belong at every URL-consuming helper, including metadata, favicon, import, and preview paths, not only primary HTTP clients.
- Filesystem abstraction libraries are part of the sandbox boundary. Canonicalize after joins, after symlink resolution, and before writes.
- MCP and agent tool logs need data classification by default: raw SQL, flags, environment-like variables, and credentials should be redacted before telemetry or local file sinks.
- CLI wrappers should construct argument arrays from typed parameters and deny nested flags unless the specific tool contract requires them.
