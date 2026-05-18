# Admin Git, FastCGI, MCP, and parser-boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-7h26-hg47-p9hx](https://github.com/advisories/GHSA-7h26-hg47-p9hx),
[GHSA-9mvm-4gwg-v8mp](https://github.com/advisories/GHSA-9mvm-4gwg-v8mp),
[GHSA-m675-2p33-xv9g](https://github.com/advisories/GHSA-m675-2p33-xv9g),
[GHSA-qjp4-4jvr-xqg3](https://github.com/advisories/GHSA-qjp4-4jvr-xqg3),
[GHSA-m2hg-wjq3-28wq](https://github.com/advisories/GHSA-m2hg-wjq3-28wq),
[GHSA-qw48-84f6-28gv](https://github.com/advisories/GHSA-qw48-84f6-28gv),
[GHSA-q5pp-gvjg-h7v4](https://github.com/advisories/GHSA-q5pp-gvjg-h7v4),
[GHSA-79cf-xcqc-c78w](https://github.com/advisories/GHSA-79cf-xcqc-c78w),
[GHSA-97r8-rf7q-wmjw](https://github.com/advisories/GHSA-97r8-rf7q-wmjw),
[GHSA-f3rg-xqjj-cj9w](https://github.com/advisories/GHSA-f3rg-xqjj-cj9w), and
[GHSA-vpfx-pxqw-2w79](https://github.com/advisories/GHSA-vpfx-pxqw-2w79).

This batch is durable because the advisories repeat four operator-relevant failure modes: authenticated users reaching admin-only control planes, routing/parser canonicalization gaps turning uploads into code, outbound discovery features becoming SSRF, and convenience serializers/installers crossing object or filesystem trust boundaries.

## What changed

- Arcane exposed Git repository management and GitOps credential operations to ordinary authenticated users, and its volume-browser `path` parameter reached `sh -c` inside a helper container.
- Caddy's FastCGI path splitting mishandled non-ASCII request paths and could treat attacker-writable non-PHP files as executable FastCGI scripts in vulnerable deployments.
- Spring AI MCP dynamic client registration trusted OAuth and protected-resource metadata URLs supplied through MCP discovery, creating SSRF exposure when DCR is enabled.
- `form-data-objectizer` let bracket-notation form keys such as `__proto__[x]` mutate `Object.prototype`.
- Graphite database files used Python `pickle` before `0.2`, so loading untrusted database files could execute code.
- Microsoft APM dereferenced symlinks inside package `.apm/prompts/` and `.apm/agents/` during install, copying host-local file contents into project deploy paths.
- webpack-dev-server's prior source-exposure fix depended on Fetch Metadata headers that are absent on plain-HTTP origins; `5.2.4` adds a stronger resource policy.
- Sveltia CMS decoded HTML entities after sanitization in entry summaries, allowing stored XSS when untrusted content can enter the CMS source.
- n8n-MCP telemetry sanitization could retain fragments from URL-shaped workflow node parameters until `2.51.3`.
- AVideo's user-enumeration fix missed a sibling unauthenticated `mention.json.php` path.

## Operator triage

1. Search for affected packages and exposed roles:
   - `github.com/getarcaneapp/arcane/backend <= 1.18.1`
   - `github.com/caddyserver/caddy/v2 >= 2.7.0 <= 2.10.2`
   - `org.springaicommunity:mcp-client-security < 0.1.9`
   - `form-data-objectizer <= 1.0.0`, `graphitedb < 0.2`, `apm >= 0.5.4 <= 0.12.4`, `webpack-dev-server <= 5.2.3`, `@sveltia/cms < 0.160.1`, `n8n-mcp < 2.51.3`, and `WWBN/AVideo <= 29.0`.
2. For Arcane, treat any non-admin user with repository or volume-browser access as a credential-exposure and helper-container command-execution lead. Rotate Git tokens or SSH keys if untrusted users could hit the Git repository endpoints.
3. For Caddy/FastCGI, prioritize systems where users can upload, sync, or edit files under a FastCGI-served tree. Verify `split_path` behavior with non-ASCII path segments in a lab before relying on WAF or extension checks.
4. For Spring AI MCP, disable dynamic client registration unless needed. If DCR is required, validate discovered metadata endpoints against explicit scheme, host, DNS, redirect, and private-IP policies before fetching.
5. For object parsers, reject `__proto__`, `constructor`, and `prototype` at every nested key level; use null-prototype objects for decoded form structures where possible.
6. For installer/package ecosystems, unpack dependencies in a throwaway workspace and fail the build on symlinks, hard links, absolute paths, or path escapes before integration copies content into a project tree.
7. For telemetry and source-code exposure bugs, assume short secrets and internal identifiers may leak even when credentials are supposedly filtered; rotate only when logs/telemetry confirm sensitive values were present.

## Replayable validation boundaries

- **Authorization boundary:** create a low-privilege test account and verify every repository, settings, sync, and browse route independently enforces admin role checks, not just authentication middleware.
- **Shell boundary:** pass metacharacter payloads through API fields that eventually compose helper commands; command construction must use argv arrays, not quoted string interpolation through a shell.
- **Routing/parser boundary:** test equivalent ASCII, mixed Unicode, encoded slash, and alternate normalization paths against upload-to-execute chains.
- **SSRF boundary:** test redirects, DNS rebinding, IPv4-mapped IPv6, link-local, metadata, loopback, and RFC1918 targets for every dynamic discovery URL.
- **Filesystem boundary:** test symlinks and nested path escapes before and after package integrity checks; hashes over package manifests do not prove safe integration behavior.
- **Render/sanitizer boundary:** sanitize after all decoding and Markdown/entity expansion, or render as text when content trust is ambiguous.

## Durable controls

- Make admin authorization explicit at handlers that mutate repositories, credentials, infrastructure, and deployment state.
- Keep command execution APIs shell-free; quote functions are not command-injection mitigations when the sink is `sh -c`.
- Treat path splitting, extension validation, and Unicode normalization as one canonicalization step with regression tests.
- Implement SSRF policy in the fetcher, not only in callers, so MCP/OAuth discovery and other plugin features share the same guardrail.
- Treat deserialization and installer inputs as hostile code-loading surfaces until proven otherwise.
- Validate telemetry redaction with adversarial URL-shaped values, short tokens, tenant IDs, and signed query parameters, not just obvious credential names.
