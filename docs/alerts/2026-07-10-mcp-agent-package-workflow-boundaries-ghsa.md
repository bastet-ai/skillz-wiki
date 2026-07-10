---
title: MCP Atlassian, SafeInstall, BabelDOC, MLflow, Windmill, and NotrinosERP boundary checks from the July 10 GHSA wave
---

# MCP Atlassian, SafeInstall, BabelDOC, MLflow, Windmill, and NotrinosERP boundary checks

This update promotes the later July 10 GHSA records that were not just availability notes. The reusable pattern is trusted automation accepting caller-controlled paths, commands, package-manager wrappers, document metadata, environment-secret references, scoped tokens, or upload filenames and then crossing into server files, developer command execution, deserialization, credential-bearing upstream calls, cross-scope code reads, or web-root execution.

Sources:

- [GHSA-g5r6-gv6m-f5jv: `mcp-atlassian` `confluence_upload_attachment` missing path validation](https://github.com/advisories/GHSA-g5r6-gv6m-f5jv)
- [GHSA-wm45-qh3g-v83f: `mcp-atlassian` attachment upload tools read server-side file paths over remote transports](https://github.com/advisories/GHSA-wm45-qh3g-v83f)
- [GHSA-xrmc-c5cg-rv7x: SafeInstall agent guard shell parsing can miss raw package execution](https://github.com/advisories/GHSA-xrmc-c5cg-rv7x)
- [GHSA-m8gf-v64p-gfmg / CVE-2026-54071: BabelDOC CMap pickle deserialization through PDF-controlled CMap names](https://github.com/advisories/GHSA-m8gf-v64p-gfmg)
- [GHSA-g35p-px32-whv6 / CVE-2026-4035: MLflow AI Gateway secrets resolve server environment variables into upstream auth headers](https://github.com/advisories/GHSA-g35p-px32-whv6)
- [GHSA-2ppx-66jv-wpw5 / CVE-2026-54136: Windmill resource-scoped API tokens can read scripts outside their allowed path via `scripts/list_search`](https://github.com/advisories/GHSA-2ppx-66jv-wpw5)
- [GHSA-qv4m-m73m-8hj7: NotrinosERP HR employee document upload preserves executable filenames in a web-served directory](https://github.com/advisories/GHSA-qv4m-m73m-8hj7)

!!! warning "Authorized validation only"
    Keep proofs to disposable MCP servers, fake Atlassian pages, sandbox coding-agent shells, local package indexes, synthetic PDFs, temp CMap directories, lab MLflow gateways, fake provider endpoints, two-token Windmill workspaces, and throwaway ERP users. Use marker files, inert packages, fake environment variables, canary scripts, and harmless upload extensions. Never upload real host secrets to Confluence/Jira, run package managers on a developer's real account, deserialize untrusted pickles on production workers, exfiltrate cloud credentials, read production scripts, or publish web shells.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-g5r6-gv6m-f5jv](https://github.com/advisories/GHSA-g5r6-gv6m-f5jv) / [GHSA-wm45-qh3g-v83f](https://github.com/advisories/GHSA-wm45-qh3g-v83f) | `mcp-atlassian` attachment tools | Remote MCP callers supply a `file_path` that is opened on the server host and uploaded to Atlassian | Add server-side file-boundary checks to MCP tools that claim to upload a caller-local file. |
| [GHSA-xrmc-c5cg-rv7x](https://github.com/advisories/GHSA-xrmc-c5cg-rv7x) | SafeInstall CLI agent guard | Shell parsing misses case-variant package managers, FD redirections, shell wrappers, or create/init scaffolding commands before policy evaluation | Test agent command guards with wrapper and normalization variants, not just plain `npm install`. |
| [GHSA-m8gf-v64p-gfmg](https://github.com/advisories/GHSA-m8gf-v64p-gfmg) | BabelDOC vendored PDF parser | PDF-controlled CMap names can resolve to an attacker-writable `.pickle.gz` and reach `pickle.loads()` | Treat document parser sidecar assets and lookup names as deserialization selectors. |
| [GHSA-g35p-px32-whv6](https://github.com/advisories/GHSA-g35p-px32-whv6) | MLflow AI Gateway | Gateway secret fields resolve `$ENV_VAR` against server environment, then send the value as provider auth to caller-configured upstreams | Test AI gateway credential stores for variable expansion plus attacker-controlled provider base URLs. |
| [GHSA-2ppx-66jv-wpw5](https://github.com/advisories/GHSA-2ppx-66jv-wpw5) | Windmill `scripts/list_search` | Route-level token scope validates action but not resource/path before returning script path and content | Add list/search endpoints to resource-scoped-token tests; do not stop at direct `GET` routes. |
| [GHSA-qv4m-m73m-8hj7](https://github.com/advisories/GHSA-qv4m-m73m-8hj7) | NotrinosERP HR documents | Authenticated employee-document uploads keep raw client filenames and extensions under web-served storage | Test role-gated document upload fields for extension validation and executable storage mapping. |

## Replayable validation boundaries

### MCP attachment upload as server-side file read

1. Run `mcp-atlassian` in a disposable remote transport mode such as HTTP/SSE, not only local `stdio` where server and user filesystem may intentionally be the same trust zone.
2. Configure fake Jira/Confluence credentials or a throwaway Atlassian space/page that can receive a harmless attachment.
3. Place a synthetic marker file on the MCP server host, for example `/tmp/mcp-atlassian-canary.txt`, and invoke only attachment-upload tools with that path.
4. Positive evidence is the marker attachment appearing on the fake Atlassian page or an upload attempt that proves the server opened the marker path.
5. Add negative controls: local `stdio` deployment documentation, a path outside the configured safe root, and a patched tool that validates or rejects server-local paths.

Report this as **remote MCP tool argument -> server-side path open -> Atlassian attachment exfiltration sink**. Do not use `/proc/self/environ`, SSH keys, cloud config, tokens, issue attachments, or customer documents as evidence.

### Agent package-install guard bypass testing

1. Install the guard only in a disposable agent shell with a scratch repository and no real credentials.
2. Build a matrix of package-manager invocations that an agent could emit: case variants, absolute paths, leading FD redirections, `sh -c` / `bash -lc` wrappers with options, and create/init/scaffolding runners.
3. Point every command at an owned local package index or inert package whose install script writes a marker only inside the temp repo.
4. Record whether SafeInstall asks/denies/allows, whether lifecycle-script disabling is enforced, and whether raw package execution occurs without a guard decision.

Report as **attacker-influenced agent command -> shell/parser normalization gap -> unguarded package-manager execution**. Avoid publishing malicious package payloads or testing on real developer workstations.

### PDF CMap name to pickle deserialization selector

1. Use an offline BabelDOC lab with no network credentials and a temp directory that contains one inert `.pickle.gz` canary file.
2. Create or adapt a synthetic PDF whose CMap `/Encoding` name resolves only to that temp canary path; do not reference system paths.
3. Run the exact PDF translation/parsing path and instrument which CMap path is opened and whether the pickle loader is reached.
4. Use an inert pickle canary that proves code-path reachability without executing commands; a patched negative control should reject absolute or traversal CMap names before lookup.

Report as **PDF CMap name -> path join absolute-path reset -> attacker-selected pickle file -> unsafe deserialization sink**.

### MLflow AI Gateway secret expansion to upstream callback

1. Build a lab MLflow gateway with a fake environment variable such as `SKILLZ_CANARY_TOKEN=mlflow-canary-only`.
2. Create the lowest-privilege user/config path allowed by the target deployment and set a gateway secret field to `$SKILLZ_CANARY_TOKEN`.
3. Point `api_base` or the equivalent provider URL only at an owned HTTPS callback service.
4. Invoke a harmless gateway request and record whether the callback receives the fake value in an auth header. Redact the canary if logs are shared.
5. Compare with a patched or hardened config that treats `$...` as literal text or disallows caller-controlled upstream bases.

Report as **gateway secret field -> server environment expansion -> caller-controlled provider request -> credential relay**. Never test with real cloud keys or production artifact credentials.

### Windmill resource-scoped token list/search drift

1. Create a Windmill lab workspace with two script paths, such as `f/allowed/canary` and `f/blocked/canary`, each containing synthetic content.
2. Mint a resource-scoped API token limited to the allowed path.
3. Query direct script routes and `GET /api/w/{workspace}/scripts/list_search` with the same token.
4. Positive evidence is blocked-path metadata or content returned only through the list/search route.
5. Keep proof to path/content canaries and response-status matrices; do not read real automation scripts, credentials, or job definitions.

Report as **resource-scoped API token -> action-only route check -> list/search returns out-of-scope script content**.

### ERP document upload to executable storage

1. Use a disposable NotrinosERP instance and a low-privilege HR test account with only the permission needed to manage employee documents.
2. Upload harmless marker files with dangerous-looking extensions, for example `skillz-canary.php.txt` and, only if approved in a lab, a non-executing `.php` marker that prints static text.
3. Record storage path, web reachability, content type, and whether the application preserves the raw client filename/extension under a web-served directory.
4. Add controls from profile-photo or other upload paths that do validate image/MIME/extension to show route-specific drift.

Report as **role-gated document upload -> raw filename preserved -> web-served executable extension**. Do not upload shells, persistence, or production employee documents.

## Reporting notes

Lead with the crossed boundary and the precondition: remote MCP transport and tool authorization, agent command influence, parser processing of an attacker-supplied PDF plus attacker-writable CMap path, MLflow gateway config authority, resource-scoped Windmill token, or HR document-upload permission. Evidence should be marker-only attachments, command-decision matrices, path-open traces, fake callback headers, two-token response tables, and upload storage maps.
