# knowns agent-server trust boundaries + Lara Dashboard admin-privilege breaks (11 GHSAs, Sept 8 wave)

**Why this is worth an operator page.** The 2026-09-08 unreviewed advisory wave contains two clusters with directly reusable operator patterns. The **knowns** server (an AI knowledge-base/agent server with an MCP tool layer, a management API, and public-tunnel republishing) ships a full set of file-boundary and auth-classification bugs that mirror the recurring "repo-local config → execution" and "agent tool argument → filesystem" classes this wiki already tracks. **Lara Dashboard** (Laravel admin panel) contributes three low-privilege admin → RCE breaks built on permission-granularity gaps and zip-extraction into the live application root. Both clusters answer the same audit question: *which "admin-adjacent" endpoint does a lesser role still reach, and what filesystem or process sink does it drive?*

## knowns — unauthenticated management API on all interfaces (GHSA-pcf3-jgx6-7m94, 9.8)

Critical. Before 0.30.0 the management API is served **without authentication on all network interfaces**, with no password on fresh installations. The standout sink is `/api/tunnel/start`, which provisions a public tunnel and **republishes the API at a publicly reachable address** — turning a host-bound service into an internet-exposed one by design.

Durable operator pattern: **default-off auth on a management surface is the whole finding.** Recon step: for any AI/knowledge/agent server, enumerate the management or admin API path family (`/api/*`, `/admin/*`, `/management/*`) with a no-auth probe and diff which verbs respond. Where a tunnel/proxy/republish endpoint exists, the second-order question is whether calling it *expands the attack surface further* (it does here). Prove with an unauthenticated existence probe and a lab instance; do not republish live APIs.

## knowns — MCP tool-argument filesystem traversal (GHSA-qjrq-cvv4-3g9w, 8.8)

High. Before 0.30.0, MCP tool arguments carrying filesystem paths are not validated, so an attacker who can steer tool invocation (malicious project content, an induced tool call, or a prompt that lands in a tool argument) can **read, create, overwrite, and delete arbitrary Markdown files reachable by the server process** via `../` sequences.

Durable pattern: **agent-tool path arguments are a second filesystem-root.** The server's project directory is the intended root, but every tool that accepts a path (`read`, `write`, `replace`, `delete`) is a root-escape candidate unless it canonicalizes and prefix-checks. This is the same class as the CodeWhale git-tool argument-injection wave (2026-09-04) and the PDM file-write advisories: audit each tool's path sink, not just the HTTP layer.

## knowns — `code.replace` overwrites arbitrary files, incl. shell startup + SSH config (GHSA-g6q2-h5cf-8q26, 8.3)

High, unauthenticated (UI required per vector, but the route-level check is the gap). The `handleCodeReplace()` handler accepts absolute paths and traversal sequences, letting callers **write content to files outside the project root — explicitly including shell startup scripts and SSH configuration files**. This is the durable "write to `~/.bashrc` / `~/.ssh/config`" persistence pattern, reachable from a code-editing tool.

Durable pattern: **a replace/write tool that does not bind its target to the project root is a credential/persistence writer.** Validation: attempt a replace against a disposable canary file just outside the root and confirm denial; never write real shell or SSH files.

## knowns — mutating `code.replace` misclassified as read-only (GHSA-q52j-357p-5pv8, 8.1)

High. Read-restricted sessions can invoke mutating code actions because `code.replace` is **classified as a read-only operation** by the authorization layer. An attacker with read-only scope edits **permission configuration files**, then escalates on subsequent calls.

Durable pattern: **the action→risk-classification table is the real auth control.** If a product gates tools by "read vs write," every tool whose write target includes *the configuration that defines read vs write* is an escalation primitive. Audit heuristic: enumerate which read-allowed tools can modify auth/permission/routing config, not just data.

## knowns — unvalidated `settings.lsp.languages` binary executes on repo open (GHSA-6ph4-r249-58p2, 7.8)

High, local attack vector. A crafted `.knowns/config.json` ships an unvalidated binary path in `settings.lsp.languages`; opening the repo **executes the binary twice under the user's account** with no verification. This is the classic **repo-trusted-config-to-execution** boundary: the repo is the untrusted input, and a config field is a direct exec sink.

Durable pattern: pair with any "open project" flow in AI/dev tooling — which config fields name executables, interpreters, or plugin paths, and is there any allowlist? Proof: a repo whose config points at a canary script that records its argv; confirm execution in a disposable workspace only.

## knowns — unauth import-route name traversal writes outside imports dir (GHSA-8mhw-737q-f96r, 9.1)

High, unauthenticated. The import routes fail to validate the `name` parameter, so traversal sequences escape the imports directory and **overwrite arbitrary files writable by the server process** — no auth required.

Durable pattern: **filename fields on unauthenticated ingestion routes.** Imports/uploads/templates are the standard surface; the check to run is whether the server resolves the name relative to the intended directory (canonicalize + prefix check) rather than concatenating it.

## knowns — unauth `POST /api/templates/preview` templateFile read (GHSA-g3m9-72x4-rrgv, 7.5)

High, unauthenticated. Directory traversal in `templateFile` reads **arbitrary files (credentials, config) and returns their content in the JSON response**. A trivial unauth file-read primitive, and a useful oracle for path discovery when paired with the import-route write.

## knowns — embedding-models/test SSRF with error-based reachability oracle (GHSA-fc26-7cjr-27x6, 7.2)

Medium. `POST /api/embedding-models/test` issues outbound requests to **caller-supplied destinations with no validation**; transport error messages reveal network reachability, enabling internal host and cloud-metadata enumeration. Durable pattern: **model/API connectivity-test endpoints are SSRF oracles** — the error message is the leak. Prove only against owned/no-content peers; never point at metadata or internal services.

## Lara Dashboard — non-Superadmin marketplace module install → RCE (GHSA-9wqq-j933-4w98, 7.2)

High. `MarketplaceModuleBrowser::installModule` (a Livewire action) lacks authorization: any non-Superadmin administrator can **download and auto-activate arbitrary PHP modules from the marketplace over unsigned HTTP**, achieving RCE as the web-server user.

Durable pattern: **module/plugin install with auto-activation is a code-execution primitive; the interesting question is which roles may invoke it.** For Laravel/Livewire admin panels, enumerate `@action`/Livewire methods on marketplace, upgrade, and plugin screens and diff the role gate against the sink (PHP download + activate = RCE). Unsigned HTTP module transport compounds it — integrity is not a control at all.

## Lara Dashboard — `settings.edit` reaches core-upgrade zip upload over live source (GHSA-849q-7g6r-c83p, 7.2)

High. `POST /admin/settings/core-upgrades/upload` is gated only by `settings.edit` (not Superadmin), letting a lesser admin **upload and extract arbitrary zip archives over the live application source tree** — e.g. replacing `routes/web.php` with embedded commands that run as the web-server user with access to env secrets and DB credentials.

Durable pattern: **zip-extract-into-app-root is the Laravel admin RCE enabler.** Reusable audit checklist: (1) which upload endpoints extract archives rather than store blobs, (2) what path confinement they enforce, (3) which permission — not which *role* — gates them, and (4) whether the extraction root is the live codebase. Validate with a marker zip containing a harmless `routes` replacement in a disposable copy; never touch a live install's `routes/`.

## Lara Dashboard — unauthorized post-builder media upload, attacker-chosen extension (GHSA-v24q-8gmj-8457, 5.4)

Medium. Authenticated accounts without content permissions can reach the post-builder image/video upload endpoints and **upload polyglot files with attacker-chosen extensions into the public web root**; execution follows if the deployment permits the uploaded file type. Same class as the CodeIgniter4 `ext_in` upload-validation work: extension trust is decided by MIME while the original name survives.

## Durable operator value

1. **Classification tables, not endpoint gates, are the auth control in agent tooling.** One knowns finding says a mutating tool is *labeled* read-only; two more say paths aren't bound to the project root. Audit the tool→(risk-class, root) mapping, not just route middleware.
2. **Repo-local config files are untrusted inputs with exec sinks** (LSP binary field) — the same boundary as project-config self-trust in dev-server tooling.
3. **Connectivity-test endpoints are standing SSRF oracles** for AI/model platforms; error text is the exfil channel.
4. **In Laravel admin panels, "settings" permissions frequently outrank their sinks**: a settings.edit token reaching a zip-extract-into-app-root endpoint is an RCE chain. Diff permission granularity against sink danger per endpoint.
5. **Auto-activating module installs over unsigned HTTP** collapse supply-chain and authorization into one bug: any role that can install can run code.

## Safety

- **Authorized scope / lab only.** Prove the knowns file-boundary findings with canary files immediately outside a disposable project root and confirm denial or containment; do not write shell startup files, SSH config, or credential files.
- **Do not** call `/api/tunnel/start` on any live system, point the embedding-models test endpoint at metadata or internal addresses, or install marketplace modules on a live Laravel install.
- Keep tokens, env files, and database credentials out of evidence and out of reports.

## Sources

- https://github.com/advisories/GHSA-pcf3-jgx6-7m94
- https://github.com/advisories/GHSA-qjrq-cvv4-3g9w
- https://github.com/advisories/GHSA-g6q2-h5cf-8q26
- https://github.com/advisories/GHSA-q52j-357p-5pv8
- https://github.com/advisories/GHSA-6ph4-r249-58p2
- https://github.com/advisories/GHSA-8mhw-737q-f96r
- https://github.com/advisories/GHSA-g3m9-72x4-rrgv
- https://github.com/advisories/GHSA-fc26-7cjr-27x6
- https://github.com/advisories/GHSA-9wqq-j933-4w98
- https://github.com/advisories/GHSA-849q-7g6r-c83p
- https://github.com/advisories/GHSA-v24q-8gmj-8457
