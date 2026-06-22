# Developer agent, dashboard, SDK, and framework control-boundary checks

Source: hourly offensive-security scan, 2026-06-19. Primary entries: GitHub advisories [GHSA-c73q-8xxr-rgqm](https://github.com/advisories/GHSA-c73q-8xxr-rgqm) / CVE-2026-55884, [GHSA-6m68-r693-78qx](https://github.com/advisories/GHSA-6m68-r693-78qx) / CVE-2026-55883, [GHSA-p749-9w62-w533](https://github.com/advisories/GHSA-p749-9w62-w533) / CVE-2026-55882, [GHSA-qw6v-5fcf-5666](https://github.com/advisories/GHSA-qw6v-5fcf-5666) / CVE-2026-54051, [GHSA-r78r-rwrf-rjwp](https://github.com/advisories/GHSA-r78r-rwrf-rjwp) / CVE-2026-48814, [GHSA-9qfv-wgh2-m6p8](https://github.com/advisories/GHSA-9qfv-wgh2-m6p8) / CVE-2026-55374, [GHSA-vcv2-r9jh-99m5](https://github.com/advisories/GHSA-vcv2-r9jh-99m5), [GHSA-jv2h-4p9v-wf5w](https://github.com/advisories/GHSA-jv2h-4p9v-wf5w), [GHSA-wg5p-8h9p-3mr7](https://github.com/advisories/GHSA-wg5p-8h9p-3mr7), [GHSA-2h46-9x5w-4wf7](https://github.com/advisories/GHSA-2h46-9x5w-4wf7), [GHSA-6rfw-mq36-jm8h](https://github.com/advisories/GHSA-6rfw-mq36-jm8h) / CVE-2026-12530, [GHSA-vmhf-c436-hxj4](https://github.com/advisories/GHSA-vmhf-c436-hxj4), [GHSA-c8qj-jx8j-fg2w](https://github.com/advisories/GHSA-c8qj-jx8j-fg2w), [GHSA-xm3x-9cfw-jhx4](https://github.com/advisories/GHSA-xm3x-9cfw-jhx4) / CVE-2026-55414, [GHSA-wpwq-4j6v-78m3](https://github.com/advisories/GHSA-wpwq-4j6v-78m3) / CVE-2026-55568, [GHSA-q7j3-v8qv-22vq](https://github.com/advisories/GHSA-q7j3-v8qv-22vq), [GHSA-8678-w3jw-xfc2](https://github.com/advisories/GHSA-8678-w3jw-xfc2), [GHSA-wcpr-6g7x-p44r](https://github.com/advisories/GHSA-wcpr-6g7x-p44r) / CVE-2026-11718, [GHSA-8fcc-w5hv-4gxv](https://github.com/advisories/GHSA-8fcc-w5hv-4gxv) / CVE-2026-11717, [GHSA-5gf6-gc35-xjpc](https://github.com/advisories/GHSA-5gf6-gc35-xjpc) / CVE-2026-11719, [GHSA-mqq5-j7w8-2hgh](https://github.com/advisories/GHSA-mqq5-j7w8-2hgh), [GHSA-c3wq-j5vh-68rc](https://github.com/advisories/GHSA-c3wq-j5vh-68rc), [GHSA-q76j-gcg9-vxc6](https://github.com/advisories/GHSA-q76j-gcg9-vxc6), and [GHSA-9wxg-vf3r-56hc](https://github.com/advisories/GHSA-9wxg-vf3r-56hc).

This batch is durable because each issue maps to a reusable offensive validation pattern: developer dashboards exposed beyond loopback, WebSocket anti-CSWSH tokens that are not actually session-bound, debug handlers mounted on privileged developer processes, agent command allowlists that validate strings but execute through shells, MCP/API servers that keep empty default secrets after incomplete fixes, repository-local config or wrappers that execute during agent indexing, checkpoint metadata that writes outside a session root, package-install helpers that treat dependency names as shell or pip control planes, package metadata rendered as trusted UI links, inert framework authorization filters, same-host SSRF that carries privileged API tokens, proxy configuration that silently weakens an assumed TLS leg, infrastructure-as-code source URLs that make Git fetchers read local files, XML schema loaders whose “no network” option is runtime-specific, MCP protocol-version or OAuth introspection edge cases that turn low-privilege or third-party tokens into tool execution, alternate CMS API actions that omit the authorization/scope applied by sibling routes, static-site build inputs that cross symlink or renderer escaping boundaries, and generator metadata fields that become source code when newline handling is overlooked.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-c73q-8xxr-rgqm / CVE-2026-55884 | Tilt HUD HTTP server | HUD routes had no authentication when bound to non-loopback interfaces, letting reachable callers trigger pre-defined resources, alter Tiltfile arguments, read engine state, and proxy into the Tilt apiserver with attached session material | Treat developer control planes as sensitive even when they are “local dev” tools; validate bind address, route auth, state-changing endpoints, and token-attaching internal proxies. |
| GHSA-6m68-r693-78qx / CVE-2026-55883 | Tilt HUD WebSocket stream | the WebSocket token was served by an unauthenticated endpoint, was not per-session, and direct clients without `Origin` could pass the fallback check | Test browser and non-browser WebSocket paths separately: token fetch, `Origin` handling, session binding, and streamed state exposure. |
| GHSA-p749-9w62-w533 / CVE-2026-55882 | Tilt HUD / apiserver debug handlers | Go `net/http/pprof` handlers were mounted under `/debug` without access control on exposed listeners | Include `/debug/pprof/*` and equivalent runtime diagnostics in dev-server recon; prove only route reachability or synthetic marker visibility, not live token or heap capture. |
| GHSA-qw6v-5fcf-5666 / CVE-2026-54051 | Network-AI sandbox policy | command allowlist globbing matched the full command string while execution used `/bin/sh -c`, so broad entries such as `git *` could also match shell metacharacter suffixes | In agent platform reviews, compare the parser used for allowlist decisions with the parser used by the execution sink; test metacharacters with inert markers only. |
| GHSA-r78r-rwrf-rjwp / CVE-2026-48814 | Network-AI MCP/SSE API | an incomplete fix left an empty default secret path that authorized non-browser callers when the service was exposed | Re-test patched claims for default-secret and non-browser transport paths; browser CORS fixes do not prove curl/SSRF/MCP client authentication. |
| GHSA-9qfv-wgh2-m6p8 / CVE-2026-55374 | `jleehr/canto-saas-api` request builder | unencoded path variables were inserted into authenticated API URLs, so attacker-controlled IDs could change the same-instance endpoint receiving the bearer token | Audit SDK wrappers where application-controlled identifiers become URL path segments before token attachment; use mocked API routes and disposable tokens. |
| GHSA-vcv2-r9jh-99m5 | `agentic-flow` MCP server | MCP tool parameters were interpolated into shell strings passed to `execSync()`, while HTTP/SSE transports exposed the same sinks without authentication or Origin/Host validation | Test agent tool arguments as untrusted data crossing into command construction; pair shell-metacharacter canaries with transport reachability checks. |
| GHSA-jv2h-4p9v-wf5w | `ouroboros-ai` project environment loading | an incomplete denylist let repository-controlled `.env` keys redirect Codex/OpenCode config homes, MCP bridge config, plugin trust roots, or SSRF-guard behavior | In AI coding agents, treat project-local environment files as execution-routing inputs; prove with marker config paths and inert MCP/plugin commands. |
| GHSA-wg5p-8h9p-3mr7 | `agent-coderag` dependency discovery | default repository indexing executed repository-controlled `gradlew` when a Gradle build file was present | Check code-indexing/RAG tools for build-system discovery that runs project wrappers before trust is established. |
| GHSA-2h46-9x5w-4wf7 | Entire CLI checkpoint restore | remote checkpoint metadata from the `entire/checkpoints/v1` branch supplied a `SessionID` used in resume/rewind transcript paths, enabling writes outside the expected session directory | Validate collaborative checkpoint/session restore flows with synthetic traversal IDs and disposable marker files only; treat checkpoint branches as repository-controlled restore input. |
| GHSA-6rfw-mq36-jm8h / CVE-2026-12530 | AWS Bedrock AgentCore SDK code interpreter | `install_packages()` built a `pip install` command from caller-influenced package names and allowed pip flags such as alternate indexes or requirements files | Treat package-install APIs as command and package-manager control planes; prove with owned package indexes and sandbox canaries, not real environment exfiltration. |
| GHSA-vmhf-c436-hxj4 | JupyterLab extension manager | PyPI project URL metadata could use a `javascript:` protocol and render as a clickable extension home-page link in the JupyterLab origin | Test package metadata-to-UI boundaries for protocol allowlists using private lab packages and harmless DOM markers. |
| GHSA-c8qj-jx8j-fg2w | DotVVM `AuthorizeActionFilter` | the framework action filter did nothing when applications relied on it for authorization | Include framework-provided authorization filters in positive/negative route matrices; prove with disposable roles and canary actions. |
| GHSA-xm3x-9cfw-jhx4 / CVE-2026-55414 | NL Portal form GraphQL resolver | unauthenticated public resolvers fetched caller-influenced same-host URLs while attaching a privileged Objecten-API token | Validate SSRF host-guard bypasses and credential forwarding with owned callback routes on the configured host or a lab mock. |
| GHSA-wpwq-4j6v-78m3 / CVE-2026-55568 | Guzzle cURL proxy handling | old libcurl builds could silently downgrade an intended `https://` proxy connection to plaintext HTTP | Add proxy-leg TLS assumptions to PHP integration reviews; capture handler/libcurl/version evidence and mocked proxy traffic only. |
| GHSA-q7j3-v8qv-22vq | OpenTofu module/provider download through `go-getter` | maliciously crafted source URLs can steer Git-backed download operations into arbitrary local-file reads during dependency acquisition | Treat IaC source URLs as supply-chain input; prove with disposable local canary files and an isolated OpenTofu workspace, not real state, credentials, or provider caches. |
| GHSA-8678-w3jw-xfc2 | Nokogiri `XML::Schema` on JRuby | the default `NONET` parse option did not block network fetches for external schema resources on JRuby, unlike CRuby/libxml2 | Add runtime-specific XML schema SSRF checks when apps parse uploaded or user-referenced schemas; evidence should be an owned callback from a lab schema only. |
| GHSA-wcpr-6g7x-p44r / CVE-2026-11718 | googleapis MCP Toolbox opaque-token validation | OAuth introspection responses with omitted `iss` could skip configured issuer checks and accept third-party tokens | Test MCP servers that delegate token checks to introspection endpoints with missing-claim matrices, fake IdPs, and harmless tool-list routes. |
| GHSA-8fcc-w5hv-4gxv / CVE-2026-11717 | googleapis MCP Toolbox opaque-token validation | OAuth introspection responses omitting mandatory `active` were not rejected, letting malformed positive-looking responses authorize protected tools | Include absent-field, false-field, and malformed introspection responses in MCP authorization harnesses; prove access only to canary tools. |
| GHSA-5gf6-gc35-xjpc / CVE-2026-11719 | MCP Toolbox for Databases protocol handlers | older MCP protocol-version handlers skipped `scopesRequired`, so low-privilege authenticated clients could request older versions or omit the header and invoke higher-privilege tools | Fuzz MCP-Protocol-Version negotiation as an authorization boundary; compare scope decisions across every supported handler with disposable database tools. |
| GHSA-mqq5-j7w8-2hgh | AlchemyCMS `GET /api/pages/nested` | unauthenticated nested-page API responses included restricted, unpublished, and draft page metadata; `?elements=true` could include restricted page element content despite sibling routes enforcing ability checks | In CMS reviews, compare every alternate tree/list/nested API against the canonical `show`/`index` authorization and publication scopes; prove only with lab pages and canary content. |
| GHSA-c3wq-j5vh-68rc | Hugo virtual filesystem / `resources.Get` direct lookup | local symlinks inside mounted directories such as vendored themes could escape the mount and let `os.ReadFile` return files reachable to the user running `hugo` | Treat static-site themes and local mounts as build-time file-read inputs; validate with disposable symlink canaries outside the site root, not real keys or config. |
| GHSA-q76j-gcg9-vxc6 | Hugo default code-block renderer | Markdown code-fence language/info strings were inserted into `class` and `data-lang` attributes without HTML escaping | Test content-adapter and contributor-controlled Markdown for renderer attribute injection with harmless DOM markers before calling it a broader XSS finding. |
| GHSA-9wxg-vf3r-56hc | OpenZeppelin Contracts Wizard generators | `info.securityContact` and `info.license` were printed into single-line comments without rejecting line terminators, so metadata from an integration or MCP tool could inject generated Solidity/Cairo/Soroban/Stylus source lines | Review code generators where untrusted agent or form fields become comments, pragmas, annotations, or source headers; prove with inert declarations in generated output only. |

## Operator triage

1. **Start with reachability.** For Tilt and Network-AI, confirm whether the developer/control service is bound to `0.0.0.0`, a container bridge, a VPN interface, a shared Codespaces/devcontainer port, or any reverse proxy. If it is loopback-only and not browser-reachable through a relay, the exploitable surface is much narrower.
2. **Separate browser and direct-client paths.** CSRF/CORS/origin controls may affect browsers only. Test direct HTTP clients, WebSocket clients with no `Origin`, SSRF relays, and MCP/SSE transports independently.
3. **Map policy decisions to sinks.** For command allowlists, record the exact string evaluated by policy, the tokenization or glob rules, and the final executor (`execve` argv vs shell string). Parser mismatch is the finding.
4. **Use canaries, not secrets.** Evidence should be route access, inert state changes, synthetic stream markers, decision tables, or mocked-token routing. Do not dump heap profiles, extract real session tokens, invoke production Tilt resources, or read live API keys.
5. **Version-negotiation and runtime differences matter.** MCP servers may enforce scopes in one protocol handler but not older handlers; XML libraries may enforce network bans in CRuby but not JRuby. Record runtime, protocol version, and negative controls.
6. **Keep file-read proofs synthetic.** For OpenTofu and other downloader issues, create a disposable marker file outside the working tree and prove only that the fetcher crosses the expected source boundary. Never read SSH keys, cloud config, `.terraform`, `.tofu`, state files, or provider caches.
7. **Diff sibling route behavior.** For CMS and framework APIs, compare nested/tree/export endpoints against the routes product teams expect to be canonical. Access-control drift often appears only in alternate serializers or preloaders.
8. **Treat build content as executable context.** Static-site renderers and contract generators may turn Markdown metadata, symlinks, comments, or headers into browser or source-code sinks. Keep evidence to generated artifacts and lab canaries.

## Replayable validation boundaries

### Developer dashboard exposure

- Inventory dev-control ports in the authorized environment: Tilt HUD, hot-reload dashboards, local Kubernetes helpers, preview tunnels, and reverse-proxied devcontainer ports.
- For Tilt-like services, capture bind address and listener path evidence first. Positive reachability is an unauthenticated response from HUD routes, WebSocket token routes, or debug endpoints from a non-loopback network position.
- For state-changing paths, use a lab project with a harmless resource that writes a marker under a temp directory. Confirm whether an unauthenticated caller can trigger only that marker resource; do not run production build/deploy tasks.
- For pprof/debug endpoints, prove with status codes, handler names, or a synthetic lab token intentionally placed in an isolated process. Do not collect real heap, goroutine, trace, or CPU profiles from shared systems.

### WebSocket stream and anti-CSWSH checks

- Fetch any advertised WebSocket token endpoint without credentials and record whether the token is static, process-wide, or session-bound.
- Attempt connection variants in a lab: expected same-origin browser request, browser request from an untrusted origin, direct client with no `Origin`, and direct client with a wrong `Origin`.
- Positive proof is receipt of a synthetic lab stream marker or session-state field from an unauthorized context.
- Keep browser-relay tests scoped to owned pages and lab services; do not collect developer state, kube contexts, environment variables, or command output.

### Agent command allowlist parser mismatch

- Extract the configured allowlist entries and classify them by shape: exact command, prefix glob such as `git *`, subcommand-specific glob, or broad shell wrapper.
- Build a throwaway workspace and replace the dangerous suffix with an inert marker, for example a command construction that would write only to a temp canary if executed in the lab.
- Compare four artifacts: the original submitted command string, the policy decision, the shell/argv executor call, and the resulting marker behavior.
- Report the boundary as **string allowlist to shell execution parser mismatch**. Do not publish production-ready payloads or execute commands outside the disposable workspace.

### Empty default secret and incomplete-fix checks

- Boot a fresh lab instance with default configuration, then test browser and non-browser callers separately.
- Exercise only harmless tool/list/config-read routes with fake values. Record whether missing, empty, invalid, and valid secrets produce distinct authorization outcomes.
- Repeat with the claimed fixed version and with an explicitly configured non-empty secret as negative controls.
- If the browser path is fixed by CORS but direct HTTP/MCP clients still succeed, report it as an incomplete fix with transport-specific evidence.

### SDK path-variable to authenticated route confusion

- Mock the upstream API host and configure the SDK with a disposable bearer token.
- Pass path variables containing dot segments, encoded slashes, literal `?`, `#`, and sibling endpoint names through application-controlled fields that normally carry IDs.
- Capture the exact request path and whether the bearer token is attached to the unintended route.
- Keep proof to same-host route confusion and fake tokens. Do not target real Canto tenants, media assets, or administrative endpoints.

### Agent repository trust and indexing execution

- Start from the exact command an operator or automation normally runs (`sync`, `index`, `resume`, `rewind`, `open workspace`) and identify files or branches that are auto-loaded from the target repository before review: `.env`, config homes, MCP YAML, plugin rosters, Gradle wrappers, checkpoint branches, lockfiles, and build manifests.
- For each file, record whether it is treated as data, policy, or executable input. Positive evidence is a marker-only config path, inert MCP command, lab wrapper invocation, or disposable restore file that proves the trust boundary without running attacker code in production.
- For checkpoint restore flows, build a disposable repository with a synthetic checkpoint branch and marker-only transcript data, then compare normalized restore paths for normal, absolute, parent-directory, encoded-separator, and sibling-directory `SessionID` values. Positive evidence is an attempted or completed write to a pre-created canary path outside the expected session directory.
- Include negative controls: clean repository, explicit safe config root, wrapper execution disabled, traversal-resistant restore path, patched restore primitives that only descend within the session root, and an allowlist that evaluates argv rather than shell text.
- Do not index untrusted public repositories with real agent credentials, mounted secrets, cloud CLIs, or writable home directories during validation.

### Package-manager and package-metadata boundaries

- Review APIs that accept package names, requirements files, index URLs, extension metadata, and project URLs. Package strings may be both identifiers and control-plane flags.
- In Bedrock AgentCore-like code interpreters, test whether package arguments can supply pip options (`--index-url`, `--extra-index-url`, `-r`) or reference sandbox files. Keep proof to owned package indexes and synthetic files inside a disposable sandbox.
- In JupyterLab-like extension UIs, publish or mock a private package with harmless `project.urls` variants (`https:`, `mailto:`, `javascript:`, `data:`) and capture whether the UI preserves unsafe protocols. Use a DOM marker only; do not target real users.
- Report the crossed boundary as **package metadata to trusted UI link** or **package install argument to package-manager control plane**, not as generic XSS/RCE unless the sink is independently demonstrated.

### Framework auth filters and privileged-token SSRF

- Build a route matrix with anonymous, low-privilege, and expected privileged roles. For action-filter issues, include a known-protected canary action and a negative control using a different authorization mechanism.
- For GraphQL or resolver SSRF, determine whether the caller controls scheme, host, path, query, redirects, and whether credentials are attached before or after host validation.
- Use a lab Objecten/API mock or owned same-host callback endpoint to capture only header presence/redacted token shape; never collect live privileged tokens or query real citizen/customer objects.
- Evidence should be request routing, status-code differences, redacted header presence, and route access deltas.

### Proxy-leg TLS downgrade assumptions

- Capture the HTTP client stack: Guzzle handler, PHP cURL extension, libcurl version, and whether HTTPS-proxy support is compiled in.
- In a lab, configure an `https://` proxy URL to a controlled proxy endpoint and observe whether the proxy leg negotiates TLS, fails closed, or silently arrives as plaintext.
- Positive proof is a version/handler matrix plus mocked traffic on a disposable proxy; do not route production credentials or customer traffic through a test proxy.
- Keep the finding precise: the origin request may still use HTTPS, while the client-to-proxy leg violates the operator's TLS assumption.

### IaC source URL to local-file read

- Start from a disposable OpenTofu project with no real state, cloud credentials, provider cache, SSH keys, or production module sources mounted.
- Create a synthetic canary file outside the project root, then use a controlled malicious source URL only in the lab to test whether the Git/go-getter download step can read outside the intended module/provider source boundary.
- Capture tool version, exact source URL shape at a high level, file path of the disposable canary, and whether the content is exposed in logs, diagnostics, module cache, or returned errors.
- Negative controls should include patched OpenTofu/go-getter versions and a benign source URL. Do not publish payloads that target common secret paths or apply the test to third-party modules without permission.

### XML schema NONET runtime check

- Identify whether the application parses user-supplied XML Schema documents and whether it runs Nokogiri on JRuby or CRuby.
- Host a harmless callback URL and reference it from a lab schema using external resource mechanisms that the application normally permits.
- Parse with default options and with explicit network-deny options. Positive evidence is a single callback from the JRuby schema parse path when the operator expected `NONET` to block network access.
- Keep proof to owned callback metadata and synthetic schemas. Do not probe internal addresses, metadata services, or customer URLs.

### MCP token introspection and protocol-version authorization

- Build a fake OAuth introspection endpoint and a disposable MCP Toolbox instance with one low-privilege canary tool and one high-privilege canary tool.
- Exercise introspection response variants: valid active token, `active:false`, omitted `active`, expected issuer, omitted `iss`, wrong issuer, and unrelated third-party issuer. Record the accept/reject decision for each.
- Exercise every supported `MCP-Protocol-Version` handler, plus a request with the header omitted. Compare `scopesRequired` enforcement across versions using the same low-privilege token.
- Positive proof is canary tool-list or canary tool-invocation access that contradicts the configured issuer/scope policy. Do not connect to production databases, expose real bearer tokens, or invoke destructive tools.

### Alternate CMS API authorization drift

- Seed a lab CMS with four page states: public published, restricted published, public draft, and restricted draft. Put unique canary text in each page and element body.
- Compare canonical routes (`show`, `index`, preview, search) with alternate routes (`nested`, tree, menu, sitemap, export, GraphQL, JSON:API includes) from anonymous, low-privilege, and expected privileged users.
- Positive proof is an alternate route returning restricted or unpublished canaries when the canonical route denies them. Capture only synthetic page IDs, flags, and marker strings.
- Do not run this against third-party customer content or publish real unpublished page names; the operator value is the route/scope mismatch.

### Static-site build file and renderer boundaries

- Use a disposable site with no secrets in the working tree, home directory, theme cache, module cache, or environment.
- For Hugo-style symlink confinement checks, place a synthetic canary outside the mounted directory and a symlink inside a local theme or mount. Exercise only the direct lookup path that the application uses, such as `resources.Get` plus a file-read helper.
- For Markdown renderer checks, create a lab content file whose code-fence language/info string contains a harmless attribute-breakout marker. Inspect the generated HTML for escaped vs executable output.
- Negative controls should include patched Hugo, Go-module theme downloads where symlinks are stripped, trusted-only content paths, and a custom renderer that escapes attributes.
- Never point symlink tests at SSH keys, cloud credentials, production config, or real content repositories.

### Generator metadata to source-code injection

- Identify generator fields that are intended as comments or metadata but are emitted into source: license, security contact, author, package URL, pragma, annotation, import alias, or header fields.
- Feed those fields through the same integration path operators actually use: web form, CLI, API, MCP tool, AI assistant, scaffold template, or CI workflow.
- Use newline, carriage-return, and Unicode line-separator canaries that add only inert declarations or marker comments to generated output. Verify whether generated source changes semantics or merely renders text.
- Keep proofs to generated artifacts and local compilation/lint behavior in a throwaway project. Do not deploy contracts, publish packages, or inject production code.

## Reporting notes

- State the crossed boundary precisely: **exposed dev dashboard to unauthenticated resource trigger**, **unauthenticated WebSocket token to state stream**, **debug handler to process-memory surface**, **allowlist glob to shell metacharacter execution**, **empty default secret to MCP tool invocation**, **path variable to bearer-tokened API route confusion**, **repository-local config to agent execution**, **checkpoint metadata to filesystem write**, **package install argument to package-manager control plane**, **package metadata to trusted UI link**, **inert authorization filter to route access**, **public resolver to privileged-token SSRF**, **HTTPS-proxy configuration to plaintext proxy leg**, **IaC source URL to local-file read**, **XML schema NONET bypass to outbound fetch**, **OAuth introspection missing-claim acceptance**, **MCP protocol-version negotiation to scope bypass**, **alternate CMS tree API to restricted/unpublished content**, **static-site symlink to build-user file read**, **Markdown info string to renderer attribute injection**, or **generator metadata newline to source-code injection**.
- Include negative controls: loopback-only bind, patched Tilt, WebSocket token bound to an authenticated session, command execution via argv without a shell, configured non-empty MCP secret, `rawurlencode()` path segment handling, patched OpenTofu/go-getter, CRuby or fixed Nokogiri JRuby, rejected missing `active`/`iss` introspection responses, identical scope decisions across MCP protocol versions, canonical CMS routes that deny the same canaries, patched Hugo, trusted-only content sources, and generator fields with newline rejection or block-comment escaping.
- Avoid mitigation-first framing in the finding body; focus on reachability, preconditions, exact trust boundary, canary evidence, and authorized impact.
