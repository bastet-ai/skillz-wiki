# MCP tool, codegen, redirect, and router boundary checks

Source: hourly offensive-security scan, 2026-06-11. Primary entries: GitHub advisories [GHSA-9gw6-46qc-99vr](https://github.com/advisories/GHSA-9gw6-46qc-99vr) / CVE-2026-48039 for Meta Ads MCP unauthenticated HTTP MCP tool execution leaking an operator Meta access token, [GHSA-4x76-22x2-rx8v](https://github.com/advisories/GHSA-4x76-22x2-rx8v) / CVE-2026-48054 for OpenZeppelin Contracts Wizard generated-test code injection through unsanitized `opts.name` / `opts.uri`, [GHSA-x426-x7cc-3fpc](https://github.com/advisories/GHSA-x426-x7cc-3fpc) / CVE-2026-48022 for `@hapi/wreck` sensitive credential-header leakage across cross-port and cross-scheme redirects, [GHSA-xf64-8mw2-4gr2](https://github.com/advisories/GHSA-xf64-8mw2-4gr2) / CVE-2026-48020 for Traefik StripPrefix route-level auth bypass through path normalization, and [GHSA-qq6c-99pv-prvf](https://github.com/advisories/GHSA-qq6c-99pv-prvf) / CVE-2026-47781 for PDM project-controlled `.pdm-plugins` execution before CLI parsing.

This batch is durable for operators because all five advisories expose a reusable assessment question: **does trusted automation, middleware, or agent tooling preserve the boundary between untrusted project/user input and privileged execution, credentials, routing, or generated code?**

## Why it matters for assessments

The affected components sit in places bug hunters and red teams routinely test:

- agent and MCP tool servers that bridge local operator tokens into HTTP-accessible tool calls;
- smart-contract scaffolding/code-generation workflows that turn user-supplied metadata into executable tests;
- HTTP client libraries that follow redirects while carrying application credentials;
- reverse-proxy middleware that strips URL prefixes before route-level authorization decisions;
- Python package-manager workflows where repository-local content executes before the intended command is parsed.

Do not report a package lockfile hit by itself. The useful finding is a reachable trust-boundary crossing: an unauthenticated or low-privilege actor can make the system execute a tool, generate executable code, forward credentials, reach a protected route, or run project-controlled plugin code in a privileged developer/CI context.

## What to map first

1. Confirm authorization for lab, staging, or customer-approved canary validation. Keep proofs canary-only.
2. Identify affected versions and deployment shape:
   - Meta Ads MCP deployments exposing an HTTP MCP transport or tool endpoint with operator Meta credentials loaded;
   - OpenZeppelin Contracts Wizard flows that generate and execute Hardhat or Foundry tests from externally influenced `opts.name` or `opts.uri`;
   - `@hapi/wreck` callers that send sensitive headers and allow redirects across scheme or port boundaries;
   - Traefik routers that combine `StripPrefix` with route-level auth, especially where multiple normalized path spellings reach the same backend;
   - PDM versions affected by GHSA-qq6c-99pv-prvf in developer, CI, or release jobs that run against contributor-controlled repositories.
3. Trace who controls the input and who owns the privileged sink: operator browser/session, CI runner, package manager process, proxy route, or outbound service client.
4. Pick a harmless canary sink: a mock MCP tool, local callback server, disposable generated test, synthetic route, or temporary plugin marker file.
5. Capture only redacted metadata, canary headers, route names, and synthetic tokens. Never publish live access tokens, cloud credentials, customer identifiers, or production private paths.

## Meta Ads MCP unauthenticated tool boundary

The MCP advisory is not just "MCP exists." The risky shape is: an MCP HTTP surface is reachable by a less-trusted origin or network actor, the server has an operator Meta access token loaded, and tool invocation can occur without binding the request to the intended authenticated operator session.

Safe validation pattern:

1. Inventory MCP endpoints, transports, and local/remote bind addresses for the assessed deployment.
2. In a lab profile, replace any real Meta token with a synthetic marker such as `skillz-meta-mcp-canary-token` or use a mocked Meta API endpoint.
3. Attempt a benign tool-list or no-op tool call from a separate unauthenticated client context.
4. Verify whether the request reaches the MCP tool handler and whether any outbound request would carry the canary token.

Strong evidence is a transcript showing unauthenticated client -> MCP tool execution -> mock outbound request containing only the synthetic token. Do not test by exfiltrating real operator tokens or calling live Meta Ads APIs unless the customer has explicitly provided a disposable test token and written scope.

## OpenZeppelin Contracts Wizard generated-test code boundary

Code generators are exploitable when untrusted metadata is inserted into source code and the generated code is then executed by the developer, CI, or an automated validation service. For this advisory, focus on `opts.name` and `opts.uri` flowing into generated Hardhat or Foundry tests.

Safe validation pattern:

```text
name: SkillzCanary'); console.log('skillz-codegen-canary'); //
uri:  https://example.invalid/skillz-canary
```

Use a disposable project and a harmless print/assertion canary. The proof should show:

- the externally controlled value that entered the generator;
- the generated test file containing executable canary syntax outside the intended string/data context;
- the test runner executing only the canary statement in a sandboxed project.

Do not inject wallet operations, deploy transactions, private-key reads, or network calls into generated tests. If the application generates code but never executes it, report a generated-code integrity issue rather than code execution.

## `@hapi/wreck` redirect credential boundary

The redirect advisory matters when a caller attaches sensitive headers to a request and follows redirects across a boundary where those headers should not travel: different scheme, different port, or different authority trust zone.

Safe validation pattern:

1. Stand up two local or approved canary listeners: one origin and one redirect target.
2. Send a request through the same `@hapi/wreck` options used by the application with a fake header such as `Authorization: Bearer skillz-redirect-canary`.
3. Have the origin respond with a redirect that changes only the tested boundary, for example `https -> http`, `:443 -> :8443`, or trusted service -> canary service.
4. Check whether the redirect target receives the fake credential header.

Evidence should be a redacted redirect transcript and header-presence table. Do not use live API keys, cookies, OAuth tokens, or third-party redirectors in public proof.

## Traefik StripPrefix path-normalization boundary

For Traefik, the reusable question is whether auth is evaluated on one path form while routing/backend access is reached through another normalized path form after `StripPrefix` processing. This is most relevant in multi-route proxies where a protected route and an unprotected/static route share backend path space.

Safe validation pattern:

```text
/tenant-admin/../public/canary
/tenant-admin/%2e%2e/public/canary
/prefix//protected-canary
/prefix/%2fprotected-canary
```

Use a synthetic route such as `/protected-canary` that returns only `skillz-traefik-canary`. Send each path as a single request and record:

| Raw path | Route/auth decision | Backend observed path | Canary reached? |
| --- | --- | --- | --- |
| `/prefix/%2fprotected-canary` | unauthenticated route | `/protected-canary` | yes/no |

Do not perform high-volume fuzzing against production proxies. Avoid claiming auth bypass unless the proof shows an unauthenticated or lower-privilege request reached a route that should require auth.

## PDM `.pdm-plugins` pre-CLI execution boundary

This PDM advisory extends the existing package-manager file-boundary theme: repository-controlled content may execute before PDM has parsed the operator's intended command. The risky assessment shape is contributor-controlled repository -> developer/CI runs `pdm ...` -> plugin code runs as the invoking user before the command can safely reject or ignore the project.

Safe validation pattern:

1. Use a temporary repository and a PDM version affected by GHSA-qq6c-99pv-prvf.
2. Add a `.pdm-plugins` payload that writes only a local marker file such as `.skillz-pdm-plugin-canary`.
3. Run a benign command that the real workflow uses, such as `pdm --version`, `pdm install --check`, or `pdm config -l`, from inside the repository.
4. Confirm whether the marker appears before any dependency installation or intended command behavior.

Do not write shell profiles, SSH files, package credentials, CI configuration, or system paths. If the runner has release tokens or signing keys, document their presence only as privilege context; never read or print token values.

## Evidence to capture

Strong evidence includes:

- exact package/component version and affected advisory ID;
- the trust boundary: unauthenticated request, contributor-controlled repo, user-controlled generator option, redirect target, or normalized path;
- the privileged sink reached: MCP tool handler, generated test execution, credential-bearing redirect, protected route, or PDM plugin execution;
- canary-only transcript, generated file, HTTP request/response table, or filesystem marker;
- a clear statement of scope and impact without sensitive data.

## Reporting heuristics

- Lead with reachability and boundary crossing, not package names.
- Separate similar-looking "agent" findings: unauthenticated MCP tool execution differs from PR-controlled MCP config and from OAuth/CORS MCP session exposure.
- For redirect issues, prove header leakage with fake credentials before discussing real-token risk.
- For proxy issues, include raw bytes or exact URL encoding; normalization bugs often collapse under client-side rewriting.
- For package-manager issues, state the actor who controls the repository and the user/runner context that executes PDM.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, CISA KEV, and GitHub advisory updated/published feeds. Newly published availability-only items in python-zeroconf, Netty HTTP/2, gRPC, Joi, and Netty Redis aggregation were not promoted as standalone pages because they did not add a reusable offensive operator workflow beyond resource-exhaustion validation. Sparse identifier-persistence and analytics-URL leakage advisories were tracked in state without publication until a clearer exploit-path or bug-hunting heuristic emerges.
