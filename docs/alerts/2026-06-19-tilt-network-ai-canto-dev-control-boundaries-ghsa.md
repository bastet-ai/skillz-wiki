# Tilt HUD, Network-AI, and Canto API control-boundary checks

Source: hourly offensive-security scan, 2026-06-19. Primary entries: GitHub advisories [GHSA-c73q-8xxr-rgqm](https://github.com/advisories/GHSA-c73q-8xxr-rgqm) / CVE-2026-55884, [GHSA-6m68-r693-78qx](https://github.com/advisories/GHSA-6m68-r693-78qx) / CVE-2026-55883, [GHSA-p749-9w62-w533](https://github.com/advisories/GHSA-p749-9w62-w533) / CVE-2026-55882, [GHSA-qw6v-5fcf-5666](https://github.com/advisories/GHSA-qw6v-5fcf-5666) / CVE-2026-54051, [GHSA-r78r-rwrf-rjwp](https://github.com/advisories/GHSA-r78r-rwrf-rjwp) / CVE-2026-48814, and [GHSA-9qfv-wgh2-m6p8](https://github.com/advisories/GHSA-9qfv-wgh2-m6p8) / CVE-2026-55374.

This batch is durable because each issue maps to a reusable offensive validation pattern: developer dashboards exposed beyond loopback, WebSocket anti-CSWSH tokens that are not actually session-bound, debug handlers mounted on privileged developer processes, agent command allowlists that validate strings but execute through shells, MCP/API servers that keep empty default secrets after incomplete fixes, and authenticated SDK path variables that can redirect bearer-tokened requests to unintended same-origin API routes.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-c73q-8xxr-rgqm / CVE-2026-55884 | Tilt HUD HTTP server | HUD routes had no authentication when bound to non-loopback interfaces, letting reachable callers trigger pre-defined resources, alter Tiltfile arguments, read engine state, and proxy into the Tilt apiserver with attached session material | Treat developer control planes as sensitive even when they are “local dev” tools; validate bind address, route auth, state-changing endpoints, and token-attaching internal proxies. |
| GHSA-6m68-r693-78qx / CVE-2026-55883 | Tilt HUD WebSocket stream | the WebSocket token was served by an unauthenticated endpoint, was not per-session, and direct clients without `Origin` could pass the fallback check | Test browser and non-browser WebSocket paths separately: token fetch, `Origin` handling, session binding, and streamed state exposure. |
| GHSA-p749-9w62-w533 / CVE-2026-55882 | Tilt HUD / apiserver debug handlers | Go `net/http/pprof` handlers were mounted under `/debug` without access control on exposed listeners | Include `/debug/pprof/*` and equivalent runtime diagnostics in dev-server recon; prove only route reachability or synthetic marker visibility, not live token or heap capture. |
| GHSA-qw6v-5fcf-5666 / CVE-2026-54051 | Network-AI sandbox policy | command allowlist globbing matched the full command string while execution used `/bin/sh -c`, so broad entries such as `git *` could also match shell metacharacter suffixes | In agent platform reviews, compare the parser used for allowlist decisions with the parser used by the execution sink; test metacharacters with inert markers only. |
| GHSA-r78r-rwrf-rjwp / CVE-2026-48814 | Network-AI MCP/SSE API | an incomplete fix left an empty default secret path that authorized non-browser callers when the service was exposed | Re-test patched claims for default-secret and non-browser transport paths; browser CORS fixes do not prove curl/SSRF/MCP client authentication. |
| GHSA-9qfv-wgh2-m6p8 / CVE-2026-55374 | `jleehr/canto-saas-api` request builder | unencoded path variables were inserted into authenticated API URLs, so attacker-controlled IDs could change the same-instance endpoint receiving the bearer token | Audit SDK wrappers where application-controlled identifiers become URL path segments before token attachment; use mocked API routes and disposable tokens. |

## Operator triage

1. **Start with reachability.** For Tilt and Network-AI, confirm whether the developer/control service is bound to `0.0.0.0`, a container bridge, a VPN interface, a shared Codespaces/devcontainer port, or any reverse proxy. If it is loopback-only and not browser-reachable through a relay, the exploitable surface is much narrower.
2. **Separate browser and direct-client paths.** CSRF/CORS/origin controls may affect browsers only. Test direct HTTP clients, WebSocket clients with no `Origin`, SSRF relays, and MCP/SSE transports independently.
3. **Map policy decisions to sinks.** For command allowlists, record the exact string evaluated by policy, the tokenization or glob rules, and the final executor (`execve` argv vs shell string). Parser mismatch is the finding.
4. **Use canaries, not secrets.** Evidence should be route access, inert state changes, synthetic stream markers, decision tables, or mocked-token routing. Do not dump heap profiles, extract real session tokens, invoke production Tilt resources, or read live API keys.

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

## Reporting notes

- State the crossed boundary precisely: **exposed dev dashboard to unauthenticated resource trigger**, **unauthenticated WebSocket token to state stream**, **debug handler to process-memory surface**, **allowlist glob to shell metacharacter execution**, **empty default secret to MCP tool invocation**, or **path variable to bearer-tokened API route confusion**.
- Include negative controls: loopback-only bind, patched Tilt, WebSocket token bound to an authenticated session, command execution via argv without a shell, configured non-empty MCP secret, and `rawurlencode()` path segment handling.
- Avoid mitigation-first framing in the finding body; focus on reachability, preconditions, exact trust boundary, canary evidence, and authorized impact.
