# MCP Java CORS and Ray Dashboard file-boundary checks

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-hv2w-8mjj-jw22](https://github.com/advisories/GHSA-hv2w-8mjj-jw22) / CVE-2026-34237 for the Model Context Protocol Java SDK, and [GHSA-j3mh-qmjj-xp83](https://github.com/advisories/GHSA-j3mh-qmjj-xp83) / CVE-2026-32981 for Ray Dashboard.

This page is durable because the pair highlights two reusable operator patterns: browser-origin trust crossing into internal agent transports, and AI/ML dashboards exposing static-file handlers that can become local file disclosure primitives.

## What changed

- **MCP Java SDK wildcard CORS** — Java servlet SSE and streamable HTTP transports emitted `Access-Control-Allow-Origin: *`. An attacker-controlled web page can make a victim browser open an internal MCP SSE endpoint, read the returned session event, and then drive follow-up requests through the browser as a relay.
- **Ray Dashboard static path traversal** — Ray Dashboard, commonly exposed on port `8265`, accepted traversal sequences in static file handling before 2.8.1, allowing reads outside the intended asset directory.
- **Common boundary** — both issues sit on developer/AI infrastructure that teams often bind to localhost, VPN, or flat internal networks. The operator value is testing whether browser-reachable origins or dashboard routes can cross that assumed internal boundary.

## Operator triage

1. **Find reachable MCP transports:** search scoped assets and internal web portals for Java MCP servers exposing `/sse`, streamable HTTP, servlet endpoints, or custom agent-tool transport paths. Record whether the endpoint is reachable only from a browser on the trusted network, from VPN, or directly from the internet.
2. **Check CORS on event streams:** send an `Origin: https://attacker.example` header to SSE and streamable HTTP routes. A wildcard `Access-Control-Allow-Origin: *` on an endpoint that returns a session identifier is a browser-read boundary, not just a header hygiene issue.
3. **Map Ray dashboards:** look for `:8265`, Ray dashboard titles, `/api/`, `/static/`, and cluster status pages. Prioritize unauthenticated dashboards and dashboards reachable from shared workstations, notebooks, jump boxes, or model-development VPCs.
4. **Separate file disclosure from cluster RCE:** this advisory is about static-file traversal. Do not imply Ray job submission or code execution unless a separate authorized test proves those routes are exposed and reachable.
5. **Correlate with agent access:** if the MCP server or Ray dashboard has access to credentials, model artifacts, prompt logs, notebook workspaces, or deployment metadata, report those as scoped impact candidates without collecting sensitive content.

## Replayable validation boundaries

### MCP Java browser-origin proof

- Use a lab MCP Java server or an explicitly approved test server. Do not use a victim's real browser session or production agent session IDs.
- Confirm the endpoint returns CORS headers with a synthetic origin:

```http
GET /sse HTTP/1.1
Host: internal-mcp.example
Origin: https://operator-controlled.example
Accept: text/event-stream
```

- A vulnerable transport returns `Access-Control-Allow-Origin: *` and an SSE event containing a session or endpoint identifier that browser JavaScript can read cross-origin.
- Demonstrate only with a synthetic session. Redact session IDs and avoid sending tool calls that access files, secrets, customer data, or external services.
- Strong evidence: request/response headers, transport type, SDK/package version, origin used, and a sanitized event showing that cross-origin JavaScript could read the session bootstrap data.

### Ray Dashboard file-read proof

- Stay inside a disposable Ray instance or a customer-approved test node. Do not read real secrets, SSH keys, cloud tokens, model weights, prompt logs, or user notebooks.
- Confirm dashboard reachability and version first. If version disclosure is unavailable, keep proof to a harmless local marker file created for the test.
- Test traversal only through the static file route identified in scope. Use a benign target such as a marker under `/tmp` on a lab host or a non-sensitive OS release file if explicitly allowed.
- A safe proof shows that traversal escapes the static directory and returns the marker content. It does not need broad filesystem enumeration.
- Strong evidence: dashboard URL, authentication state, Ray version or build evidence, sanitized traversal request, and response containing only the synthetic marker.

## September 22 follow-up: Open VSX deployment-level CORS reflection → token theft chain

The open-vsx.org deployment (VS Code extension marketplace; [GHSA-px7g-fw3g-w264](https://github.com/advisories/GHSA-px7g-fw3g-w264) / [CVE-2026-90882](https://nvd.nist.gov/vuln/detail/CVE-2026-90882)) returned `Access-Control-Allow-Origin` **reflecting the requesting origin together with `Access-Control-Allow-Credentials: true`** on the authenticated `/user/` endpoint family — `/user`, `/user/tokens`, `/user/namespaces`, `/user/search/{name}`, `/user/namespace/{name}/members`. Because `/user/csrf` was readable the same way, the reflection simultaneously defeated the CSRF token on write endpoints, chaining to `/user/token/create` to mint (and exfiltrate) a personal access token with publish/delete rights over the victim's namespaces.

Operator value beyond the MCP Java case:

- **Deployment-level vs application-level CORS.** The headers were emitted by the CDN/edge layer, not the application — the Open VSX software sets `allowCredentials(true)` against exactly one derived origin and defines no `/user/` CORS mapping. When testing CORS, treat the response header as evidence about the *deployment*, not the code: a reflection you can trigger proves nothing the app config explains, and the vendor "no config produces this" statement is itself confirmation the fix is infrastructure-side. Fingerprint by sending two distinct synthetic `Origin:` values and diffing the reflected pair (`ACAO` value + `ACAC`).
- **CSRF-token readability converts CORS-read into CORS-write.** Any credentialed-readable endpoint that returns the CSRF token (or a token seed) collapses the classic "GET is read-only" boundary. On credentialed APIs with permissive CORS, enumerate endpoints for token/secret material before concluding the finding is disclosure-only; the chain proof is: reflected ACAO+ACAC on the token endpoint → cross-origin `fetch(..., {credentials:'include'})` reads the token → cross-origin POST replays it. Demonstrate only against your own account on the real service or a lab deployment; the strongest bounded proof stops at reading a disposable token you then revoke.
- **Publisher-identity theft is supply-chain access.** An exfilable marketplace publish token is an extension-update RCE channel against the token owner's install base; report the token type and its capability scope (publish/delete rights), not the value.

## Reporting heuristics

- Lead with the failed trust boundary:
  - MCP Java: a browser from an arbitrary origin can read internal agent-transport session bootstrap data.
  - Ray: a dashboard static-file path can escape its asset directory and read local files.
- Include preconditions: network position/browser reachability for MCP, Ray Dashboard exposure and vulnerable version for Ray, and whether authentication or VPN was required.
- Avoid overclaiming. Wildcard CORS without readable sensitive responses is weak; path traversal without a sensitive file or synthetic marker is incomplete.
- Tie impact to the tested environment only: internal agent tool access, cluster metadata, prompt/log artifacts, notebook workspaces, or deployment credentials should be described as potential targets unless explicitly proven with safe canaries.
