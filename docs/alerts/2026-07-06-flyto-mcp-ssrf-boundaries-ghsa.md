# flyto-core HTTP MCP execution and SSRF guard-boundary checks

Source: hourly offensive-security scan, 2026-07-06. Primary entries: GitHub Advisory Database [GHSA-h9f9-h6gm-wc85](https://github.com/advisories/GHSA-h9f9-h6gm-wc85) / CVE-2026-55786 and [GHSA-794r-5rp2-fpg8](https://github.com/advisories/GHSA-794r-5rp2-fpg8) / CVE-2026-55787.

These advisories are durable for operators because they expose two reusable agent-platform seams: an HTTP MCP route that bypasses the normal API authentication and module-denylist path, and a URL-fetch guard that checks only native private ranges while IPv6 transition addresses can still route to embedded IPv4 loopback, RFC1918, link-local, or metadata destinations. Keep proofs to inert module calls, route/auth decision tables, owned callbacks, and explicit lab canaries only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-h9f9-h6gm-wc85](https://github.com/advisories/GHSA-h9f9-h6gm-wc85) / CVE-2026-55786 | `flyto-core` `POST /mcp`, versions `>= 2.26.2, < 2.26.4` | unauthenticated JSON-RPC `tools/call` requests can reach `execute_module`, including modules that eventually run shell-backed actions, while analogous REST execution routes enforce auth and filtering | MCP/agent assessments should compare every transport and route family, not just the documented REST API, for equivalent auth, denylist, and dangerous-tool controls. |
| [GHSA-794r-5rp2-fpg8](https://github.com/advisories/GHSA-794r-5rp2-fpg8) / CVE-2026-55787 | `flyto-core` URL validation / HTTP atomic modules, versions `<= 2.26.2` | `validate_url_ssrf` blocks hardcoded native private ranges but misses IPv4-mapped, IPv4-compatible, 6to4, and NAT64 address forms that can embed private IPv4 targets | URL allowlist and SSRF reviews should include parser-normalized destination families, not only literal host strings or native IP ranges. |

## Operator triage

Prioritize targets where one of these is true:

1. `flyto serve` or a wrapper exposes `POST /mcp` on a shared host, developer workstation, CI runner, container bridge, internal network, or `0.0.0.0` bind.
2. The deployment has shell, process, file, HTTP, browser, package, or workflow modules registered and callable through MCP tools.
3. Product documentation or reverse proxy rules protect `/api/*` routes but do not explicitly protect `/mcp` or other agent transports.
4. Low-privilege workflow authors can supply URLs to `http.get` or sibling modules that return response bodies.
5. The target runs in a dual-stack, NAT64, 6to4, cloud, Kubernetes, or container environment where transition-form addresses may route to internal services.

Lower priority: single-user local-only labs where the route is unreachable from any attacker-controlled context, deployments without dangerous modules, or URL-fetch modules that never return response body, status, timing, or error detail to a lower-trust caller.

## Replayable validation boundaries

### HTTP MCP auth-parity harness

Use this only in a disposable flyto-core lab or an explicitly authorized target where agent-platform route testing is in scope.

- Preconditions: affected version, known bind host/port, a harmless built-in or test module that returns a fixed marker, and an account state that proves the analogous REST route requires authentication.
- Confirm normal API execution behavior first: unauthenticated REST execution should fail, while an authenticated test principal can call the inert module if intended.
- Send an unauthenticated JSON-RPC `tools/call` request to `/mcp` for the inert module. Capture only status code, tool name, module ID, response marker, and absence/presence of `Authorization`.
- Positive evidence: `/mcp` executes or dispatches the module without credentials even though the equivalent REST route requires credentials or denylist checks.
- Negative controls: patched `2.26.4` or later, a reverse proxy rule that blocks unauthenticated `/mcp`, and a module ID that should be denied by policy.
- Do not run shell commands, read files, collect environment variables, exfiltrate prompts, or publish command-execution payloads. If a dangerous module must be referenced, stop at route reachability and denylist/parity evidence.

Report this as **MCP transport authentication drift**, not simply RCE. Strong evidence includes bind address, route family, request/response IDs, auth headers intentionally omitted, module allow/deny policy, and patched-route behavior.

### IPv6 transition-address SSRF guard harness

Use this when workflow authors or lower-trust users can provide URLs to flyto-core HTTP modules.

- Preconditions: affected version, one owned external callback endpoint, one approved lab-internal canary service if internal reachability is in scope, and a matrix of URL forms to test.
- Start with an owned external callback to prove the module performs server-side fetches and returns or logs enough evidence to distinguish server fetch from browser fetch.
- Test transition forms against only approved canaries. Useful classes are IPv4-mapped IPv6, IPv4-compatible IPv6, 6to4, NAT64 well-known prefix, and NAT64 local-use prefix.
- Positive evidence: a URL that embeds an otherwise blocked canary destination passes validation and produces callback, status, timing, or response-marker evidence.
- Negative controls: direct native blocked address rejected, patched `2.26.3` or later, and a public IPv6 address that should remain allowed.
- Do not target cloud metadata, loopback admin panels, Kubernetes APIs, databases, or production private services unless the program gives a specific canary for that exact destination. Never capture real metadata or internal service responses.

Capture a decision table rather than a payload dump:

| URL class | Expected policy | Observed behavior | Evidence |
| --- | --- | --- | --- |
| Direct native private canary | rejected | rejected or fetched | validation error or canary marker |
| IPv4-mapped canary | rejected after unwrapping embedded IPv4 | rejected or fetched | callback/status/marker |
| NAT64 or 6to4 canary | rejected when it maps to a blocked IPv4 destination | rejected or fetched | callback/status/marker |
| Public owned callback | allowed | fetched | callback log |

## Reporting notes

- Lead with the crossed boundary: **unauthenticated MCP route to module dispatch** or **workflow URL to internal fetch through IPv6 transition normalization gap**.
- Include version, bind address, route path, authentication state, module name category, URL class, normalized destination, response-body exposure, and patched-version negative controls.
- Keep all artifacts synthetic: inert module markers, fake workflow names, owned callback domains, disposable internal services, and redacted headers.
- Avoid impact inflation. Claim host command execution only if an authorized lab proves it safely; otherwise report the stronger, safer finding as authentication/denylist drift reaching a dangerous-tool dispatch path.
