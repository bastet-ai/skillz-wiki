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

## July 30 follow-up: outbound authority, secret, and file-write parity

Six later flyto-core advisories expand the same workflow-author trust boundary. Versions before `2.26.7` can expose operator environment values or write outside the configured sandbox; versions through `2.26.6` also contain outbound-request and verification-callback gaps. Version `2.26.7` is the fixed control identified by all six records.

| Advisory | Caller-controlled input | Privileged behavior added later |
| --- | --- | --- |
| [GHSA-c9hr-64h3-gxpc / CVE-2026-67424](https://github.com/advisories/GHSA-c9hr-64h3-gxpc) | initial URL accepted by `http.get`, `http.request`, or `http.batch` | automatic redirect reaches a destination that was never revalidated |
| [GHSA-pgwh-4jj4-qm8v / CVE-2026-67428](https://github.com/advisories/GHSA-pgwh-4jj4-qm8v) | URL supplied to an HTTP-emitting module outside the guarded sibling family | module performs the fetch because an `ssrf_protected` metadata label is not an enforcing guard |
| [GHSA-jx74-cqjv-2c67 / CVE-2026-67426](https://github.com/advisories/GHSA-jx74-cqjv-2c67) | unauthenticated `flyto-verification` `/run` `callback_url` | service posts a result and attaches its internal runner-secret header |
| [GHSA-qq9q-xgm3-xv9g / CVE-2026-67425](https://github.com/advisories/GHSA-qq9q-xgm3-xv9g) | public `base_url` for LLM, agent, model, or vector modules | module attaches an operator-configured provider key |
| [GHSA-hr7p-wg7r-hg9m / CVE-2026-67427](https://github.com/advisories/GHSA-hr7p-wg7r-hg9m) | `${env.VAR}` in workflow data | pre-dispatch interpolation reads a host variable even while `env.get` is denied |
| [GHSA-2956-977x-2w3r / CVE-2026-67429](https://github.com/advisories/GHSA-2956-977x-2w3r) | `image.download` `output_dir` plus `output_path`, or output paths in sibling media/document modules | process writes outside `FLYTO_SANDBOX_DIR`; `image.download` also accepts attacker-hosted bytes |

### Build a module-by-capability differential

Do not test only the nominally guarded module. Inventory every registered module that can open a socket, attach a credential, resolve a workflow variable, or write a file. Record the enforcement function reached by each concrete code path.

| Capability | Positive control | Differential rows | Bounded positive evidence |
| --- | --- | --- | --- |
| outbound fetch | guarded `http.get` to an owned listener | sibling HTTP/API/GraphQL/notification/AI module; direct URL; one owned redirect | unapproved canary listener receives a marker request |
| callback | configured engine callback | `/run` with an owned alternate callback and no auth | alternate listener receives a fake runner-key fingerprint |
| provider request | fixed provider endpoint | caller-selected owned `base_url` | listener receives only a deliberately fake provider-token marker |
| environment read | denied `env.get` | `${env.SKILLZ_CANARY}` in text, URL, header, and nested values | resolver returns the inert canary despite module denial |
| file write | `file.write` under the sandbox | `image.download` and one format-constrained sibling to a disposable sibling directory | marker file exists outside sandbox but inside the temporary fixture |

For redirects, use two owned listeners and capture initial parsed authority, DNS answer, every `Location`, resolved next-hop authority, socket peer, and returned marker. Compare direct private-class canaries, public-to-public redirects, public-to-prohibited-class lab redirects, cross-port redirects, loops, and over-limit chains. Never substitute cloud metadata or a real internal service for the second listener.

For callback and provider-key tests, seed unique fake values such as `runner-canary-A` and `provider-canary-B`. Record only a hash or short fingerprint. A positive requires **caller chooses authority -> flyto attaches the identified fake credential class -> owned listener receives it**. An outbound request without the marker is not credential disclosure.

For environment-policy parity, place only `SKILLZ_CANARY=env-marker-C` in the process. Compare direct `env.get`, whole-value interpolation, embedded interpolation, nested object/list values, and trace/result serialization. Stop when the inert value crosses the denied policy boundary; do not enumerate process variables or test real key names.

For file confinement, create `tmp/sandbox` and `tmp/sibling`, set `FLYTO_SANDBOX_DIR` to the former, and serve a random text marker from an owned local HTTP server. Test absolute, relative, sibling-prefix, normalized `..`, caller-selected base, and symlink rows as an unprivileged user. A positive is an actual marker write under `tmp/sibling`, not merely a resolved path string. Never target startup files, credentials, service configuration, executable search paths, or files outside the disposable tree.

### Reporting boundaries

Keep each edge independent:

- a metadata tag without an enforcing call is **module-policy drift**, not proof that every module is exploitable;
- a redirect callback proves final-destination reachability only when the owned second listener receives it;
- an alternate provider or callback authority proves secret relay only with a fake marker attached;
- pre-dispatch interpolation bypasses the environment capability policy only when the denied module and interpolation path are tested in the same configuration; and
- an outside-sandbox write is not code execution unless a separately authorized consumer executes that exact artifact.

Preserve the module ID, caller role, raw and normalized selector, guard reached, credential class, redirect chain or final path, affected-versus-`2.26.7` result, and synthetic marker hash. Do not publish the advisories' live-secret, metadata, or shell-oriented examples as assessment payloads.

## October 14 follow-up: denylist grammar vs namespaced module IDs

The [GHSA-h9f9-h6gm-wc85](https://github.com/advisories/GHSA-h9f9-h6gm-wc85) record was enriched in the updated feed on 2026-10-14 with the full line-level source-to-sink trace. Two details are new to operators beyond the auth-parity rule already on this page:

1. **The module denylist never matched the dangerous module in the first place.** The default filter is `_DEFAULT_DENYLIST = ["shell.*", "process.*"]`, but the registry ID that reaches `asyncio.create_subprocess_shell` is `sandbox.execute_shell` — the pattern is anchored on the leading name segment, so a dot-namespaced module ID whose dangerous verb is not the first segment slips through. Even if the MCP route had applied `module_filter` (it does not — `handle_jsonrpc_request` is called without one), `sandbox.execute_shell` would still have been reachable. **Grep rule: enumerate every registered module ID (registry decorators, `tools/list` output) and match each denylist/allowlist pattern against the full namespaced ID list. A denylist written against category names while the registry keys on dotted IDs is decoration, not a control.**
2. **Three independent gates all had to fail together, and only one was the missing auth.** Route-level `Depends(require_auth)` absent, per-request `module_filter` absent, and denylist-grammar miss. The REST sibling route enforces both auth *and* the filter — so the differential probe in the harness above (same module, REST vs `/mcp`) isolates which gate is missing rather than stopping at "auth bypassed." The reproduction confirmed root-inside-container execution with no `Authorization` header; default bind is `127.0.0.1`, so on a shared host the browser-pivot and co-tenant threat models apply even without a `0.0.0.0` flag, and `--host 0.0.0.0` makes the whole chain network-reachable.

Sweep this against any agent platform that registers modules under namespaced IDs: feed `tools/list` IDs through the product's own denylist matcher offline and diff what survives. Proof stays bounded to inert marker modules and decision tables; do not invoke shell-class modules even in labs — dispatch reachability plus matcher-diff evidence is the finding.
