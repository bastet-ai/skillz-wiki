# Nebula Mesh, FUXA, MagicMirror, Langflow, AWS API MCP, and Anyquery boundary batch

Source: hourly offensive-security scan, 2026-06-08; updated 2026-06-10. Primary entries: GitHub advisories [GHSA-598g-h2vc-h5vg](https://github.com/advisories/GHSA-598g-h2vc-h5vg), [GHSA-273q-qgh5-wrj6](https://github.com/advisories/GHSA-273q-qgh5-wrj6), [GHSA-7hp6-g3pq-3pc3](https://github.com/advisories/GHSA-7hp6-g3pq-3pc3), [GHSA-w86f-rf9w-h3x6](https://github.com/advisories/GHSA-w86f-rf9w-h3x6), [GHSA-h9fj-c2qr-76g2](https://github.com/advisories/GHSA-h9fj-c2qr-76g2), [GHSA-8ghr-w65f-j3qr](https://github.com/advisories/GHSA-8ghr-w65f-j3qr), [GHSA-ph6f-2cvq-79hq](https://github.com/advisories/GHSA-ph6f-2cvq-79hq), [GHSA-vwmf-pq79-vjvx](https://github.com/advisories/GHSA-vwmf-pq79-vjvx), [GHSA-2cpp-j2fc-qhp7](https://github.com/advisories/GHSA-2cpp-j2fc-qhp7), [GHSA-hrj8-hjv8-mgwc](https://github.com/advisories/GHSA-hrj8-hjv8-mgwc), and [GHSA-9pg3-25fq-p6cc](https://github.com/advisories/GHSA-9pg3-25fq-p6cc).

This batch is durable because the advisories repeat operator-useful patterns: mesh-management API authorization drift, control-plane CSRF, YAML configuration injection, unauthenticated read-SSRF oracles, public AI-flow build execution, MCP filesystem-policy bypasses, and local automation script injection from SQL-controlled browser URLs.

## What changed

- **Nebula Mesh API ownership gaps** — non-admin operator API keys can mint API keys for other operators, re-enroll another operator's hosts, and mutate host/network/firewall resources when API handlers trust bearer authentication without the Web UI's per-CA ownership checks.
- **Nebula Mesh API-key redirect leakage** — the operator API-key creation handler redirects to `/ui/operators/<id>?new_key=<raw-token>&key_name=<name>`, placing a newly minted bearer token in browser history, proxy access logs, and cross-origin `Referer` headers if the detail page loads third-party assets. The same redirect also demonstrates why user-controlled names in `Location` query strings need URL encoding before they cross into logs, caches, or older proxy parsers.
- **Nebula Mesh UI CSRF** — mutating `/ui/*` routes process requests when the session cookie validates, so sibling-subdomain compromise, same-site injection, or browser behavior around `SameSite=Lax` can reach CA deletion, CA rotation, API-key minting, operator disablement, and settings changes.
- **Nebula Mesh agent config YAML injection** — operator-controlled host advanced fields such as `ListenHost` and `TunDevice` are interpolated into generated `config.yml`, allowing newline-based YAML injection that changes lighthouse, relay, or related agent behavior.
- **FUXA unauthenticated Socket.IO SSRF** — `DEVICE_WEBAPI_REQUEST` and `DEVICE_PROPERTY` handlers can be reached without authentication and return response bodies from server-side HTTP, OPC UA, or ODBC requests to the Socket.IO client.
- **FUXA TDengine DAQ SQL injection** — tag identifiers sent through `/api/daq` or Socket.IO `DAQ_QUERY` can bypass single-quote escaping with backslashes when TDengine backs the DAQ store, exposing historical PLC tag values.
- **FUXA scheduler privilege escalation** — authenticated non-admin users can create or modify scheduled device actions that write tags or run server-side scripts normally reserved for administrators.
- **MagicMirror `/cors` SSRF and secret expansion** — unauthenticated `/cors?url=` fetches arbitrary URLs server-side and expands `**ENV_VAR**` placeholders before the request, turning a proxy feature into an internal-read and environment-secret exfiltration primitive.
- **Langflow public flow-build RCE** — `POST /api/v1/build_public_tmp/{flow_id}/flow` is intentionally unauthenticated for public flows but can accept attacker-controlled flow data whose custom component code reaches unsandboxed `exec()`.
- **AWS API MCP filesystem restriction bypass** — affected MCP server versions can bypass `no-access` and `workdir` file-access policy modes, exposing local file contents through the assistant/MCP context.
- **Anyquery browser plugin AppleScript/JXA injection** — local SQL writes to browser tab plugin tables can inject newline-bearing URLs into `osascript` templates on macOS, converting SQL control into host command execution.

## Operator triage

1. **Prioritize control planes that manage trust roots or OT devices:** Nebula Mesh CA/operator APIs and FUXA device/scheduler routes matter more than ordinary CRUD because successful validation can affect mesh identity, traffic steering, PLC tags, or automation scripts.
2. **Inventory alternate transports:** do not stop at REST routes. FUXA's Socket.IO events and Langflow's public-flow build endpoint show how unauthenticated or lower-privileged paths often sit outside the main UI authorization model.
3. **Map policy claims to sinks:** for MCP filesystem policy, MagicMirror CORS proxying, and Nebula ownership controls, compare the documented restriction to the exact code path that consumes file paths, URLs, bearer tokens, or generated configs.
4. **Use canaries before sensitive destinations:** prove server-side fetch with a tester-controlled HTTP/DNS endpoint, prove file reads with planted scratch files, and prove code execution with inert marker commands in disposable labs.
5. **Separate single-bug findings from chains:** Nebula YAML injection is most impactful when chained with API ownership bypass; FUXA scheduler escalation assumes non-admin authentication; Langflow RCE requires a reachable public flow build path.
6. **Capture negative controls:** valid versus cross-operator resource IDs, normal versus newline-containing YAML fields, authorized versus unauthenticated Socket.IO events, safe URL versus internal/canary URL, stored public flow versus supplied flow data.

## Replayable validation boundaries

### Nebula Mesh API, UI, and config boundaries

- Use only program-owned or lab Nebula Mesh instances. CA and host enrollment operations can disrupt real mesh identities.
- For API ownership checks, create two scoped non-admin operators in a lab, then attempt cross-operator API-key creation, host re-enrollment, host CRUD, network CRUD, and firewall reads/writes with one operator's bearer token against the other's resource IDs.
- For API-key redirect leakage, create a disposable operator key through the lab UI and capture only the `303 Location` header or a lab reverse-proxy log line showing the query-string shape. Immediately revoke the test key. Do not publish raw tokens, screenshots containing complete keys, browser-history exports, or real proxy logs.
- For UI CSRF, use a lab operator session and a benign state change such as creating then deleting a disposable test object. Avoid rotating, retiring, or deleting production CAs.
- For YAML injection, set a disposable host's advanced field to a newline-containing value and compare generated config before and after. Do not redirect real production mesh traffic; a lab-only marker key or harmless config flag is enough.
- Report the trust boundary: operator token to admin token, operator A to operator B host, browser-origin page to CA-management action, or advanced text field to generated agent config.

### FUXA Socket.IO, DAQ, and scheduler boundaries

- Validate only in FUXA labs, test tenants, or explicitly scoped OT ranges. Do not write real PLC tags or run scripts that affect physical processes.
- For SSRF, connect to Socket.IO and send `DEVICE_WEBAPI_REQUEST` or `DEVICE_PROPERTY` only toward a tester-controlled callback service first. Record the callback and the echoed response behavior; do not target cloud metadata or internal control networks without explicit authorization.
- For TDengine DAQ SQLi, use a disposable TDengine-backed FUXA lab with planted tag rows. Demonstrate the escape with synthetic tag IDs and return only canary rows.
- For scheduler escalation, use a non-admin test user and schedule a no-op or scratch-tag write on a simulated device. Do not schedule repeated actions against production projects.
- Include auth mode, Socket.IO namespace/event names, user role, DAQ backend, and whether the response body or scheduled action result was observable.

### MagicMirror SSRF and placeholder expansion

- Discover only in authorized scope; MagicMirror commonly listens on port 8080, but internet-wide opportunistic probing is out of scope for this wiki guidance.
- First send `/cors?url=` to a tester-controlled HTTP endpoint and capture method, source IP, and user agent.
- If placeholder expansion is in scope, use a harmless lab environment variable such as `MM_CANARY=skillz-canary` and a callback URL containing `**MM_CANARY**`.
- Avoid requesting cloud metadata, localhost admin panels, private network hosts, or real secret variables unless the customer explicitly authorizes those destinations and values.

### Langflow public flow build

- Confirm the target exposes a public flow and the `build_public_tmp` endpoint before testing supplied `data` behavior.
- Use a disposable Langflow lab or program-provided test flow. Custom component code should write a benign marker or perform a controlled callback; never read environment variables, credentials, model data, or files from production.
- Report the route, public flow ID, whether authentication was absent, the supplied-data override, and the minimal evidence that custom code executed.

### AWS API MCP and Anyquery local automation

- For AWS API MCP, test policy modes (`no-access`, `workdir`, unrestricted) with planted local canary files. The finding is policy bypass into MCP client context, not extraction of real credentials or source files.
- Include the MCP server package name, version, configured file-access mode, configured workdir, path form that bypasses it, and where the file content appeared in the assistant/tool transcript.
- For Anyquery, treat this as a local privilege/context boundary: a user who can run SQL against Anyquery on macOS can reach AppleScript/JXA execution in browser plugins. Validate in a throwaway macOS lab with `do shell script` writing a marker file.
- Do not publish command payloads that steal browser data, cookies, keychain material, or cloud credentials.

## Reporting heuristics

- Lead with the **boundary crossed**, not the CVE list: operator-to-admin, cross-tenant mesh host takeover, unauthenticated socket to internal fetch, public flow to Python `exec()`, MCP path policy to local file exposure, or SQL-controlled URL to `osascript`.
- Include route/event/sink evidence: `/api/v1/operators/{id}/api-keys`, `/ui/operators/{id}?new_key=...`, `/api/v1/hosts/{id}/reenroll`, `/ui/*` mutating route, `DEVICE_WEBAPI_REQUEST`, `/api/daq`, `/api/scheduler`, `/cors`, `build_public_tmp`, MCP file argument, or Anyquery browser tab table.
- Keep proof artifacts reversible: disposable CAs, simulated hosts, canary HTTP servers, scratch files, marker commands, and test PLC tags.
- Call out environmental dependencies: TDengine backend, MagicMirror network exposure, public Langflow sharing, AWS API MCP file-access mode, macOS browser plugin installation, or Nebula Mesh operator role model.
- Treat secret-in-URL findings as evidence-handling sensitive: redact all but a short prefix/suffix, note every observed sink class (`Location`, access log, browser history, `Referer`), and prove token usability only with a disposable key in a lab-owned tenant.

## Notes on skipped items from this scan

- Availability-only DoS entries, sparse XSS/header-hardening entries, CSV/formula injection, and generic historical package issues were marked processed without standalone publication.
- Older updated-feed items for Langflow, MagicMirror, AWS API MCP, and Anyquery were promoted here because they add durable agent/MCP, SSRF, and automation-boundary validation patterns not covered by the immediately previous batch.
