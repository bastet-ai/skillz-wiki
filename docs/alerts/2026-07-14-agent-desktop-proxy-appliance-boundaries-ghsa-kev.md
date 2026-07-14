# Anyquery SSRF, yutu MCP file-write, TidGi import RCE, TsDProxy IP spoofing, Auth0 query-token, and SonicWall SMA1000 checks

Source: hourly offensive-security scan, 2026-07-14 late GitHub advisory and CISA KEV wave. Primary entries: [GHSA-hwrq-8wxh-q4xv](https://github.com/advisories/GHSA-hwrq-8wxh-q4xv) / CVE-2026-54628, [GHSA-2c7f-fxww-6w6c](https://github.com/advisories/GHSA-2c7f-fxww-6w6c) / CVE-2026-50158, [GHSA-9hc2-hjx8-q6pv](https://github.com/advisories/GHSA-9hc2-hjx8-q6pv), [GHSA-pqg7-v6wh-3pfp](https://github.com/advisories/GHSA-pqg7-v6wh-3pfp), [GHSA-ffq7-hh2j-r24p](https://github.com/advisories/GHSA-ffq7-hh2j-r24p) / CVE-2026-50157, and CISA KEV entries [CVE-2026-15409](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) / [SNWLID-2026-0008](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008) plus [CVE-2026-15410](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

This batch is durable because each item maps to a repeatable operator boundary: unauthenticated SQL-compatible access reaching server-side URL fetchers, MCP tool parameters escaping a declared filesystem root, desktop knowledge-base imports executing repository-provided startup modules, reverse proxies appending trusted client IP state to attacker-supplied forwarding headers, OAuth bearer tokens accepted from logged URLs, and appliance routes crossing into SSRF or administrator-scoped command execution.

!!! warning "Authorized validation only"
    Keep proofs to disposable Anyquery/yutu/TidGi/TsDProxy/Auth0-Symfony labs, owned callback hosts, fake bearer tokens, synthetic repositories, temporary files, and owned/lab SonicWall SMA1000 appliances. Do not query cloud metadata, production internal services, real TiddlyWiki workspaces, live Tailscale backends, production OAuth tokens, customer appliance configs, shell startup files, service paths, credentials, or command payloads beyond inert markers.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-hwrq-8wxh-q4xv](https://github.com/advisories/GHSA-hwrq-8wxh-q4xv) / CVE-2026-54628 | Anyquery `server` mode | MySQL-compatible clients can create SQLite virtual tables such as `json_reader`/`log_reader` that fetch arbitrary URLs | Extend the existing Anyquery server-mode check from file writes to SQL-to-SSRF reachability. |
| [GHSA-2c7f-fxww-6w6c](https://github.com/advisories/GHSA-2c7f-fxww-6w6c) / CVE-2026-50158 | yutu MCP `caption-download` tool | Caller-supplied `file` reaches `os.Create()` instead of the `YUTU_ROOT`-confined root API | Test MCP tool parameters for filesystem-root bypasses, not just command invocation. |
| [GHSA-9hc2-hjx8-q6pv](https://github.com/advisories/GHSA-9hc2-hjx8-q6pv) | TidGi Desktop / TiddlyWiki import | Imported repository `.tid` files can register startup modules that auto-execute when the workspace boots | Treat desktop note/wiki repository imports as code-loading surfaces. |
| [GHSA-pqg7-v6wh-3pfp](https://github.com/advisories/GHSA-pqg7-v6wh-3pfp) | TsDProxy reverse proxy | Incoming `X-Forwarded-For` / `X-Real-IP` are not stripped before proxy forwarding | Add forwarding-header spoof checks to identity-aware proxy assessments. |
| [GHSA-ffq7-hh2j-r24p](https://github.com/advisories/GHSA-ffq7-hh2j-r24p) / CVE-2026-50157 | Auth0 Symfony SDK Authorizer | Protected routes may accept bearer access tokens from URL query parameters as well as `Authorization` headers | Test token transport invariants and log/referer replay exposure. |
| [CVE-2026-15409](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) / [CVE-2026-15410](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | SonicWall SMA1000 appliances | CISA lists exploited unauthenticated SSRF and authenticated-admin code-injection conditions | Add SMA1000 to perimeter-appliance validation queues with SSRF callback and inert command-boundary evidence only. |

## Replayable validation boundaries

### Anyquery SQL-to-SSRF virtual table proof

1. Start Anyquery in `server` mode in an isolated lab with no cloud role credentials and egress restricted to owned callback infrastructure plus a synthetic internal canary listener.
2. Connect to the MySQL-compatible listener with the same authentication posture the assessment is testing.
3. Create a virtual table using the vulnerable URL-fetching module family (`json_reader`, `log_reader`, or the app-supported equivalent) and point it first at an owned public callback URL.
4. Repeat only against a lab-owned private canary such as an RFC1918 listener you control; do not probe metadata services, production hosts, or third-party internal networks.
5. Capture a decision table: listener bind address, client auth state, raw URL class, resolved address class, callback observed, rows returned, and patched/egress-denied control.

Report this as **network SQL listener -> SQLite virtual table URL fetcher -> server-side request from Anyquery host**. Pair it with the earlier server-mode file-write check when both are present; keep evidence to callback IDs and synthetic response markers.

### yutu MCP `caption-download` filesystem-root bypass

1. Run yutu with `YUTU_ROOT` pointing at a temporary directory and expose the MCP server only inside a lab.
2. Invoke `caption-download` with a normal in-root path to establish the expected confined behavior.
3. Invoke the same tool with a traversal or absolute-path canary aimed at a disposable path outside `YUTU_ROOT`, for example under `/tmp/yutu-mcp-canary/`.
4. Verify only marker-file creation/overwrite semantics and process ownership; never target existing files, dotfiles, service config, web roots, cron paths, or credentials.
5. Add controls for other caption file-write methods that use the confined root API, patched builds, nonexistent parent directories, and read-only filesystem mounts.

Report this as **MCP file parameter -> unconfined `os.Create()` sink -> write outside declared tool root**. Strong evidence is a path-normalization table plus before/after marker existence.

### TidGi Desktop repository-import startup module execution

1. Create a disposable TidGi/TiddlyWiki workspace and a local Git repository containing only harmless `.tid` canaries.
2. Add a startup-module-shaped `.tid` file that performs an inert marker action such as writing a temporary file inside the lab profile or logging `TIDGI-STARTUP-CANARY`.
3. Import the repository through the same TidGi workflow a user would use for untrusted or shared wikis.
4. Reboot/open the imported workspace and observe whether TiddlyWiki auto-registers the module and runs `exports.startup()` without an explicit trust prompt.
5. Add controls for patched TidGi behavior, non-startup module types, restricted `platforms` fields, and importing the same repository with startup execution disabled if available.

Report this as **repository import -> `.tid` module registration -> desktop startup code execution**. Do not include payloads that spawn shells, read user files, or persist outside the disposable workspace.

### TsDProxy forwarding-header spoofing

1. Place a lab backend behind TsDProxy that echoes only request headers and a harmless route decision, not secrets.
2. Authenticate as a disposable Tailscale user if the deployment requires it.
3. Send requests containing controlled `X-Forwarded-For` and `X-Real-IP` values such as `127.0.0.1` or a lab allowlisted address.
4. Record whether the backend receives attacker-supplied values before or alongside the real client IP appended by the proxy.
5. Add controls for stripped identity headers, patched proxy behavior, backend frameworks that trust the first vs last forwarded IP, and routes that do not use forwarded IPs for authorization.

Report this as **trusted overlay user -> proxy preserves client-supplied forwarding headers -> backend IP-trust confusion**. Avoid using production admin routes; prove with route/decision markers only.

### Auth0 Symfony query-parameter bearer-token acceptance

1. Build a disposable Symfony route protected by the Auth0 Symfony SDK Authorizer and issue a fake or lab-scoped access token with no production privileges.
2. Confirm baseline access with a redacted `Authorization` bearer-token header.
3. Repeat with the token supplied only in a query parameter and no `Authorization` header.
4. Capture whether the route authenticates, whether redirects/logging/referrer sinks retain the token, and whether a patched SDK rejects query-token transport.
5. Test negative controls: missing token, malformed token, wrong audience, expired token, and an endpoint outside the Authorizer guard.

Report this as **protected HTTP route -> bearer token accepted from URL query -> replay-prone token transport**. Evidence should use redacted/fake tokens and sanitized access logs.

### SonicWall SMA1000 KEV appliance boundary checks

1. Confirm explicit authorization and product ownership before touching any SMA1000 appliance. Prefer vendor lab images or customer-approved maintenance windows.
2. For CVE-2026-15409, validate only SSRF reachability with an owned callback and route/auth evidence. Do not request cloud metadata, internal management ports, or third-party hosts.
3. For CVE-2026-15410, test only as an administrator in a lab and stop at command-construction evidence or an inert marker command such as printing a nonce to a controlled log.
4. Record appliance version, route family, auth state, callback/marker ID, and patched negative control.
5. Keep the report bounded to the preconditions CISA lists: unauthenticated remote SSRF for CVE-2026-15409 and specific authenticated-administrator command execution conditions for CVE-2026-15410.

Report these as **perimeter appliance route -> unintended outbound request** and **administrator-controlled input -> command wrapper execution boundary**. Do not publish exploit payloads or perform state-changing appliance actions.

## Reporting notes

- Lead with preconditions: listener exposure, MCP transport reachability, desktop import trust model, proxy/backend IP-trust policy, token transport accepted by the route, appliance ownership, and authenticated role.
- Prefer compact evidence tables over payload dumps: actor, input field/header/path, validated identity/root, sink reached, canary observed, and patched control.
- Redact callback tokens, bearer tokens, Tailscale identities, repo URLs from customer environments, appliance hostnames, internal IPs, and any file contents not created solely as markers.
- Same-hour advisories for CA key zeroization on error paths, elevated-privilege configuration disclosure, CPU amplification, tar-bomb/OOM, generic prototype pollution, and sparse OpenStack Mistral exposure were marked processed without promotion because this run did not identify a safer reusable workflow beyond existing secret-handling, DoS-exclusion, prototype-pollution, or exposed-API testing guidance.
