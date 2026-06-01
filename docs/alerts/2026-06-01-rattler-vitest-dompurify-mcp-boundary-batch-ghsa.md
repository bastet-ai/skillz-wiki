# Rattler/Pixi install writes, Vitest dev-server code execution, DOMPurify selectedcontent XSS, and MCP HTTP auth boundaries

Source: GitHub Security Advisories, updated 2026-06-01: [GHSA-q53q-5r4j-5729](https://github.com/advisories/GHSA-q53q-5r4j-5729) / CVE-2026-47425, [GHSA-2h32-95rg-cppp](https://github.com/advisories/GHSA-2h32-95rg-cppp) / CVE-2026-47428, [GHSA-5xrq-8626-4rwp](https://github.com/advisories/GHSA-5xrq-8626-4rwp) / CVE-2026-47429, [GHSA-87xg-pxx2-7hvx](https://github.com/advisories/GHSA-87xg-pxx2-7hvx) / CVE-2026-47423, [GHSA-63gr-g7jc-v8rg](https://github.com/advisories/GHSA-63gr-g7jc-v8rg), and [GHSA-4g6j-g789-rghm](https://github.com/advisories/GHSA-4g6j-g789-rghm) / CVE-2026-48119.

This batch is durable for offensive operators because each advisory maps to a reusable boundary test: package-manager entry-point path traversal, browser/dev-test server trust collapsing into file write and Node execution, sanitizer bypass via browser DOM re-cloning, unauthenticated MCP HTTP access to master-key tools, and authenticated agent result forgery across tenant-owned monitors.

## What changed

- **rattler / pixi noarch entry-point write** — `rattler <0.43.2` parsed `noarch:python` entry-point names with only trimming before joining them onto the install prefix. A malicious conda package can place `..`, separators, backslashes, or absolute paths in `info/link.json` entry points, causing executable wrappers to be written outside the intended prefix or clobbering in-prefix tools. Downstream `pixi` and `rattler-build` consumers share the install path; fixed in pixi `0.69.0` and rattler-build `0.65.0`.
- **Vitest browser-mode reflected script to API-token compromise** — `@vitest/browser >=4.0.17,<4.1.6` and `>=5.0.0-beta.0,<5.0.0-beta.3` inserted the `otelCarrier` query parameter as JavaScript source in `/__vitest_test__/`. Same-origin script execution can read `VITEST_API_TOKEN` and call authenticated browser APIs; the published impact chain writes `vite.config.ts` so Vitest/Vite reload executes Node-side payload code.
- **Vitest UI/API file read/write and execution boundary** — `vitest <4.1.0` exposed `/__vitest_attachment__` and related API/browser-mode file operations with path-cleaning gaps and privileged write/execute operations. Exposing Vitest UI/API to a network host can be equivalent to granting file read/write and script execution to clients with the API token; Windows path handling adds a direct arbitrary-file-read path via `\\?\\..\\` traversal.
- **DOMPurify `selectedcontent` sanitizer bypass** — `dompurify 3.4.4` allowed `<selectedcontent>` by default. Chromium/WebKit can re-clone selected `<option>` content after DOMPurify has already walked that subtree, reintroducing event-handler markup into the returned string before insertion fires XSS.
- **AgenticMail MCP HTTP auth bypass** — `@agenticmail/mcp <0.9.27` starts a Streamable HTTP `/mcp` endpoint with `--http` / `MCP_HTTP=1` but no HTTP authentication. Remote clients that reach the port can initialize a session and call tools forwarded by the server with its own `AGENTICMAIL_MASTER_KEY`, including gateway/admin tools.
- **Nezha service-monitor result forgery** — Nezha accepts service-monitor `TaskResult` messages from authenticated agents based on existing service ID only. A low-privilege user with one valid agent can forge monitoring results for another user's service ID, corrupt current/history state, and inject attacker-controlled result text into victim-owned notifications.

## Operator triage

1. **Prioritize package-install trust boundaries** where untrusted conda packages, private channels, generated lockfiles, CI bootstrap jobs, or agent-managed environments use `pixi`, `rattler-build`, `py-rattler`, or rattler directly.
2. **Treat developer/test servers as exploitable surfaces** when Vitest UI, API, or browser mode binds beyond localhost, is reachable through tunnels, cloud workspaces, Codespaces-like environments, shared runners, or preview boxes.
3. **Look for clickable dev-server links** in issue trackers, PR comments, logs, CI artifacts, or chat. The browser-mode `otelCarrier` path needs a victim to load a crafted runner URL while the server is active.
4. **Map sanitizer-to-sink flows** for DOMPurify: attacker-controlled HTML sanitized with DOMPurify `3.4.4` as a string and then inserted via `innerHTML`, template rendering, rich-text preview, CMS block rendering, email preview, or Markdown/HTML import.
5. **Inventory MCP HTTP transports** that forward server-side credentials to tool calls. `@agenticmail/mcp` is the concrete package, but the heuristic applies to any MCP server exposing Streamable HTTP/SSE without an independent auth layer.
6. **For Nezha, separate agent auth from task authorization**: the bug needs a valid low-privilege agent credential, then an unrelated victim service ID.

## Replayable validation boundaries

### rattler / pixi entry-point path write

- Build a disposable conda `noarch:python` package in a lab with `info/link.json` entry-point names that attempt to escape the environment scripts directory to a temp canary path.
- Install with an affected `rattler`, `pixi`, or `rattler-build` consumer inside a container or throwaway prefix.
- Capture intended prefix, malicious entry-point metadata, actual written path, file mode, and whether an existing in-prefix executable was clobbered.
- Do not target system `PATH`, developer tools, or persistent user config on a live host. A temp canary executable is enough.

### Vitest browser-mode token and config-write chain

- Reproduce in a disposable project running affected `@vitest/browser` in watch/browser mode.
- Use a benign `otelCarrier` payload first to prove same-origin script execution on `/__vitest_test__/`.
- If code-execution proof is explicitly authorized, write only a harmless marker into a temporary config or test file and let Vitest/Vite reload it; do not alter real project config.
- Evidence should include package version, bind host, runner URL, token exposure route, API call used, and benign marker execution.

### Vitest UI/API exposed-file boundary

- Confirm the API/UI bind address and whether it is reachable from another machine, container, workspace peer, or tunnel.
- Retrieve only the API token from the served Vitest UI page in an authorized lab; do not scrape unrelated project files.
- On Windows, validate the `\\?\\..\\` path-normalization issue with a synthetic `secret.txt` outside the project root.
- For write/execute impact, use Vitest's own test-file or config reload behavior with a harmless temp marker; report exposure of `allowWrite` / `allowExec` semantics after patching.

### DOMPurify `selectedcontent` XSS check

Use the advisory's minimal payload in a local page that mirrors the target sink:

```js
const dirty =
  '<select><button><selectedcontent></selectedcontent></button>' +
  '<option selected=javascript:1>' +
  '<img src=x onerror=alert(1)>x' +
  '</option></select>';
const clean = DOMPurify.sanitize(dirty);
document.body.innerHTML = clean;
```

- Confirm the vulnerable exact version (`3.4.4`) and browser family. The bypass was reproduced in Chromium/WebKit paths; Firefox behavior differs.
- Replace `alert(1)` with a harmless in-page marker for reports.
- The strongest reports prove the full application path: attacker input → DOMPurify string sanitization → returned string inserted into DOM.

### AgenticMail MCP HTTP auth bypass

- Start a lab `@agenticmail/mcp <0.9.27` instance with `MCP_HTTP=1` or `--http` and a synthetic master key.
- From a separate unauthenticated client, send MCP `initialize` to `/mcp`, capture the `mcp-session-id`, then call a non-destructive master-key-documented tool such as `setup_guide`.
- Do not invoke destructive tools (`delete_agent`, relay/domain setup, cleanup) against shared systems. Listing tool availability and a read-only call is sufficient.
- Report reachability of the HTTP port, lack of HTTP auth, server-side master-key forwarding, tool called, and package version.

### Nezha service-monitor result forgery

- Use two lab users/tenants: victim owns a service monitor; attacker owns one authenticated agent.
- Submit a forged `TaskResult` from the attacker agent for the victim service ID with a unique benign result string.
- Verify only cross-tenant state corruption or notification text injection in the lab. Do not falsify production monitoring data.
- Report the mismatch: outbound task dispatch enforces selected/owned servers, while inbound result handling accepts an existing service ID without confirming reporter assignment or owner coverage.

## Reporting heuristics

- For package-manager writes, show path control and install context. A dependency version alone is weak; a persistent executable path or clobbered command in an automated workflow is strong.
- For Vitest, avoid framing it as a production app bug unless the dev/test server is actually reachable by an attacker or a victim can be induced to load the runner URL. Include bind address and trust path.
- For DOMPurify, include the sanitizer version, browser, sanitized output or fired marker, and the application sink. Mention `selectedcontent` re-cloning as the bypass mechanism.
- For MCP HTTP, distinguish server authentication to upstream services from client authentication to the MCP transport. The flaw is unauthenticated clients borrowing server-side tool credentials.
- For Nezha, keep impact to integrity/cross-tenant monitor control unless paired with a separate credential or notification execution path.

## Notes on skipped items from this scan

- CISA KEV remained catalog `2026.05.29` with PAN-OS CVE-2026-0257 already reflected.
- PortSwigger research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, and Disclosed sitemap had no separate new promotable offensive-operator deltas in this pass.
