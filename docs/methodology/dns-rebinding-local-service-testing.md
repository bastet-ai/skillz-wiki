# DNS Rebinding Local-Service Testing

Use this workflow when an authorized assessment includes browser-reachable developer tools, appliance dashboards, loopback services, or private-network web applications that trust `localhost`, RFC1918 addresses, or browser-origin headers too much.

Primary source: GitHub Security Lab, [DNS rebinding attacks explained: The lookup is coming from inside the house!](https://github.blog/security/application-security/dns-rebinding-attacks-explained-the-lookup-is-coming-from-inside-the-house/) (June 2025).

## Operator value

DNS rebinding turns a victim browser into a network pivot without breaking the browser same-origin model: JavaScript is loaded from an attacker-controlled hostname, then later DNS answers for that same hostname resolve to `127.0.0.1`, a private IP, or an approved lab canary. If the target local service trusts network location, weak `Host` checks, or missing CSRF/CORS boundaries, the browser can interact with it as the same origin.

Promote a finding only when you can prove a meaningful boundary crossing, such as:

- Browser JavaScript can read or mutate a loopback/private service response that should not be reachable from web content.
- The service accepts a rebinding hostname in `Host` or absolute URLs where it should require a pinned local origin.
- A local admin/dev endpoint performs a state change without an explicit anti-CSRF or user-confirmation boundary.
- A private-network service exposes secrets, config, build artifacts, or agent/tool control through unauthenticated browser requests.

Do not report DNS rebinding just because a service listens on `127.0.0.1`; prove browser-mediated access to an operator-relevant endpoint.

## Scope and safety boundaries

- Use only owned domains, lab clients, and customer-approved targets.
- Use synthetic canary services for private-network tests; do not probe arbitrary internal hosts.
- Do not read real tokens, notebooks, cloud metadata, device config, customer data, or production secrets.
- Prefer route/auth decision tables and harmless canary values over destructive state changes.
- Avoid browser profiles with real accounts unless the program explicitly authorizes authenticated browser testing.

## Preconditions to check

1. A browser can load attacker-controlled JavaScript from an owned hostname.
2. The hostname's DNS answers can change quickly enough for the browser to re-resolve it.
3. The target service is reachable from the browser host after rebinding.
4. The target service accepts requests for the rebinding hostname, weak `Host` values, or no `Host` validation.
5. The target endpoint has meaningful read/write impact beyond availability.

## Lab canary setup

Use a dedicated domain such as `rebind-test.example` and a DNS service you control. Keep TTL low, but remember browsers and resolvers may cache longer than the authoritative TTL.

Decision table to capture:

| Phase | DNS answer | Browser URL | Expected evidence |
| --- | --- | --- | --- |
| Bootstrap | Public web server IP | `http://rebind-test.example:<port>/` | JavaScript loads from owned host |
| Rebind | Lab canary IP, `127.0.0.1`, or approved RFC1918 IP | Same origin URL | Browser sends request to rebound target |
| Validation | Same rebound IP | `/canary`, `/version`, or harmless route | Response marker or status proves boundary |

A minimal canary target can expose a harmless marker route:

```bash
python3 -m http.server 18080 --bind 127.0.0.1
```

Place only non-sensitive marker files in that directory. Never use this pattern to read real local files.

## Manual validation workflow

### 1. Fingerprint candidate services

From an authorized workstation or lab host, identify browser-reachable local/private web services:

```bash
# Loopback developer and agent consoles
for port in 3000 5000 8000 8080 8888 11434 18080; do
  curl -sS -m 2 -D - "http://127.0.0.1:${port}/" -o /tmp/rebind-${port}.body \
    | sed -n '1,20p'
done

# Approved private canary host only
curl -sS -m 2 -D - http://192.0.2.10:18080/canary -o -
```

Capture headers that imply trust boundaries:

- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- cookies without SameSite constraints
- admin/debug route names
- redirects or absolute links derived from `Host`
- JSON APIs without CSRF tokens

### 2. Test `Host` acceptance without DNS first

Before using a browser, check whether the service rejects unexpected hostnames:

```bash
curl -sS -m 2 -D - \
  -H 'Host: rebind-test.example' \
  http://127.0.0.1:18080/canary -o -

curl -sS -m 2 -D - \
  -H 'Host: attacker.invalid' \
  http://127.0.0.1:18080/canary -o -
```

Evidence is stronger when the service accepts arbitrary external-looking `Host` values or builds trusted links from them.

### 3. Prove same-origin rebound behavior with a harmless route

Host JavaScript on the public bootstrap server that repeatedly requests a canary path from the same origin:

```html
<!doctype html>
<meta charset="utf-8">
<title>DNS rebinding canary</title>
<pre id="out"></pre>
<script>
const out = document.getElementById('out');
async function probe() {
  try {
    const r = await fetch('/canary', { credentials: 'include', cache: 'no-store' });
    const text = await r.text();
    out.textContent += `${new Date().toISOString()} ${r.status} ${text.slice(0, 80)}\n`;
  } catch (e) {
    out.textContent += `${new Date().toISOString()} blocked ${e}\n`;
  }
  setTimeout(probe, 1000);
}
probe();
</script>
```

After the browser loads the page, switch DNS for `rebind-test.example` to the approved loopback/private canary. Record:

- authoritative DNS changes and timestamps
- browser network log showing requests to the same URL
- canary server access logs
- response marker, route status, or benign body snippet

### 4. Escalate only to authorized impact endpoints

If the canary route proves the browser can cross the boundary, test the least sensitive real endpoint that demonstrates impact:

```javascript
fetch('/api/version', { credentials: 'include', cache: 'no-store' })
  .then(r => r.text())
  .then(t => console.log(t.slice(0, 120)));
```

Good proof endpoints include `/version`, `/health`, `/whoami` with a synthetic lab user, or a canary-only setting. Avoid endpoints that dump environment variables, files, notebooks, token stores, model weights, queue contents, or device config.

## High-signal target patterns

Prioritize systems where rebinding has durable impact:

- AI/agent dashboards that expose tool execution, memory, MCP, browser, or file APIs on loopback.
- Developer servers with hot-reload, filesystem, package-install, or debug consoles.
- Router/NAS/printer/appliance admin panels reachable from the browser host.
- Local OAuth callback handlers and desktop helper services.
- Kubernetes, cloud, or CI helper UIs bound to private interfaces.
- Electron/native apps that expose HTTP bridges to web content.

## Evidence checklist

Include these artifacts in the report:

- Exact tested hostname, public bootstrap IP, rebound IP, and timestamps.
- DNS answers before and after rebinding.
- Browser request/response evidence for the same origin URL.
- Target service access logs or canary route hits.
- `Host`, `Origin`, cookie, CORS, and CSRF-relevant headers.
- Minimal impact proof with synthetic markers only.
- Preconditions and user-interaction requirement.

## When to stop

Stop testing if:

- The target rejects the rebinding hostname or requires a pinned `Host`.
- The only accessible endpoints are static or unauthenticated public content.
- Proving further impact would require reading secrets or changing production state.
- The program scope excludes browser-mediated local-network testing.

## Related Skillz Wiki pages

- [CORS Vulnerability Analysis Methodology](cors-vulnerability-analysis.md)
- [URL allowlists and canonicalization](../best-practices/url-allowlists-canonicalization.md)
- [Agent runtime trust boundaries](../best-practices/agent-runtime-trust-boundaries.md)

## October 1 follow-up: Lektor admin blueprint, the textbook rebinding target (folded)

**Lektor 3.3.14 / 3.4.0b15** ([GHSA-76hh-mx5x-4xrx](https://github.com/advisories/GHSA-76hh-mx5x-4xrx), 8.1): the CMS's local **admin API blueprint** has *no* CSRF tokens, no Origin/Referer validation, no CORS config, and no Host allowlist. A malicious web page can cross-origin POST to `newattachment`, `deleterecord`, `build`, `clean`, and `publish` from the victim's browser, writing arbitrary files, deleting pages, wiping build output, and triggering deployment, and with DNS rebinding the same page can also *read* endpoints for data disclosure.

This is the cleanest public reproduction of this page's precondition list, use it as the checklist exemplar: (1) service listens on loopback (dev-server admin UI), (2) state-changing endpoints with zero anti-CSRF, (3) no Host pinning, (4) meaningful impact (arbitrary file write through a "content editor"). Bug-hunt shortcut for any localhost dev/CMS tooling: fire a **cross-origin form POST** (simple request, no preflight) at each write endpoint from an owned page *before* attempting rebinding, if the write lands, Origin-based defenses were never the barrier and rebinding only adds the read leg. Prove with a canary attachment in a disposable project only.

## November 19 follow-up: the local MCP HTTP servers that shipped without Host or Origin checks (obsidian-sync-mcp + todoist-mcp, 2 GHSAs)

Two self-hosted **Streamable HTTP MCP servers** fell to the same browser-delivered pattern the same day, and together they pin down the two-check fix every local MCP/dev-server target should be tested against:

- **obsidian-sync-mcp <= 0.5.6** ([GHSA-mx6p-3fg7-v6pj](https://github.com/advisories/GHSA-mx6p-3fg7-v6pj), CVE-2026-77283, high, fixed 0.5.7): documented **no-auth mode** (empty `MCP_AUTH_TOKEN`, including the README "simplest" quickstart and the default docker-compose) dispatched every MCP method with zero per-request check. Any website the operator visits can rebind to `127.0.0.1` (or the operator's LAN/VPN/Docker-published address) and drive the full tool surface: `read_note`, `write_note`, `edit_note`, `delete_note`, `move_note`, `list_notes`, `list_folders`, `list_tags`, `get_note_metadata`. The 0.5.7 fix shows why **both** checks are needed: the Host check defeats classic rebinding, and the Origin check defeats the *direct* `fetch http://127.0.0.1:<port>/mcp` variant where the Host is genuinely loopback but the Origin is the attacker's site and wildcard CORS would leak the response. Non-browser MCP clients send no Origin, so an Origin check must not break them.
- **todoist-mcp `todoist-mcp-http` 10.3.1** ([GHSA-833v-v58w-294h](https://github.com/advisories/GHSA-833v-v58w-294h), CVE-2026-76807, critical): loopback-bound HTTP mode runs every tool with the **operator's server-side `TODOIST_API_KEY`**; the middleware validates that the *server's* token is configured, then calls `next()` without ever authenticating the browser caller, and `POST /mcp` hands the request straight to `StreamableHTTPServerTransport`. Rebinded browser JS gets add/complete/update/delete tasks, comments, reminders, labels, goals, assignments as the operator. The stdio entrypoint is not browser-reachable; only the HTTP transport is.

Operator rules:

1. **Server-credential-validated is not caller-authenticated.** In MCP HTTP mode, grep the request middleware for what the token check actually covers: validating that the server holds a valid upstream API key (todoist pattern) authenticates nothing about the caller. The caller must present its own secret (bearer) or pass Host+Origin pinning. Decision table: no-token + no-Host-check = full tool takeover; token-validated + no-Host/Origin = same takeover via server-held credential; caller-token required = safe (browsers attach no bearer).
2. **Test both browser variants separately on every local MCP/dev-server port.** Classic rebinding (attacker Host, rebinding DNS) and direct-loopback-fetch with attacker Origin (`fetch('http://127.0.0.1:PORT/mcp')` from an owned page). A service that survives one often dies to the other; wildcard `Access-Control-Allow-Origin` on `/mcp` is the tell for variant two.
3. **Fingerprint the whole MCP HTTP surface at once.** `for p in 3000 3001 8000 8080 30000..; curl -X POST http://127.0.0.1:$p/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'` on the authorized workstation: a `tools/list` response without credentials is the finding precondition; enumerate tools before escalating to any state-changing call. Validate only against your own running servers and disposable accounts; the write/delete legs (delete_note, delete-object) prove impact with your own canary items.
