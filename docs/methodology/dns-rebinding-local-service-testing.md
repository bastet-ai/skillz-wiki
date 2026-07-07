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
