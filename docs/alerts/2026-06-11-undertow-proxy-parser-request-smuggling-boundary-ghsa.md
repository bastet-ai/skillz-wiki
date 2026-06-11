# Undertow proxy-parser request-smuggling boundary

Source: hourly offensive-security scan, 2026-06-11. Primary entries: GitHub advisories [GHSA-3gv6-g396-9v4r](https://github.com/advisories/GHSA-3gv6-g396-9v4r) / CVE-2026-28367, [GHSA-8v4x-mgvp-p658](https://github.com/advisories/GHSA-8v4x-mgvp-p658) / CVE-2026-28368, and [GHSA-vqqj-9cmv-hx43](https://github.com/advisories/GHSA-vqqj-9cmv-hx43) / CVE-2026-28369 for Undertow request-smuggling parser differentials.

This is durable for operators because it gives a reusable edge-stack test pattern: **the upstream proxy and Undertow disagree about where headers end, what counts as a header name, or whether leading whitespace is valid, so one HTTP byte stream becomes two different request interpretations**.

## Why it matters for assessments

Many Java application estates place Undertow behind a load balancer, CDN, reverse proxy, WAF, API gateway, or service mesh ingress. The authorization and routing decision often happens at the first hop, while the application server makes the final request interpretation. The Undertow advisories highlight three differential classes worth checking in any approved request-smuggling review:

- header-block terminator confusion, including non-standard `\r\r\r` handling;
- header-name parsing differences between Undertow and the proxy;
- first-header lines that begin with one or more spaces and are normalized by Undertow even though the form is invalid.

The target is not generic malformed-request fuzzing. The useful operator workflow is to prove a **proxy-to-origin parser split** with harmless canaries, then show whether that split can affect routing, authentication context, cache keys, or request queue boundaries.

## What to map first

1. Confirm written authorization for HTTP request-smuggling testing. These probes can desynchronize shared infrastructure if run carelessly.
2. Identify the front door and the origin stack:
   - CDN, WAF, load balancer, reverse proxy, ingress controller, service mesh, or Apache Traffic Server / Google Cloud Classic Application Load Balancer where applicable;
   - Undertow-backed services, such as WildFly, JBoss EAP, Quarkus deployments using Undertow, or embedded Undertow applications.
3. Collect safe baseline responses for a disposable route such as `/`, `/health`, `/robots.txt`, or a lab-only canary endpoint.
4. Use a dedicated test host or tenant whenever possible. Avoid production endpoints with shared connection pools unless the rules of engagement explicitly allow smuggling validation.
5. Keep payloads non-destructive: no credential reuse, no admin paths, no hidden data fetches, and no cross-user request targeting.

## Safe validation boundary

Use single-connection probes against lab or explicitly scoped targets. Prefer a purpose-built request-smuggling harness that can show front-end and back-end response boundaries without spraying traffic.

Minimal raw-socket shape for a lab canary:

```python
#!/usr/bin/env python3
import socket
import ssl

host = "app.example.test"
port = 443
payload = (
    b"GET /canary-a HTTP/1.1\r\n"
    b"Host: app.example.test\r\n"
    b"User-Agent: skillz-smuggle-canary\r\n"
    # Replace this line only in an authorized lab to test one parser differential at a time.
    b"X-Canary: baseline\r\n"
    b"\r\n"
    b"GET /canary-b HTTP/1.1\r\n"
    b"Host: app.example.test\r\n"
    b"Connection: close\r\n\r\n"
)

ctx = ssl.create_default_context()
with socket.create_connection((host, port), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        s.sendall(payload)
        print(s.recv(8192).decode("latin1", errors="replace"))
```

For Undertow-specific lab checks, mutate only one boundary at a time and record whether the proxy and origin disagree:

- a header block ending with the advisory-highlighted `\r\r\r` sequence;
- a crafted header name that the proxy rejects, forwards, rewrites, or interprets differently from Undertow;
- a first header line that begins with spaces before the header name.

Do not include a weaponized desync payload in public reports. If the program requires proof beyond a parser split, coordinate a private replay with the triage team using canary-only paths and a test account.

## Evidence to capture

Strong evidence shows all of the following:

- exact proxy/origin topology that was in scope, including product/version when the customer can provide it;
- the raw request bytes, escaped safely in a file attachment or hex dump;
- baseline response on a normal request;
- differential response when the single malformed boundary is introduced;
- whether the effect is limited to rejection/normalization or reaches a second request, alternate route, cache key, auth decision, or queue desync;
- timestamps, connection reuse behavior, and correlation IDs for the tester-owned canary requests.

Keep evidence scoped to canary paths. Do not demonstrate access to another user request, protected production data, internal admin panels, or secrets.

## Reporting heuristics

- Lead with the boundary: **front-end proxy and Undertow parse the same HTTP stream differently**.
- Name the differential class, not just "request smuggling": terminator confusion, header-name confusion, or leading-whitespace normalization.
- Include the smallest harmless impact observed: cache poisoning possibility, route confusion, auth-gate bypass precondition, or confirmed queued-request desync.
- Separate confirmed impact from plausible impact. A parser mismatch without desync is still useful evidence, but it is not the same as account takeover or data exposure.
- Recommend a private reproduction window if the next proof step could disturb shared infrastructure.

## Notes on skipped adjacent items

Updated-feed Keycloak token-revocation and WebAuthn policy-bypass advisories from the same scan were already represented in state as processed identity-boundary items and did not require a new page this hour. Generic availability-only and local-crash entries remained processed without publication unless they exposed a reusable operator boundary.
