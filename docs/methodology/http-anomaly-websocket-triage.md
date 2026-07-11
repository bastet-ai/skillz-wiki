---
title: HTTP anomaly and WebSocket triage
---

# HTTP anomaly and WebSocket triage

Use this playbook when a web target produces too many near-identical HTTP or WebSocket responses for manual review. The goal is not to replace reasoning; it is to rank response outliers, preserve replay context, and turn “interesting” differences into safe, reportable validation.

## Operator signal

PortSwigger Research published several durable 2025 workflows that are worth carrying into day-to-day testing:

- [Introducing HTTP Anomaly Rank](https://portswigger.net/research/introducing-http-anomaly-rank) frames large Intruder/Turbo Intruder result sets as an outlier-ranking problem instead of repeated sorting by status, length, or word count.
- [WebSocket Turbo Intruder: Unearthing the WebSocket Goldmine](https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine) highlights a common blind spot: many scanners and testers stop at the protocol upgrade, leaving authorization, race, injection, and parser-state bugs inside WebSocket messages under-tested.
- [Beware the false false-positive: how to distinguish HTTP pipelining from request smuggling](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling) is the reporting discipline check: connection reuse artifacts can look like request smuggling, so desync claims need raw-byte proof and a differential effect.

The reusable lesson: rank first, replay second, classify only after you can explain the parser or state boundary that produced the anomaly.

GitHub Advisory updates in July 2026 added a concrete parser-differential example for ASGI/WebSocket stacks: [Daphne before 4.2.2 reconstructed a raw handshake request from Twisted-parsed headers and passed it to Autobahn, where Python `splitlines()` treated non-standard bytes such as `\x0b`, `\x0c`, `\x1c`, `\x1d`, `\x1e`, and `\x85` as line separators](https://github.com/advisories/GHSA-xh68-hfp5-5x5m). The operator value is not the specific bytes alone; it is the workflow of testing whether the HTTP server, framework adapter, WebSocket handshake library, and ASGI application agree on where one header ends and the next begins.

## When to use this

- Intruder, Turbo Intruder, ffuf, httpx, nuclei, or custom fuzzing generated hundreds or thousands of responses.
- Sorting by one column hides the interesting cases because the target emits dynamic lengths, redirects, localized errors, or cache noise.
- The app upgrades to WebSocket and important business actions continue over frames instead of REST endpoints.
- A raw HTTP test suggests smuggling or connection confusion, but the evidence could also be normal keep-alive or pipelining behavior.

## Inputs to preserve

For every candidate anomaly, keep enough context to replay it exactly:

- full request bytes or Burp request item
- response status, headers, body length, word count, line count, timing, and redirect target
- connection behavior: new connection vs reused connection, HTTP version, TLS ALPN, proxy path, and upstream host
- payload slot name and value
- authenticated role, tenant, object ID, and any CSRF/session markers used during the test
- for WebSockets: upgrade request, selected subprotocol, origin, cookies, first server frame, message direction, opcode, and frame payload

## Workflow: anomaly-ranked HTTP review

1. **Cluster the boring baseline.** Send a small negative-control corpus first: known-good value, known-bad value, empty value, overlong value, encoded separator, and random marker.
2. **Collect multiple response features.** Do not rely on one metric. Track status, length, words, lines, header set, redirect host/path, title, JSON keys, error token, and timing bucket.
3. **Rank outliers.** Prioritize responses that differ across multiple dimensions, such as same status but unique header/body token, normal length but unusual redirect, or common error page with a distinct JSON key.
4. **Replay top anomalies manually.** Re-send the exact request in Repeater or a controlled script, then vary one input at a time.
5. **Prove the boundary.** Tie the anomaly to a meaningful trust boundary: parser differential, authorization decision, object lookup, template rendering, cache key, file path, backend route, or upstream service selection.
6. **Add negative controls.** Show that adjacent payloads fail and a fixed or validated path rejects the same input.

## Triage patterns that pay off

| Anomaly | What to test next | Operator value |
| --- | --- | --- |
| Same status, shorter body | hidden authorization branch, early exception, alternate template | May reveal IDOR, route confusion, or validation bypass. |
| Same length, unique word/token | dynamic error detail, backend stack message, feature flag branch | Often exposes parser or integration boundaries. |
| Redirect target changes | open redirect, post-login return URL, host header trust | Pair with [return URL scheme-bypass testing](return-url-scheme-bypass-testing.md). |
| Header set changes | cache, CORS, auth challenge, proxy routing | Useful for cache poisoning, CORS, and edge/origin differentials. |
| Timing outlier | race window, blind injection, upstream callback, lock contention | Replay carefully; do not turn timing probes into DoS. |
| One tenant/object differs | missing ownership filter, stale cache key, relation scope drift | Use two disposable accounts and synthetic objects only. |

## Workflow: WebSocket replay and fuzzing

1. **Capture the upgrade.** Save the HTTP request that produced `101 Switching Protocols`, including cookies, `Origin`, `Sec-WebSocket-Protocol`, and path/query parameters.
2. **Map message types.** Record client and server frames for login/bootstrap, subscribe/join, create/update/delete, search, export, and admin-like actions.
3. **Identify authority fields.** Mark tenant IDs, room IDs, user IDs, document IDs, role names, workflow IDs, and action names inside frame payloads.
4. **Replay with role changes.** Use two lab accounts. Attempt only canary reads/writes across owned objects and explicitly out-of-scope objects created for the test.
5. **Probe parser boundaries.** Mutate JSON types, duplicate keys, nested arrays/objects, encoded separators, null bytes if the stack permits them, and oversized-but-safe strings.
6. **Test race candidates intentionally.** If the app acknowledges frame order, send paired canary operations concurrently against disposable resources and record ordering. Avoid high-volume race floods unless the rules of engagement permit it.
7. **Preserve frame evidence.** Reports should include the upgrade request, sanitized frame pair, expected authorization decision, observed decision, and a REST or UI negative control if one exists.

## Workflow: WebSocket handshake parser differentials

Use this when the target is a Python/ASGI, Node, Java, or reverse-proxied WebSocket service where one component parses the HTTP upgrade and another component rebuilds or reinterprets it before application code sees the connection.

1. **Fingerprint the handshake path.** Record the edge proxy, application server, framework adapter, WebSocket library, and app-visible ASGI/WSGI/request-scope headers when disclosed by headers, errors, docs, or lab instrumentation.
2. **Build a harmless upgrade baseline.** Use an owned account and a WebSocket route that only echoes, subscribes to a canary room, or returns a synthetic server marker. Save the exact raw `GET` upgrade request.
3. **Mutate header values, not just header names.** Test safe canary values containing unusual line-boundary bytes, encoded separators, obs-fold-like whitespace, duplicate header names, mixed casing, and delimiter-adjacent markers. Keep one mutation per request.
4. **Compare app-visible scope.** The signal is an injected or rewritten header, subprotocol, origin, host, authorization marker, tenant marker, or client IP value visible to the application after a successful or rejected handshake.
5. **Prove a security boundary.** Tie the differential to something the app trusts: `Origin`, `Host`, `X-Forwarded-*`, auth-bearing cookies/headers, selected subprotocol, tenant/room routing, or feature flags. A parser mismatch with no trusted sink is a hardening bug, not an exploit path.
6. **Add negative controls.** Show normal headers, adjacent safe bytes, patched versions, or direct-to-origin requests do not create the same app-visible header set.
7. **Keep denial-of-service out of scope unless approved.** Some adjacent WebSocket advisories involve unlimited frame/message sizes. For normal bug-hunting reports, document configured limits or a tiny capped rejection test; do not send large frames to shared services.

Evidence table template:

| Test | Raw header marker | App-visible value | Expected decision | Observed decision |
| --- | --- | --- | --- | --- |
| Baseline | `X-Canary: ws-baseline` | `ws-baseline` | One header only | One header only |
| Differential candidate | `X-Canary: a<separator>b` | `a` plus injected canary header, or rejection | Reject or preserve value as one header | Record exact result |
| Negative control | Adjacent encoded/escaped marker | Preserved as one value, or rejection | No injected header | Record exact result |

## Request smuggling sanity check

Before claiming request smuggling, distinguish it from ordinary connection reuse:

- Use raw-byte captures, not screenshots of confusing response order.
- Compare direct-to-origin and through-proxy behavior when authorized.
- Show a front-end/back-end parser disagreement or a harmless cross-request effect, not just delayed responses.
- Keep canaries single-user and single-connection; never target other users or shared production traffic.
- Include a control request that demonstrates normal HTTP pipelining or keep-alive behavior does **not** explain the result.
- For WebSocket upgrade desync claims, prove where the disagreement occurs: edge proxy, HTTP server, handshake library, framework adapter, or application-visible scope. A successful `101` alone is not evidence of header smuggling.

## Safe boundaries

- Stay inside authorized targets and test accounts.
- Use synthetic object IDs, tenants, rooms, files, and callback domains.
- Do not exfiltrate real messages, documents, tokens, or private tenant data through WebSocket tests.
- Do not run volumetric race or timing tests on shared production systems without explicit approval.
- For desync work, stop at harmless canary effects and raw-byte evidence.
- For handshake parser tests, avoid injecting real credentials, cookies, bearer tokens, internal hostnames, or production tenant IDs. Use canary headers and disposable rooms/accounts.

## Reporting notes

A strong report leads with the boundary and the replay proof:

- “WebSocket `subscribe` frame trusts client-supplied `tenantId` after session auth.”
- “Fuzzed `redirect` parameter produced a unique redirect-host anomaly that persists across login.”
- “Front-end accepts one request boundary while origin parses another; single-connection canary proves queue poisoning.”

Include the original ranked result, exact replay request/frame, affected role, canary object, observed impact, and negative controls. Avoid saying “the scanner found it”; explain why the anomalous response is security-relevant.

## Sources

- [PortSwigger Research: Introducing HTTP Anomaly Rank](https://portswigger.net/research/introducing-http-anomaly-rank)
- [PortSwigger Research: WebSocket Turbo Intruder: Unearthing the WebSocket Goldmine](https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine)
- [PortSwigger Research: Beware the false false-positive: how to distinguish HTTP pipelining from request smuggling](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling)
- [GitHub Advisory: Daphne WebSocket handshake header smuggling through Autobahn `splitlines()` handling](https://github.com/advisories/GHSA-xh68-hfp5-5x5m)
- [GitHub Advisory: Daphne unlimited WebSocket frame/message sizes](https://github.com/advisories/GHSA-rrc9-mx66-ffcm)
