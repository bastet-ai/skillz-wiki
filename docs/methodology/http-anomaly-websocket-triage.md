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

## Request smuggling sanity check

Before claiming request smuggling, distinguish it from ordinary connection reuse:

- Use raw-byte captures, not screenshots of confusing response order.
- Compare direct-to-origin and through-proxy behavior when authorized.
- Show a front-end/back-end parser disagreement or a harmless cross-request effect, not just delayed responses.
- Keep canaries single-user and single-connection; never target other users or shared production traffic.
- Include a control request that demonstrates normal HTTP pipelining or keep-alive behavior does **not** explain the result.

## Safe boundaries

- Stay inside authorized targets and test accounts.
- Use synthetic object IDs, tenants, rooms, files, and callback domains.
- Do not exfiltrate real messages, documents, tokens, or private tenant data through WebSocket tests.
- Do not run volumetric race or timing tests on shared production systems without explicit approval.
- For desync work, stop at harmless canary effects and raw-byte evidence.

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
