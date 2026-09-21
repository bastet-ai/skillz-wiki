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

## July 28 Rust HTTP parser and identity-header update

A later unreviewed GitHub wave adds Rust parser variants and a proxy identity-canonicalization check:

- [GHSA-frmw-v2hf-gvj9](https://github.com/advisories/GHSA-frmw-v2hf-gvj9): Rouille forwards bare-LF header values into an upstream request;
- [GHSA-fgf8-ph7p-m275](https://github.com/advisories/GHSA-fgf8-ph7p-m275): Rouille forwards `Transfer-Encoding` after `tiny_http` has already de-chunked the body;
- [GHSA-5hc2-r3jq-vc45](https://github.com/advisories/GHSA-5hc2-r3jq-vc45): `tiny_http` treats any `Transfer-Encoding` value as chunked and discards `Content-Length`;
- [GHSA-5wm6-g4fr-88x8](https://github.com/advisories/GHSA-5wm6-g4fr-88x8) and [GHSA-998j-f97v-vpgr](https://github.com/advisories/GHSA-998j-f97v-vpgr): CR/LF acceptance crosses into request or response header serialization;
- [GHSA-f2m2-cc3f-h4j2](https://github.com/advisories/GHSA-f2m2-cc3f-h4j2): OpenShift `oauth-proxy` removes dash-form identity headers but may leave underscore aliases that WSGI or PHP later canonicalizes to the same application variable.

Treat these GitHub entries as leads until the exact source, affected build, deployment topology, and observed parser behavior are confirmed. The durable method is broader than any one library: compare the bytes and normalized fields at every hop, including transformations performed before a proxy reserializes the request.

### Two-hop parser fixture

Build a local chain with the candidate Rouille or `tiny_http` component in front of a mock origin that records raw bytes and parsed request boundaries. Run one mutation per fresh connection:

1. duplicate `Content-Length` / `Transfer-Encoding` controls;
2. a non-`chunked` transfer coding with a short inert body;
3. a chunked body that the first hop decodes before forwarding;
4. an inert request header containing a bare LF canary;
5. a response-header value derived from a harmless query or cookie marker containing encoded CR/LF;
6. the same fixtures against a patched or strict-parser negative control.

Record four artifacts: bytes sent to hop one, hop-one parsed fields/body, bytes reserialized toward hop two, and hop-two request/response boundaries. A useful positive result is not merely a 400/500 response. Show that the same input becomes a different message count, body length, header set, route, or cacheable response at the next hop.

Do not aim smuggling probes at shared production connection pools. Use canary routes, one connection per fixture, no victim traffic, and no protected endpoints. Do not open response-splitting output in a browser if doing so could trigger active content; preserve raw bytes instead.

### Dash-versus-underscore identity matrix

For an identity-aware reverse proxy, seed a mock upstream that reports only the normalized identity variable it receives. Use a disposable low-privilege user and fake identity values:

| Incoming client field | Proxy output to upstream | Expected result |
| --- | --- | --- |
| no identity header | proxy-generated authenticated identity only | accept baseline |
| `X-Forwarded-User: canary` | client value removed/replaced | authenticated identity only |
| `X_Forwarded_User: canary` | client alias removed before framework normalization | authenticated identity only |
| both forms with different canaries | all client forms removed | one proxy-generated value |
| case and repeated-header variants | canonicalized and removed | one proxy-generated value |

Capture raw ingress headers, proxy egress headers, the framework server-variable map, and the application-visible principal. The bounded finding is **client-supplied alias survives the trusted proxy -> upstream canonicalization merges it with the protected identity key -> application observes the canary principal**. Do not impersonate a real administrator or access another user's data; a fake principal echoed by a local upstream is sufficient.

Report parser and identity findings separately. An underscore alias is header canonicalization/identity confusion, not HTTP request smuggling unless it also changes message boundaries. Likewise, CR/LF acceptance is an injection primitive until a second parser or serializer demonstrates a security-relevant split.

## July 28 tunnel request-target preservation follow-up

[GHSA-fh2f-xfxc-q9cc / CVE-2026-54650](https://github.com/bablilayoub/openhole/security/advisories/GHSA-fh2f-xfxc-q9cc) adds a non-smuggling parser differential in `openhole` through 0.1.1. The server passed Go's decoded `r.URL.Path` through the tunnel rather than preserving the escaped request target. Encoded dot segments and separators could therefore arrive at a local backend as literal traversal or route separators even when ServeMux rejected the corresponding literal ingress path. Both server and CLI need the 0.1.2 request-target-preservation fix.

Use an isolated tunnel and a local backend rooted at `TEMP/web`, with one synthetic marker in `TEMP/sibling`. Record four representations of the same path: raw client request target, Go `URL.Path`, `EscapedPath()`, and the exact backend request target. Compare literal `../`, encoded dots, encoded slash, mixed/double encoding, and an ordinary encoded character. The backend should return only route identity and the synthetic sibling marker; do not point it at a real filesystem root.

A bounded positive result is **ingress encoded path passes the public mux -> tunnel forwards a decoded path -> local backend resolves the synthetic sibling marker or a protected route**. This is request-target normalization confusion, not request smuggling. Report backend canonicalization as a separate defense and repeat with both openhole components at 0.1.2; upgrading only one side does not prove the full tunnel preserves the target.

## July 29 Apache Traffic Server multi-protocol update

A July 29 unreviewed advisory wave extends this method to Apache Traffic Server (ATS) 9.x and 10.x deployments. The operator-relevant records are:

- [GHSA-5cvm-p8jm-mcrf / CVE-2026-58150](https://github.com/advisories/GHSA-5cvm-p8jm-mcrf): `Transfer-Encoding` accepted on HTTP/2 ingress and carried into an HTTP/1 downgrade;
- [GHSA-rphg-9r4x-89j3 / CVE-2026-57834](https://github.com/advisories/GHSA-rphg-9r4x-89j3): malformed chunk framing permits a request-boundary split;
- [GHSA-crqg-wq4g-597m / CVE-2026-58153](https://github.com/advisories/GHSA-crqg-wq4g-597m): HTTP/2 origin trailers are forwarded to HTTP/1 clients without the expected chunked framing;
- [GHSA-9jfm-2xhc-ghxj / CVE-2026-58155](https://github.com/advisories/GHSA-9jfm-2xhc-ghxj): over-long header names are truncated, creating header aliases, policy bypass, and request-smuggling preconditions;
- [GHSA-r6wf-4rwv-gf97 / CVE-2026-58156](https://github.com/advisories/GHSA-r6wf-4rwv-gf97): URL userinfo and port parsing can diverge from port-based access control;
- [GHSA-4c56-c2ph-pp8x / CVE-2026-65325](https://github.com/advisories/GHSA-4c56-c2ph-pp8x): a multiplexed HTTP/2 origin connection may be reused for a new hostname without checking that the server certificate covers that hostname; and
- [GHSA-h8g5-f6vh-4g26 / CVE-2026-24033](https://github.com/advisories/GHSA-h8g5-f6vh-4g26): an additional HTTP request/response-smuggling record whose initial description does not identify the exact differential.

The [Apache announcement thread](https://lists.apache.org/thread/5prl9glcm9g2swnq9hqxvnokylm1gr6d) groups these fixes in ATS 9.2.15 and 10.1.4. The GitHub records were unreviewed and several adjacent entries provide only generic labels. Confirm source or byte-level behavior before assigning a specific class; do not turn a generic "improper access control" record into a stronger claim by inference.

### Four-recorder ATS lab

Build an isolated fixture with four evidence points: client bytes, ATS ingress interpretation, ATS egress bytes, and origin/client interpretation. Use one fresh connection and one mutation per case.

| Case | Controlled mutation | Decisive evidence |
| --- | --- | --- |
| H2 downgrade | forbidden `Transfer-Encoding` plus inert body | ATS emits an ambiguous HTTP/1 message or origin counts a different number/length of requests |
| Chunk grammar | one malformed chunk delimiter/size form | ATS and mock origin disagree on body end or next request boundary |
| H2 origin trailers | one `x-canary-trailer` from a mock H2 origin | HTTP/1 client recorder sees trailer bytes outside valid chunked framing |
| Header aliasing | two long canary names sharing a prefix near the observed limit | policy and origin resolve different canonical names or values |
| URL authority | userinfo, explicit port, omitted port, and encoded delimiter variants | ACL authority/port differs from the authority ATS actually dials |
| H2 connection reuse | two owned TLS hostnames with distinct certificate coverage | request for host B reuses host A's connection without B certificate coverage |

For H2/H3 cases, prefer protocol-capable local clients and byte recorders rather than hand-editing pseudo-headers. Log decoded pseudo-headers and the exact HTTP/1 serialization. Use only `/canary-a` and `/canary-b`; never target protected routes or shared user traffic.

For long-name testing, find the boundary with harmless repeated characters and two marker headers. The positive result is not a crash: prove **client sends distinct names -> ATS truncates or aliases them -> policy/origin sees one protected-equivalent name or a changed routing decision**. Do not use real authentication, forwarding, or tenant headers.

For authority and port parsing, run two owned listeners on separate loopback ports and return only listener identity. Record raw absolute-form target, parsed scheme/userinfo/host/port, ACL decision, DNS result, and selected listener. Do not probe internal services or metadata endpoints.

For origin coalescing, use a local CA, `a.example.test`, and `b.example.test`; configure certificates so the expected coverage is explicit. Send a normal A request, then a B request over the candidate reuse path. A bounded positive is **B request is carried on A's established H2 origin connection even though A's certificate does not cover B**. Prove only listener identity and certificate names; do not intercept credentials or tenant data.

Repeat every fixture on 9.2.15 or 10.1.4. Preserve exact raw bytes, stream IDs, connection IDs, parsed fields, message counts, and fixed-build decisions. Availability and memory-safety-only siblings from the same wave are not separate operator workflows unless an authorized lab can establish a specific non-crash trust-boundary effect.

### Late-wave ATS destination, ACL, and connection-state checks

The later July 29 feed page adds operator-relevant siblings from the same [Apache announcement](https://lists.apache.org/thread/5prl9glcm9g2swnq9hqxvnokylm1gr6d):

- [GHSA-jmf6-wg5m-793g / CVE-2026-58178](https://github.com/advisories/GHSA-jmf6-wg5m-793g): ESI recursion can fetch attacker-selected URLs;
- [GHSA-f54r-392m-jmr7 / CVE-2026-58189](https://github.com/advisories/GHSA-f54r-392m-jmr7): plugin retry-counter resets can bypass redirect limits and amplify SSRF;
- [GHSA-vc32-c93g-p2f6 / CVE-2026-58157](https://github.com/advisories/GHSA-vc32-c93g-p2f6): server sessions or tunnels may be reused across client connections;
- [GHSA-vv89-hv6r-vgqh / CVE-2026-58159](https://github.com/advisories/GHSA-vv89-hv6r-vgqh): Unix-domain-socket listeners and ACL matching can bypass IP access controls;
- [GHSA-99g5-7fmc-568c / CVE-2026-58158](https://github.com/advisories/GHSA-99g5-7fmc-568c): PROXY protocol parsing can truncate ports in addition to a stack-overflow condition; and
- [GHSA-xm2f-jc7r-hmhj / CVE-2026-58177](https://github.com/advisories/GHSA-xm2f-jc7r-hmhj): the ATS 10 Cripts framework includes a path-traversal primitive alongside memory-safety issues.

These descriptions are terse. Do not infer a route, parameter, traversal depth, cross-client data class, or ACL normalization rule that the source does not establish. Derive exact request shapes from the matching ATS build in an isolated lab.

For ESI and redirect testing, use two owned HTTP listeners plus an owned redirector. Return only random canaries. Compare direct fetches, nested ESI references, same-authority redirects, cross-authority redirects, loops, and chains immediately below/at/above the configured limit. Capture each normalized URL, retry counter, redirect hop, and final peer. Never target metadata, loopback services outside the fixture, RFC1918 applications, or production origins.

For session/tunnel reuse, create clients A and B and origins A and B with distinct inert markers. Record client connection ID, ATS transaction/session/tunnel ID, origin connection ID, authority, TLS identity, and marker returned. A bounded positive is **client B transaction inherits or reuses client A's server-side state -> B receives A's synthetic marker or reaches A's canary origin**. Do not use real cookies, credentials, cached objects, or user traffic.

For ACL and PROXY protocol checks, put ATS behind a local trusted sender and use only fake source addresses/ports. Compare TCP and UDS listeners, absent/valid/malformed PROXY headers, boundary ports, repeated fields, and the address/port visible at each policy hook. The positive result must show a decision difference—such as a fake denied principal becoming allowed—not merely a crash. Never spoof a production trusted proxy or use a real privileged identity.

For Cripts path handling, instrument the candidate file/path sink and place one marker in a disposable sibling-prefix directory. Test relative, absolute, encoded, symlinked-parent, and sibling-prefix forms. Stop at canonical-path or inert marker evidence; do not read secrets or write application/startup files. Repeat all cases on ATS 9.2.15 or 10.1.4 as applicable.

## July 30 IBM WebSphere and Liberty follow-up

[GHSA-974x-wv37-rccw / CVE-2026-11541](https://github.com/advisories/GHSA-974x-wv37-rccw) adds IBM WebSphere Application Server and Liberty to the same proxy-to-origin parser-differential workflow. IBM's [primary security bulletin](https://www.ibm.com/support/pages/node/7277550) confirms HTTP request smuggling in traditional WebSphere 8.5 and 9.0 and Liberty 17.0.0.3 through 26.0.0.6. The public record does **not** identify the conflicting grammar, header, or intermediary, so do not label it CL.TE, TE.CL, HTTP/2 downgrade, or another specific class without byte-level evidence.

### WebSphere estate discovery

Before sending malformed traffic, establish the actual chain and a trustworthy version control:

1. inventory scoped Java application endpoints and note any WebSphere/Liberty evidence supplied by the customer, deployment manifest, approved version endpoint, or server owner;
2. map every HTTP hop—CDN/WAF, load balancer, IBM HTTP Server or another reverse proxy, ingress/service mesh, then WebSphere or Liberty;
3. determine where TLS terminates, where HTTP/2 is downgraded, and which hop performs authentication, route, cache, and connection-pooling decisions;
4. create `/canary-a` and `/canary-b` handlers that return only route name, request sequence, connection ID, and a random tester-owned marker; and
5. pair the candidate build with a fixed negative control. IBM maps the correction to Liberty APAR `PH71808` and traditional WebSphere APAR `PH71706`; its bulletin names Liberty 26.0.0.7, traditional 9.0.5.29, and 8.5.5.31 as fix-pack controls when available.

Do not infer exposure from a generic Java response or banner alone. A useful reconnaissance result binds the approved host to the WebSphere/Liberty role, version evidence, and the specific front-end path that reaches it.

### Differential-first fixture

Use the two-hop/four-recorder method already described on this page. Replay a small standards-based corpus rather than guessing a weaponized chain:

- ordinary `Content-Length` and chunked baselines;
- conflicting or repeated framing fields;
- transfer-coding token, case, whitespace, and list variants;
- chunk-size, extension, delimiter, trailer, and premature-termination boundaries;
- HTTP/2-to-HTTP/1 conversion controls when that conversion exists in the real topology; and
- connection-close versus keep-alive controls.

Run one mutation on one fresh connection, then a separately identifiable canary request. Record client bytes, front-end decision, bytes emitted toward WebSphere, origin interpretation, response count/order, and connection reuse. The first bounded positive is **one client stream -> different front-end and WebSphere message boundaries**. Only then test a harmless route or fake-principal decision on the same disposable fixture.

Repeat the exact raw fixture against the APAR/fix-pack control. A 400/500 response, timeout, or closed connection is not request-smuggling proof. Likewise, IBM's generic impact rating does not prove that a particular deployment bypasses authentication: report parser split, queued-request desynchronization, route difference, and policy effect as separate edges.

Keep this work off shared production pools unless the rules of engagement explicitly authorize it. Do not target victim traffic, real sessions, protected data, or administrative routes; synthetic route and fake-principal markers are sufficient.

## September 21 Netty HTTP/1 framing follow-up: the strict-validator gates skip the no-extension and no-semicolon paths (6 GHSAs)

A Netty `netty-codec-http` cluster (published 2026-09-18, surfaced via the updated feed 2026-09-21T18:33Z) extends this page's framing battery with a single reusable lesson: **strict syntax validators are usually wired behind a cheap pre-check (`if` the line contains `;`, `if` the token has whitespace) — everything outside the pre-check keeps the old lenient path.**

- [GHSA-9mrj-55p4-qwf4](https://github.com/advisories/GHSA-9mrj-55p4-qwf4) / CVE-2026-93566: `checkChunkExtensions` runs the strict chunk-size-line validator **only when the line contains `;`** — a chunk-size line with an embedded bare CR (`0\rX`) passes unvalidated while a strict intermediary frames differently → smuggling. Test chunk lines with bare CR, bare LF, and post-digit junk with and without `;` — the differential between the two branches is the finding.
- [GHSA-xvf3-842c-j48x](https://github.com/advisories/GHSA-xvf3-842c-j48x) / CVE-2026-93573: **split `Transfer-Encoding` fields** (two TE headers) bypass the final-chunked validation; [GHSA-c599-gp9v-cp79](https://github.com/advisories/GHSA-c599-gp9v-cp79) / CVE-2026-93562: malformed TE values accepted incomplete; [GHSA-c9wq-39xx-437p](https://github.com/advisories/GHSA-c9wq-39xx-437p) / CVE-2026-93574: **post-digit whitespace inside the chunk-size token** accepted. Combine with the existing `Transfer-Encoding : chunked` whitespace-before-colon item on the June 11 Netty codec page — sweep TE as: duplicated, spaced, cased, suffixed, and chunk tokens as `0 \r\n`, `0\t\r\n`, `+0`, `0;` and `0\rX`.
- [GHSA-6f4p-h3xm-c8rc](https://github.com/advisories/GHSA-6f4p-h3xm-c8rc) / CVE-2026-93565 (7.5): `RtspMethods.valueOf()` **trims trailing control bytes** (`PLAY\x00`, `PLAY\r`) before the method cache lookup — the decoder reports a fully successful `PLAY` and the application layer cannot distinguish it from a clean token; the fix for the HTTP method class hardened `HttpMethod.valueOf()` only, and the RTSP sibling kept the lenient `checkNonEmptyAfterTrim()`. Reusable rule: **after any method/token validation fix, enumerate sibling `valueOf()` implementations in the same codec family (RTSP, SIP, ICE, custom binary-over-HTTP) and fuzz trailing NUL/CR/LF/tab — a null-byte-padded method token is a front-end-vs-origin matcher split waiting to happen on any RTSP/media proxy leg.**
- [GHSA-xf8w-rc87-x5gw](https://github.com/advisories/GHSA-xf8w-rc87-x5gw) / CVE-2026-93567 + [GHSA-ffvg-hfwh-x2pp](https://github.com/advisories/GHSA-ffvg-hfwh-x2pp) / CVE-2026-93568 (both 7.5): HTTP/1 **authority-form CONNECT** translated to a malformed HTTP/2 CONNECT with a **Host-controlled `:authority`**, and HTTP/2/3 **Extended CONNECT** (`:protocol`) silently **downgraded to plain CONNECT** by the translation layer. Operator value: on any Netty-backed gRPC/WebSocket/proxy translation leg, compare what the front accepted against what the H2 layer emitted — `:authority` sourced from a header an attacker controls, and protocol-extension requests silently losing their extended semantics, are both connect-target trust splits. Probe with a lab origin that logs the decoded `:authority` and `:protocol` per transport.

Same validation boundary as everywhere on this page: single-connection lab canaries against your own raw-byte logging backend, one mutation per fresh connection, front-decision vs origin-interpretation tables. The Quarkus SmallRye leak (CVE-2026-94449), websockets-next unbounded-buffer OOM (CVE-2026-87742), and Redis cluster-bus length items were tracked without promotion (availability-only).
