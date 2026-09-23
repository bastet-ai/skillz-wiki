# HTTP/3 fuzzing, race, and downgrade testing with Turbo Intruder

Source: PortSwigger Research, [Tom Stacey, "HTTP/3 in Burp Suite - it's time to find a bigger wordlist"](https://portswigger.net/research/http3-in-burp-suite) (published 2026-09-23), with the referenced race papers [QUIC-er Races](https://portswigger.net/research) (single-datagram attack) and *Chaos by Design* (QPACK blocked-stream server-side race orchestration).

PortSwigger's September 2026 release adds an HTTP/3 engine to Turbo Intruder plus an **HTTP/3 Adapter** extension that converts all Burp Suite traffic to HTTP/3. This converts HTTP/3 from "protocol the scanner negotiates by accident" into a first-class test surface: sub-10-ms race groupings, downgrade-leg injection, and access to HTTP/3-only endpoints that were previously invisible to standard tooling.

!!! warning "Authorized, bounded testing only"
    100k+ RPS is a denial-of-service against most production targets. Run volume attacks only inside an explicit rate/volume budget with customer sign-off, on routes you own or are approved to hammer, or against a lab twin. The race and downgrade proofs below need single-digit request counts.

## Why HTTP/3 changes the race calculus

HTTP/1.1 races ride on TCP connection reuse and the single-packet attack; HTTP/2 races ride on multiplexed streams. HTTP/3 gives two *tighter* primitives, both now built into Turbo Intruder's gate system:

- **Single-datagram attack** (from *QUIC-er Races*): QUIC lets you pack multiple requests into **one UDP datagram**, so the server processes the whole race group in a single receive + event-loop turn. No TCP segmentation, no inter-packet gap — the tightest grouping available on any HTTP version.
- **QPACK blocked-stream orchestration** (from *Chaos by Design*): hold a stream blocked on QPACK dynamic-table state to **park a request mid-processing** and release it deterministically. Server-side race orchestration instead of stochastic timing luck.

Turbo Intruder selects the technique automatically when `engine=Engine.HTTP3, gateMode='auto'`, and only uses QPACK if the server supports it. Start from the shipped `race-http3.py` example:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP3,
                           gateMode='auto')  # selects the correct technique for me
    for i in xrange(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

Set `gateMode` explicitly to force one technique when you need to prove *which* primitive won the race (the QPACK vs single-datagram verdict table is the reportable artifact — the same TOCTOU pair landing under one technique and not the other localizes the race window to the QUIC receive layer).

## Fingerprinting HTTP/3 support before you test

Decide per-host, not per-brand:

1. DNS: query HTTPS/SVCB records (`dig HTTPS _dns1.example.com`, or `dig HTTPS example.com`) for an `alpn="h3"`/`h3` entry — that is the advertisement.
2. HTTPS: check responses for an `Alt-Svc: h3=":443"` header.
3. Confirm over UDP: a host can advertise H3 and have it firewalled; conversely, an origin behind a CDN may answer H3 on a port you weren't told about.

Both signals missing ≠ not testable: the Adapter's *Show unsupported origins* tab lists domains failing the H3 handshake — useful when sweeping many domains in Always mode. Treat H3 capability as a **per-origin property with its own attack surface** (separate QUIC stack, separate QPACK implementation, separate downgrade bridge at the edge).

## Volume fuzzing: the tuning knobs

For wordlists/param brute-force where throughput is the finding:

- **Minimize request and response**: `HEAD`, or `GET /` with `Range: bytes=-1` (server returns one byte — `Content-Length: 1` responses keep the *response* small too). Under the HTTP3 engine you can drop `Host` entirely: `:authority` is implied by the target.
- **AUTO engine** (Professional) auto-selects the highest HTTP version and dynamically tunes as network state drifts; for long campaigns prefer it. Exception: **never use AUTO for desync attempts** — desync needs the BURP engine (HTTP/1.1, connection reuse disabled) so each request gets its own connection and you control framing.
- Manual tuning by engine: `THREADED` (`concurrentConnections`, `requestsPerConnection`, `pipeline=True` if the server pipelines), `BURP2` (`concurrentConnections`), `HTTP3` (`concurrentConnections`). Raise each until the RPS counter plateaus or failures start.
- Co-locate: same-region cloud box pushed the author's laptop 100k RPS over Wi-Fi to ~180k RPS.

Sanity-check volume claims against scope: 180k RPS against a shared edge is an availability event, and rate-limiter/lockout behavior is usually the actual finding (see the vendor-forwarding-header lockout-bucket resets already on this wiki), not the throughput itself.

## Downgrade-leg attacks: kettled HTTP/3 requests

Edge bridges that translate H3 → HTTP/1.1 to the origin re-serialize your request in a **different grammar** than the one you sent. Turbo Intruder's HTTP/3 engine supports kettled request syntax (same escapes as the BURP2 engine) to inject bytes that only decode after the downgrade:

```
GET / HTTP/1.1
foo: bar^~Transfer-Encoding:^schunked

engine.queue(target.req, kettled=True)
```

Escape set: `^~` CRLF, `^s` space, `^0` null, `^r` CR, `^n` LF, `^x02` arbitrary hex, `^^` literal `^`. The above attempts `Transfer-Encoding: chunked` header injection **once the bridge re-serializes to HTTP/1.1** — i.e., smuggling past an H3 front end that validated pseudo-headers but whose HTTP/1.1 origin leg re-parses a naive header block.

Pseudo-header overrides add the second differential axis: `:path` and `:method` are implied by the request line, `:authority`/`:scheme` by the request target, and you can set them explicitly to diverge:

```
GET / HTTP/1.1
:scheme: httpx
:authority: intranet.example.com
```

Mismatched `:authority` vs the transport SNI/target, or a non-standard `:scheme`, tests whether the bridge trusts the pseudo-header (origin-routing decisions, cache keys, virtual-host selection) or the connection parameters — the H3 shape of the approved-host/foreign-tuple family already canonical on this wiki. Validation workflow, lab-bounded: own front-end/origin pair running an H3-terminating proxy in front of HTTP/1.1 origin; log the exact bytes the origin sees for each kettle canary (mirrors the raw-byte transform-recorder harness on the [HTTP desync research campaigns page](http-desync-research-campaigns.md)); prove header-injection by a benign extra header reaching the origin recorder, and routing confusion by a canary vhost hit — not by reaching real internal services.

## HTTP/3-only targets: the Adapter

The [HTTP/3 Adapter](https://github.com/portswigger/HTTP3-adapter) converts HTTP/1.1/HTTP/2 traffic from **all** Burp tools to HTTP/3 and back, exposing sites that *only* serve H3 to Scanner/Repeater/Intruder:

- **Explicit HTTP/3 only** mode: only requests carrying `X-Http3: 1` go over H3 — keeps your normal traffic normal and makes the H3 leg an explicit, greppable variable.
- **Always HTTP/3 where possible**: every request tries H3 first, falls back to its original protocol.
- When a request misbehaves, *Log exchange to output* dumps original + converted request; the *Show unsupported origins* tab enumerates handshake failures.

Operator rule: an H3-only (or H3-preferred) service is a **separate implementation** of your target — its own parser (QPACK/QUIC framing), often its own edge, and its own downgrade bridge. Test behavioral parity between the H3 and TCP legs on identical routes: response-diff verdict tables (status, headers, security headers, auth outcomes) across the same request on both transports. Divergence either way is a finding (H3 leg skipping a WAF/edge security layer present on TCP, or vice versa).

## Reporting heuristics

- For races: report the technique (single-datagram vs QPACK vs legacy single-packet), the QUIC/edge stack and version, the gate script, and the deterministic grouping evidence (same-datagram timestamps / blocked-stream release log). A race that only lands over H3 is still a race — say so, and note the TCP-path result as the negative control.
- For downgrade injection: attach the raw-bytes-before (wire) and raw-bytes-after (origin recorder) pair; the exhibit is the *transform table*, not the payload.
- For H3-only parity gaps: attach the verdict table with the exact `X-Http3: 1` request/response and the converted-request log.
- Never report 100k RPS throughput as impact against production; report it only as campaign capacity on approved scope.

Related pages: [HTTP desync research campaigns](http-desync-research-campaigns.md) (raw-byte transform recorder, framing primitives), [HTTP anomaly and WebSocket triage](http-anomaly-websocket-triage.md), and the [Canonicalization differentials at security gates](canonicalization-differentials-at-security-gates.md) page (approved-tuple families the `:authority` mismatch generalizes).
