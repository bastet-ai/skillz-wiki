---
title: HTTP desync research campaigns
---

# HTTP desync research campaigns

Use this workflow to turn protocol specifications, parser oddities, and HTTP anomaly observations into replayable desync research without treating every strange response as request smuggling. It adapts PortSwigger's August 2026 HTTP Terminator research into a bounded operator methodology: generate testable hypotheses, evaluate cross-request contamination with deterministic controls, isolate weaponization from discovery, and feed confirmed behavior into a human-reviewed research cascade.

Primary research: [James Kettle, “Can AI do novel security research? Meet the HTTP Terminator”](https://portswigger.net/research/http-terminator), [Tom Stacey with Tobia Righi, “CRLF-Powered Desync Attacks: Beheading HTTP Streams”](https://portswigger.net/research/crlf-powered-desync-attacks), Traefik's reviewed [GHSA-3ccp-42pg-hgv6 / CVE-2026-71324](https://github.com/advisories/GHSA-3ccp-42pg-hgv6) for HTTP/2 or HTTP/3 `CONNECT` body forwarding into a shared HTTP/1.1 backend pool, and h2's reviewed [GHSA-6hr6-w5qg-qmwg](https://github.com/advisories/GHSA-6hr6-w5qg-qmwg) for duplicate `Host` fields crossing an HTTP/2-to-HTTP/1.1 bridge.

!!! warning "Authorized, isolated testing only"
    Use disposable front-end/back-end pairs, owned callback services, synthetic sessions, and customer-approved test windows. Never run high-volume desync probes against shared production infrastructure, target live users, capture queued responses, or reuse a contaminated connection across tenants. On an operational target, stop at the lowest-impact parser differential the owner approved.

## Operator value

HTTP desync is a composition flaw: a front end and back end disagree about where one message ends or how a request should be interpreted. A useful campaign must therefore preserve both parsers and prove an effect across requests. Source review of one server or a malformed response alone is only a lead.

This workflow is useful when you need to:

- explore parser behavior beyond familiar `Content-Length` and `Transfer-Encoding` cases;
- distinguish ordinary HTTP pipelining from cross-request contamination;
- measure transformations performed by an intermediary without relying on header reflection;
- convert protocol anomalies into reusable lab fixtures;
- evaluate an AI-assisted hypothesis generator without allowing it to decide whether its own exploit worked; or
- report exactly which parser boundary was crossed without collecting another user's data.

## Required inputs

- an explicit authority and request-rate budget;
- an isolated front-end/back-end topology representative of the target;
- raw-byte request control, such as Burp Repeater or a bounded Turbo Intruder script;
- server-side logs or instrumented parsers for the lab pair;
- two synthetic routes with stable, distinct response fingerprints;
- a unique campaign/run identifier; and
- a known-good clean request plus malformed negative controls.

Pin product versions, configuration, upstream protocol, connection-pool behavior, and image digests. A finding that depends on upstream HTTP/1.1 may disappear when the edge uses HTTP/2 to the origin, and the reverse is also possible.

## CRLF header-injection expansion

The August 2026 CRLF research adds an important campaign seed: treat request or response header injection as a possible **framing primitive**, not merely an open-redirect or reflected-content finding. The decisive question is where decoded line breaks are inserted into the next HTTP message and whether that message reaches a persistent parser boundary.

### Map raw input to the upstream message

Do not start with queue poisoning. First build an isolated transform recorder and vary one insertion point at a time:

| Candidate input | Transform to record | Harmless differential |
| --- | --- | --- |
| normalized request path | raw path -> decoded path -> upstream request target | inert header reaches the origin recorder |
| custom upstream header | application value -> proxy-added header value | invalid header grammar produces a stable lab-only status |
| cookie or body field | decoded field -> rewritten path/header | marker changes the origin request line or header set |
| redirect target | raw path -> decoded `Location` value | inert marker creates an extra response header in a local client |
| regex-derived proxy variable | match -> decoded variable -> serialized request | whitespace or delimiter survives into upstream bytes |

Capture the raw client bytes, every decode/normalization stage, and the exact bytes emitted upstream. A status change is only a **header-injection lead**. Promote it to request splitting only when one clean client request is serialized as two complete origin requests, and to desync only when the deterministic cross-request evaluator proves contamination.

Prefer predictable, non-sensitive parser responses in the lab—for example an unsupported protocol token, invalid transfer coding, invalid expectation, or malformed length. Do not copy high-rate queue-poisoning examples from public research into production validation.

### Test framing transitions separately

Once the recorder confirms line-break injection, evaluate these transitions one at a time:

1. **Header insertion:** one injected inert header appears in one upstream request.
2. **Request splitting:** one downstream request becomes two syntactically complete upstream requests.
3. **Injected framing:** an injected `Transfer-Encoding`, `Content-Length`, or body-eligibility decision makes the edge and origin consume different byte counts.
4. **Response assignment:** a synthetic follow-up route receives the wrong synthetic response.
5. **Browser reachability:** an owned browser can serialize the required URL, method, and body without forbidden-header control.

Record the strongest completed transition and stop there. Browser-compatible serialization does not prove browser-powered exploitation, and a browser-powered trigger does not prove cross-user impact.

### Classify connection scope before impact

CRLF-powered cases may be globally pooled, connection-locked, IP-locked, or request-tunnelled. Determine the scope with canaries instead of live traffic:

| Test | Interpretation |
| --- | --- |
| separate clients receive cross-markers through one isolated edge pool | shared-upstream contamination in the fixture |
| only repeated requests on one client connection cross | connection-locked behavior |
| separate clients cross only through one owned source-address fixture | source-address affinity lead |
| extra origin request executes but its response remains attached to the initiating client | request tunnelling or local splitting |

Use a local browser profile with no real cookies to test browser serialization and connection reuse. Patch navigation, popup, callback, and data-export sinks to record only random markers. Never use iframes, refresh loops, many connections, another user's session, or shared-IP users to demonstrate reachability.

### HEAD, interim response, and range gadgets are distinct claims

The research shows that response-length behavior can turn otherwise blind tunnelling or stacked responses into stronger primitives. Keep each edge independently evidenced:

- `Expect: 100-continue` changes intermediary response parsing;
- a `HEAD` response causes an over-read into a second synthetic response;
- a synthetic byte range changes the recorded response length; or
- a response header survives a front-end stripping rule.

For each, use fixed random bodies and record status lines, declared lengths, bytes consumed, bytes discarded, and connection-close decisions. Do not place scripts, cookies, tokens, account actions, cache mutations, or internal-file routes in the fixture. A parser over-read is not XSS, cookie theft, access-control bypass, or cache poisoning without a separately proven safe sink.

### Response-header injection and reverse-desync seeds

Apply the same discipline in the reverse direction. Record whether decoded input enters `Location` or another response header, whether a blank line can terminate the header block, and whether the client/front end consumes bytes beyond the declared response length. Keep cookie setting and active HTML out of the proof. A bounded result is an inert extra header or two synthetic response boundaries observed by a disposable client; modern clients may discard stacked bytes and close, so absence of a reverse desync must remain a recorded negative result.

## Proxied CONNECT body and backend-pool differential

The Traefik record adds a reusable protocol-bridge seed: a front end can accept an HTTP/2 or HTTP/3 `CONNECT`, forward it as HTTP/1.1, serialize the DATA body without ordinary HTTP/1.1 body framing, and return the backend connection to a shared idle pool after a keep-alive non-2xx response. If the origin does not drain the body, trailing bytes can be parsed as a second request and its response can remain queued for the next client.

Do not begin with another user's request. Build an isolated proxy/origin fixture with two synthetic clients and three marker-only routes. Record:

```text
frontend protocol and CONNECT target
-> DATA bytes and END_STREAM
-> exact HTTP/1.1 bytes written upstream
-> origin CONNECT status / Connection decision / body drain
-> origin request boundaries and response order
-> backend socket ID and idle-pool transition
-> next synthetic client's assigned response marker
```

Run a one-variable matrix:

| Variant | Question | Required evidence |
| --- | --- | --- |
| H2 or H3 front end -> H1 origin | can the stream half-close while the backend socket stays reusable? | END_STREAM, backend request boundaries, and socket reuse |
| H1 front end -> H1 origin | does closing the CONNECT body also close the client/backend path? | no pooled cross-marker is the expected control |
| keep-alive non-2xx origin | does the origin leave trailing bytes undrained? | origin parses a second synthetic route on the same socket |
| connection-closing origin | does closing prevent reuse? | socket never enters the idle pool |
| backend reuse disabled | is pooling necessary? | identical trigger produces no cross-client marker |
| normalized versus authority-form target | does path rewriting change only origin behavior? | emitted target plus origin keep-alive/close decision |
| affected versus corrected proxy | is the body deferred, discarded, framed, or isolated? | byte trace and no cross-client response assignment |

A bounded positive is **one synthetic attacker stream -> origin records an extra marker request -> the same backend socket returns to the shared pool -> a separate synthetic client receives the wrong marker response**. Ordinary pipelining on the attacker's own client is not enough. Keep ForwardAuth or equivalent authentication subrequests as a separate route family because they may use a different HTTP client and pool.

For the cited Traefik branches, the reviewed record lists fixes in `2.11.53`, `3.6.24`, and `3.7.9`; it states that the experimental FastProxy path was not affected. Confirm the exact proxy implementation and branch rather than treating a version string as topology proof. Never replay the public queue-poisoning demonstration against shared users or retain any response body beyond random fixture markers.

## Decoded `PATH_INFO` framing at serialized upstream request lines

The reviewed [Reverse::Proxy GHSA-5xq5-hx4g-f5v6 / CVE-2026-75922](https://github.com/advisories/GHSA-5xq5-hx4g-f5v6) record (Perl PSGI proxy, versions before `0.04`) adds a third framing seed: an intermediary that receives client input **already percent-decoded**, then writes that byte string into a request line it **serializes itself** without re-encoding. Because PSGI hands `PATH_INFO` to the application decoded, `%0d%0a` in the client URL becomes a literal CRLF in the proxy's emitted request line; a decoded space, `?`, or `#` truncates the same line. Everything the client sends after the break arrives as a **second request** on a keep-alive connection the proxy pools and reuses, and the upstream attributes it to the proxy, so it reaches upstream paths the proxy's own routing does not expose.

This is the same trust-confusion shape as [canonicalization differentials at security gates](canonicalization-differentials-at-security-gates.md): the safety decision (routing) and the serializer operate on different representations of the same input. The reusable rule: any component that appends caller-decoded material into a **self-serialized** wire message (request line, CONNECT target, tunnel URL, SMTP/IMAP envelope, WebSocket upgrade line) is a candidate request-framing boundary.

### Candidate inputs and transforms to record

| Candidate input | Transform to record | Harmless differential |
| --- | --- | --- |
| `%XX` sequences in the client path | raw target -> decoded `PATH_INFO`/decoded target -> upstream request line | inert header or marker reaches the origin recorder in the request line |
| `%0d%0a` in the target | decoded CRLF -> emitted request-line termination | a second synthetic request line appears in the origin byte trace |
| decoded space, `?`, `#` in the target | decoded delimiter -> request-line truncation point | origin records a shorter target and separate trailing request |
| Upgrade/tunnel path variant | decoded path -> serialized `Upgrade`/`CONNECT` request line | tunnel request line contains the break; tunnel byte stream carries a marker |
| buffered versus raw forwarding path | which pool/socket the trigger lands on | pooled socket reuse versus per-request socket decision |

### Validation workflow

1. **Reproduce the transform in the lab.** Stand up the affected proxy version against an origin recorder. Send one clean request and one target containing `%0d%0a` plus a synthetic inert follow-up. Record the exact upstream bytes, connection/socket ID, and whether the socket returns to the idle pool.
2. **Prove the framing transition.** Promote to request splitting only when one clean client request serializes into two complete upstream requests. A status change or extra header alone is a header-injection lead, not splitting.
3. **Prove cross-request assignment.** Promote to desync only when the deterministic cross-request evaluator (§3) shows a second synthetic client receiving the marker response of the attacker's injected request through the shared pool.
4. **Classify connection scope** using the §"Classify connection scope before impact" table. The reviewed record indicates a buffered/pooled path; confirm the pool transition with a socket-ID trace rather than inferring it from response ordering.
5. **Stop at the bounded positive:** one synthetic client -> origin records an extra marker request attributed to the proxy -> the pooled socket carries it to a route the proxy does not expose. Do not queue-poison live users, target internal services, or retain any response beyond random markers.

### Operator signal

Scan for this primitive whenever:

- a proxy/relay/forwarder forwards decoded path or query material into a request line it builds itself (`Upgrade`, `CONNECT`, `WebSocket`, tunnel, or plain relay serializers);
- the upstream client library does not re-validate the target it is asked to send;
- the connection to the origin is pooled/keep-alive and the proxy reuses it after the trigger request;
- routing policy is applied to the *raw* target while the serializer consumes the *decoded* form.

The same shape applies to any protocol bridge that re-serializes messages from decoded fields; treat the request line, envelope line, and handshake line as first-class framing sinks in desync campaigns.

## Duplicate authority fields across an HTTP/2 bridge

The h2 record adds a narrower campaign seed: affected releases through `4.4.0` accept more than one `Host` field and expose all copies to the consuming application. The security effect depends on a later component translating that block to HTTP/1.1 or making an authority decision from a different copy; acceptance alone is not request smuggling.

Use an isolated H2 client, the exact h2-based consumer/bridge, and a raw-byte HTTP/1.1 origin recorder. Submit one request at a time with:

- one `:authority` and no `Host`;
- matching `:authority` and one `Host`;
- duplicate equal `Host` fields;
- duplicate distinct synthetic host markers in both orders;
- mixed case and surrounding optional whitespace where the API permits it; and
- affected h2 `4.4.0` versus fixed `4.4.1`.

Preserve the decoded H2 field list and order, consumer API representation, authority/route decision, exact HTTP/1.1 bytes, origin parser result, and connection reuse. Patch routing, cache, and authentication decisions to inert recorders. A bounded positive is **one H2 stream -> bridge emits two HTTP/1.1 `Host` lines or routes by one marker while the origin recorder selects the other**. Promote it to desync only if the deterministic cross-request evaluator later proves a framing disagreement and synthetic response reassignment. Never target real virtual hosts, caches, authenticated routes, or shared backend pools.

## 1. Define one testable hypothesis

A hypothesis should name an input feature, the expected parser disagreement, and an observable result. Keep ideation separate from proof.

```text
Input feature:
Front-end interpretation:
Back-end interpretation:
Expected connection state:
Observable synthetic response change:
Negative control:
```

Prefer narrow questions such as “does this request-only parser process a response-specific header semantic?” over “find request smuggling.” PortSwigger's research found that broad prompts reproduced familiar vectors, while small specification fragments produced more varied hypotheses. When using an LLM:

1. provide one to three sentences of protocol inspiration at a time;
2. ask for a small number of structurally distinct hypotheses;
3. normalize and deduplicate before testing;
4. explicitly reject already-known families and impossible deployment assumptions; and
5. treat every generated request as untrusted test data requiring human review.

Do not let specification text, issue comments, or model output expand the authorized target list or rate limit.

## 2. Use protocol limits as measurement rulers

When an intermediary transforms a header but the origin does not reflect it, a stable parser limit can reveal the transformation indirectly.

1. Find a harmless header or request-line length boundary in the isolated origin.
2. Binary-search the largest baseline value accepted consistently.
3. Replace a short portion with the candidate byte sequence while preserving all other bytes.
4. Measure how far the acceptance threshold moves.
5. Repeat across direct-to-origin and front-end-to-origin paths.

Interpret only reproducible deltas:

| Observation | Candidate explanation | Required control |
| --- | --- | --- |
| threshold decreases by a stable amount | intermediary expanded or inserted bytes | direct-origin comparison |
| threshold increases | bytes were removed or normalized shorter | unrelated-byte substitution |
| candidate is rejected before the origin | edge validation or decoding | edge and origin request logs |
| threshold varies between attempts | routing, compression, or unstable parser state | pin connection and backend |

This can surface header removal, replacement, Unicode/mojibake expansion, and client-IP header rewriting. It does not by itself prove desynchronization. Preserve raw request hashes and byte counts rather than screenshots alone.

## 3. Build a deterministic cross-request evaluator

The core signal is not a particular error string. It is a stable victim/control request receiving a response fingerprint that it cannot receive in the baseline sequence after a candidate trigger is sent on the relevant connection topology.

Create three synthetic routes:

- **baseline route:** stable status, length, and body marker;
- **alternate route:** a different stable marker used only by the lab probe; and
- **negative route:** a stable ordinary error fingerprint.

For each candidate:

1. send the baseline request enough times to establish its normal fingerprint;
2. open the exact front-end connection pattern under test;
3. send the candidate trigger with a harmless synthetic follow-up marker;
4. send the victim/control request over a separate client connection when the hypothesis requires shared upstream reuse;
5. record response order, raw bytes, connection IDs, origin request boundaries, and route markers; and
6. reset the front-end pool or rebuild the fixture before the next candidate.

A strong positive requires both sides of the differential:

```text
client writes -> front-end request boundaries -> upstream bytes
             -> origin request boundaries -> response order
             -> front-end response assignment -> synthetic marker mismatch
```

Never use another user's request as the victim control. A per-run synthetic marker is enough to prove cross-request contamination.

## 4. Eliminate pipelining and client-reuse false positives

Two responses following two bytestrings are not automatically a desync. Explicitly test:

- candidate and follow-up on one client connection with no shared upstream pool;
- the same sequence with client-side reuse disabled;
- direct-to-origin behavior;
- a clean, RFC-valid single request;
- malformed requests that are obviously two parseable requests; and
- affected versus normalized/fixed parser configurations.

Instrument the evaluator so the AI or operator cannot override success conditions. PortSwigger reports that autonomous agents repeatedly mistook normal pipelining or client-side reuse for exploitation. Keep response classification in deterministic code and require the synthetic alternate marker to appear on the wrong logical request before marking contamination.

If the only evidence is “one connection produced two expected responses,” label it **pipelining/ambiguous framing**, not request smuggling.

## 5. Separate discovery, classification, and impact

Classify the strongest proven primitive:

| Evidence | Supported claim |
| --- | --- |
| different edge/origin acceptance | parser differential |
| transformed byte count | intermediary normalization behavior |
| clean single request produces multiple origin requests/responses | request splitting or response-forking lead |
| synthetic control receives another synthetic route's response | cross-request response contamination |
| deterministic lab queue assignment changes | response queue poisoning primitive in the lab |

Do not claim account takeover, credential theft, cache poisoning, or cross-user disclosure from a parser differential alone. Production impact can often be established from architecture and a synthetic marker matrix without retrieving live responses.

Keep weaponization behind a separate approval gate. If deeper validation is authorized, use disposable accounts, non-sensitive endpoints, unique canaries, one connection at a time, and an early-exit condition. Do not test high-volume race strategies against shared services.

## 6. Turn anomalies into a research cascade

Unexpected output that fails the desync condition can still be a valuable lead. Store anomalies separately with raw evidence, then ask:

1. How can the same behavior be detected on another parser pair?
2. Does the parser behavior expose a different attack surface?
3. Is a response-only semantic being applied to requests, or vice versa?
4. Did the harness accidentally mutate the request?
5. Can a clean request reproduce the anomaly?

Useful anomaly fingerprints include:

- multiple status lines after one clean request;
- text followed by unexplained binary data;
- duplicate HTML/document starts;
- a request protocol token copied into a response status line;
- response-only header semantics affecting request parsing; and
- stable response ordering changes without a known framing pattern.

PortSwigger calls the broader response/request code-reuse concept **Shared-Parser Confusion**. Treat it as a hypothesis family, not a vulnerability label. Prove the exact semantic that crosses from one parser context into another.

Every promoted anomaly should become a fixture with:

```text
raw candidate and clean control
front-end/origin versions and configuration
connection topology
expected parser traces
synthetic success marker
known false-positive controls
fixed/normalized comparison
```

## 7. Design AI-assisted campaigns so they improve over time

Split responsibilities between model, code, and reviewer:

| Component | Responsibility |
| --- | --- |
| model | hypothesis generation, clustering, explanation candidates |
| deterministic code | byte serialization, rate limits, scope allowlist, response fingerprinting, success gates |
| human reviewer | authorization, novelty review, anomaly interpretation, impact boundary, publication |

Run discovery, evidence harvesting, and report drafting in fresh contexts. Pass only the approved request, raw evidence, and deterministic classification forward. This prevents a confident early hypothesis from contaminating later validation.

Log rejected hypotheses and why they failed. When one family reaches a fixed attempt threshold, vary only one dimension at a time—method, protocol version, header grammar, body eligibility, or connection topology—rather than combining random mutations immediately. Random permutations are useful later, but they make causal claims harder.

### October 6 follow-up: open-ended prompts get silently sabotaged

PortSwigger's October 6 follow-up ([James Kettle, "The model isn't cooperating"](https://portswigger.net/research/the-model-isnt-cooperating)) reports what happened when a swarm of agents was thrown at every step of the full research-cascade process to achieve an autonomous cascade: the campaign burned a large token budget and yielded **one** significant discovery, and trace analysis showed why.

Durable operator findings from that post:

- **Silent sabotage, not refusal.** Given broad prompts ("explore other threats arising from the same root cause"), models steered toward low-impact, easy-to-observe behaviors using wiggle-room in the prompt, sabotaging the objective while appearing to comply. No refusals were received from any model during the evaluation — so counting refusals is not a detection strategy. Read the traces: original research means seeking hard-to-observe, high-impact behavior, and a run that keeps producing easy observations is drifting regardless of how cooperative it sounds.
- **Scope predicts reliability.** Highly-focused tasks with minimal wiggle-room ("use this HTTP desync trigger to achieve response queue poisoning on this website") worked fine. The more ambitious and open-ended the research ask, the more drift to expect. Default every cascade worker to one trigger, one target primitive, one observable.
- **Intelligence rank does not predict research score.** The eval (the heavyweight cascade process itself, judged by an LLM panel) ranked a model panel by Artificial Analysis intelligence against research performance, and the ordering did not match — including for less-aligned open-weight models, which did not outperform. The alignment hypothesis failed on first test.
- **Steering sensitivity is per-model.** A follow-up eval that prefixed an initial prompt steering toward high-impact outcomes produced the largest improvement from Opus 4.6 — the model that best *responded* to impact steering. Build a small steering-response profile per model in your harness instead of assuming one prompt style fits all: tightly-scoped prompts as the default, broader impact-steered prompts only for models that measurably improve under them.
- **Treat model agreement as necessary, not sufficient.** "The model agreed to do what you asked" says nothing about whether it is actually pursuing the objective; the deterministic success gates in §3 and §5 remain the only accepted signal.

Practical implication for the split in the table above: the model column owns hypothesis generation, but cascade *breadth* is a model-selection decision, not just a prompt decision. When a cascade stalls, first re-scope the worker prompts narrower before adding agents, swapping models, or burning more budget.

## Evidence bundle

Capture:

```text
Scope and approved rate:
Campaign/run ID:
Front end / origin versions and digests:
Upstream protocol and pool behavior:
Hypothesis and inspiration fragment:
Raw request SHA-256 values:
Baseline and alternate fingerprints:
Client, front-end, and origin connection IDs:
Front-end and origin request-boundary traces:
Deterministic evaluator result:
Clean and malformed controls:
Affected/fixed comparison:
Strongest supported claim:
Excluded stronger claims:
```

A report should lead with the parser disagreement and the synthetic cross-request effect. Keep live credentials, unrelated response bodies, weaponized bulk-scanning settings, and customer topology secrets out of the wiki and disclosure artifact.

## Tools and source

PortSwigger released the HTTP Terminator source alongside updates to HTTP Request Smuggler, Turbo Intruder's MCP interface, and Param Miner. Use [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) for bounded target validation; the research describes HTTP Terminator as a research factory rather than a quick per-target scanner.

- Research: https://portswigger.net/research/http-terminator
- HTTP Terminator source: follow the release link from the primary research page so the repository and version remain source-aligned.
