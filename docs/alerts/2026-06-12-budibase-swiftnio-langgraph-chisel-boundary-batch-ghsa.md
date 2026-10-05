# Budibase SSRF, SwiftNIO HTTP translation, LangGraph checkpoint, and Chisel tunnel boundary checks

Source: hourly offensive-security scan, 2026-06-12. Primary entries: GitHub advisories [GHSA-g6qx-g4pr-92v7](https://github.com/advisories/GHSA-g6qx-g4pr-92v7) / CVE-2026-48146, [GHSA-6964-pp88-6wp9](https://github.com/advisories/GHSA-6964-pp88-6wp9) / CVE-2026-48128, [GHSA-4px2-pw77-vc85](https://github.com/advisories/GHSA-4px2-pw77-vc85) / CVE-2026-28898, [GHSA-cq87-8r7h-962v](https://github.com/advisories/GHSA-cq87-8r7h-962v) / CVE-2026-28970, [GHSA-98xf-r82g-9mhx](https://github.com/advisories/GHSA-98xf-r82g-9mhx) / CVE-2026-48121, [GHSA-24fp-5v3p-rvpw](https://github.com/advisories/GHSA-24fp-5v3p-rvpw) / CVE-2026-48113, and [GHSA-9r4w-jg96-92mv](https://github.com/advisories/GHSA-9r4w-jg96-92mv).

This batch is durable because each item exposes a reusable operator boundary: low-code outbound HTTP guard bypasses, HTTP/2-to-HTTP/1 and start-line parser differentials, agent checkpoint identifier objects crossing into MongoDB query operators, tunnel ACL checks enforced only during handshake, and attestation parser state accepting attacker-controlled trusted measurements.

## What changed

- **Budibase OAuth2 token SSRF** — `@budibase/server` before 3.39.0 used raw `fetch(config.url)` for OAuth2 token retrieval instead of the codebase's `fetchWithBlacklist()` wrapper. A user with Builder-level configuration access can point the token endpoint at internal services and have the Budibase server fetch it.
- **Budibase automation query SSRF** — Budibase before 3.39.0 accepted a user-controlled `queryId` in the automation Execute Query step and forwarded it into query execution. When paired with a REST datasource that can reach internal infrastructure, automation execution can turn into server-side request replay with response data flowing back through automation output.
- **SwiftNIO HTTP/2-to-HTTP/1 request smuggling** — `swift-nio-http2` before 1.44.1 did not reject CR, LF, or NUL bytes in HTTP/2 pseudo-header values before translating them into HTTP/1.1 messages. Reverse-proxy patterns that bridge HTTP/2 clients to HTTP/1 backends can emit injected headers or additional requests on the backend connection.
- **SwiftNIO outbound HTTP start-line injection** — SwiftNIO 2.0.0 through 2.99.0 validated header names and values but not request URI, request method, or response reason phrase in the HTTP/1 start line. Proxy or client applications that place attacker-controlled path/method text onto the wire can become request-smuggling or response-splitting gadgets.
- **LangGraph MongoDBSaver NoSQL injection** — `@langchain/langgraph-checkpoint-mongodb` through 1.3.0 used `thread_id`, `checkpoint_ns`, and `checkpoint_id` values from `config.configurable` directly in MongoDB queries. Object payloads such as MongoDB operators can bypass intended thread or tenant scoping when applications forward untrusted request fields into LangGraph checkpoint config.
- **Chisel post-handshake tunnel ACL bypass** — Chisel through 1.11.4 checked `--authfile` ACLs against the client's declared remotes during initial setup, but did not repeat the same decision for later SSH channels carrying actual tunnel traffic. An authenticated client can declare an allowed remote, then open channels to arbitrary server-reachable `host:port` destinations.
- **Go-Attestation trusted measurement injection** — `go-attestation` through the affected 2026-05-15 state did not skip `SignatureHeaderSize` vendor bytes when parsing EFI signature lists. Crafted TPM event logs can inject arbitrary SHA-256 values into a verifier's trusted measurement list, weakening remote-attestation trust decisions.

## Operator triage

1. **Map control-plane privileges first:** Budibase requires Builder-style configuration or automation access; Chisel requires authenticated client access; LangGraph requires an app path that accepts checkpoint config from user input; Go-Attestation requires verifier ingestion of attacker-influenced event logs.
2. **Look for bridge components:** SwiftNIO findings matter most when HTTP/2 input is translated to HTTP/1 backends, or when a Swift proxy/client serializes user-controlled URI/method/reason text into raw HTTP/1.
3. **Prefer canary proof over sensitive reads:** SSRF evidence should be collaborator/canary callbacks or synthetic internal endpoints. LangGraph proof should use synthetic checkpoints. Chisel proof should target a disposable listener. Attestation proof should use lab logs with marker hashes only.
4. **Separate reachability from impact:** A report is stronger when it proves the exact crossed boundary without claiming broader RCE, secret theft, or full tenant compromise unless that was safely and explicitly demonstrated in scope.

## Replayable validation boundaries

### Budibase outbound HTTP guard bypasses

- Test only on a lab instance or customer-approved Budibase workspace where the tester has authorization to configure OAuth2, datasources, and automations.
- For the OAuth2 path, set the token URL to a tester-controlled callback endpoint and trigger the token-fetch flow. Do not target cloud metadata, database admin ports, or production internal services.
- For the automation query path, create a disposable REST datasource and automation Execute Query step that fetches a canary HTTP server under tester control. Confirm that the request originates from the Budibase server-side network location.
- Evidence should include Budibase version, package/component, role used, configuration object shape with sensitive fields redacted, callback receipt, response-handling path, and a patched 3.39.0 negative check if available.

### SwiftNIO HTTP translation and start-line parser differentials

- Use an isolated reverse-proxy or harness that exercises `HTTP2FramePayloadToHTTP1ServerCodec` / `HTTP2ToHTTP1ServerCodec`; do not send desync payloads to shared production frontends.
- Send an HTTP/2 request with a synthetic path containing encoded or raw control-byte markers that the harness will translate to an HTTP/1 backend. The backend should be a disposable logger that records raw bytes, not a real application.
- For SwiftNIO HTTP/1 start-line validation, build a proxy/client harness where the tester controls the request URI or method field. Confirm whether CR/LF markers reach the serialized start line as a second header/request in vulnerable versions and are rejected in fixed releases.
- Evidence should include the codec/library version, bridge topology, raw backend byte log, harmless marker route/header names, and a clear statement that testing occurred in a single-user lab connection.

### LangGraph MongoDBSaver checkpoint scope

- Validate against an isolated MongoDB and a test application that uses `@langchain/langgraph-checkpoint-mongodb` with synthetic tenants, threads, namespaces, and checkpoints.
- Create checkpoint A for tenant/thread A and checkpoint B for tenant/thread B. Then submit a checkpoint config where `thread_id`, `checkpoint_ns`, or `checkpoint_id` is an object operator payload instead of a string.
- Positive proof is a query result crossing from the attacker's expected thread/namespace into another synthetic checkpoint. Negative proof is strict string/schema enforcement or patched 1.3.1 behavior.
- Evidence should include the package version, exact API path that accepts `config.configurable`, redacted payload shape, expected tenant/thread IDs, observed checkpoint ID, and cleanup.

### August 6: LangGraph SQL namespace segment matching

[GHSA-47pj-3jcm-6whg](https://github.com/advisories/GHSA-47pj-3jcm-6whg) / CVE-2026-71433 adds a distinct store-boundary failure in `langgraph-checkpoint-postgres` and `langgraph-checkpoint-sqlite` before 3.1.1. These stores flattened hierarchical namespace tuples into dot-joined strings and implemented scoped reads with SQL pattern matching. A prefix such as `("foo",)` could therefore include sibling namespaces such as `("foobar",)` or `("foo2",)`; `_` and `%` in labels acted as pattern metacharacters; suffix matching could confuse leaves such as `alice` and `malice`; and SQLite `LIKE` introduced a case-folding difference from exact `get`/`put`/`delete` operations. This is pattern construction, not SQL injection, and the advisory limits impact to `search` and `list_namespaces` reads.

Build an isolated two-tenant store fixture for each backend. Seed only random marker values under namespace tuples that differ by one controlled dimension:

| Case | Requested scope | Control sibling |
| --- | --- | --- |
| segment prefix | `("tenant", "1")` | `("tenant", "12")` |
| lexical sibling | `("foo",)` | `("foobar",)` |
| underscore | `("user_1",)` | `("userX1",)` |
| percent | a label containing `%` | a non-descendant matching the resulting pattern |
| suffix | `suffix=("alice",)` | leaf `malice` |
| SQLite case | one mixed-case label | a case-only sibling |

Record the logical namespace tuple, flattened database value, bound pattern, escape character, generated predicate, backend, operation, and returned marker IDs. Run exact `get`, `put`, and `delete` as negative controls without mutating the sibling record. A bounded positive is **scope tuple A -> SQL pattern lacks a segment boundary or escapes -> `search`/`list_namespaces` returns synthetic marker B**. Repeat against 3.1.1 and, where practical, `InMemoryStore`; the fixed SQL behavior should require exact namespace equality or a literal dot before descendants and should escape pattern characters.

Do not query real agent memory, prompts, checkpoints, or hosted tenant data. Report read-scope drift only: do not infer write/delete access, SQL injection, or universal hosted exposure. Preserve deployment backend and namespace-label preconditions; fixed-length identifiers without `%` or `_` are an important negative control because one such label cannot be a prefix of another.

### Chisel tunnel ACL enforcement

- Use a dedicated Chisel lab server with an `--authfile` that allows one benign destination, such as a disposable echo listener on `127.0.0.1:9001`, and denies another listener on `127.0.0.1:9002`.
- Authenticate as the low-privilege test user and declare only the allowed remote during handshake. After setup, attempt to open a later channel to the denied listener.
- Proof is positive when traffic reaches the denied canary listener despite the initial ACL declaration being limited. Do not use the bypass to reach real internal services.
- Evidence should include Chisel version, `authfile` rule with secrets redacted, declared remote, attempted post-handshake destination, canary listener log, and fixed 1.11.5 behavior if available.

### Go-Attestation measurement parser boundary

- Keep this in an offline lab verifier. Generate or mutate a TPM event log containing an EFI signature list with non-zero `SignatureHeaderSize` and a marker SHA-256 value in the vendor header bytes.
- Feed the log to the vulnerable parser and observe whether the marker hash appears in the trusted measurement database. Repeat with fixed parser behavior or a patched build to confirm the vendor header bytes are skipped.
- Do not use real device endorsement material, production boot logs, or customer trusted databases as proof artifacts.
- Evidence should include parser commit/version, synthetic event-log fixture hash, marker value, parser output before/after patch, and the UEFI field layout that triggered the boundary.

## Reporting heuristics

- Lead with the exact boundary crossed: Builder-controlled OAuth2 URL to server-side fetch, automation query ID to backend REST request, HTTP/2 pseudo-header to HTTP/1 backend bytes, URI/method text to HTTP/1 start line, checkpoint config object to MongoDB operator, Chisel handshake ACL to later SSH channel, or TPM vendor bytes to trusted measurement entry.
- Preserve preconditions. These are high-signal when tied to role, feature, bridge topology, package version, and deployment pattern; they become noisy if reported as generic SSRF, generic request smuggling, or generic auth bypass.
- Use inert canaries and lab-only listeners. Avoid metadata-service reads, backend desync against real users, production tenant checkpoint access, internal network pivoting, or manipulating real attestation trust stores.

## July 24 SwiftNIO HTTP/2 header-value follow-up

[GHSA-q3g2-m552-3r9c](https://github.com/advisories/GHSA-q3g2-m552-3r9c) / CVE-2026-64785 extends the bridge matrix beyond the earlier pseudo-header issue. In affected `swift-nio-http2` pipelines, regular HTTP/2 header values could carry CR/LF/NUL or other controls into an HTTP/1.1 serialization, while `:path` could carry spaces that alter request-line tokenization. Stock pipelines with outbound HTTP/1 validation enabled reject these forms; exposure requires a bridge that disables that validator or trusts the translated `HTTPRequestHead` before forwarding. Version `1.45.0` is the fixed control.

Add paired raw-byte fixtures for a regular marker header and a marker `:path`. Record the inbound H2 representation, translated request head, outbound-validator setting, exact HTTP/1 bytes at a disposable backend, and parser decision. Use one connection and harmless routes only. Report **validated-looking H2 field -> H2/H1 codec -> changed HTTP/1 field or request-line structure**, not generic request smuggling when stock outbound validation blocks the path.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. SwiftNIO decompression/header-block/ByteBuffer resource issues, MLflow model-version enumeration, Firefly II stored XSS, and similar availability or narrow UI findings were tracked but not promoted in this batch because they did not add a stronger reusable privilege, tenant, parser-differential, filesystem, or control-plane boundary than the items above. No new PortSwigger, Trail of Bits, ProjectDiscovery, Disclosed, or CISA KEV item in this run added a higher-signal offensive operator workflow than the GitHub advisory batch above.

## October 5 follow-up: LangGraph SDK auth decorator `actions=` silently applies resource-wide ([CVE-2026-104873](https://github.com/advisories/GHSA-fvww-7h3r-vfhp))

`langgraph-sdk` registered handlers written as `@auth.on.threads(actions=["create"])` for **every action** on the resource instead of the listed subset. Because the resource-wide handler is selected ahead of broader fallback handlers, authorization logic that lives in those fallbacks never runs — an authenticated user may read/update/delete another user's threads, assistants, or crons depending on what the mis-scoped handler returns. Fixed 0.4.4; only Python deployments using `actions=` on resource-scoped decorators (`@auth.on.threads`, `@auth.on.assistants`, `@auth.on.crons`) are affected.

Operator axes: this is the selector-granularity sibling of the wrong-predicate family — a filter parameter that is accepted, parsed, and then dropped by the dispatcher. Audit rule for any decorator/annotation-based authorization system: register the same handler twice, once scoped to one action and once scoped to a different action, then exercise the *unlisted* action; if the scoped handler fires, the filter is decorative and every fallback behind it is dead. Black-box version on LangGraph deployments: with two lab users, have user B call threads read/update/delete endpoints against user A's synthetic thread while the app's auth handler used `actions=`; a deny that should come from a fallback handler returning 403 instead succeeds = the mis-scope is live. Keep proofs to disposable threads/assistants and never touch real assistant state or cron jobs.
