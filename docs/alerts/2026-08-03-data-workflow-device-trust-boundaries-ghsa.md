---
title: Data workflow, AI corpus, command-wrapper, and device-adoption boundaries
---

# Data workflow, AI corpus, command-wrapper, and device-adoption boundaries

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-08-03. These entries were unreviewed database records at scan time. Confirm the affected revision, deployment configuration, caller role, and corrected behavior from the linked upstream material before reporting.

This wave yields five durable operator patterns: data captured for one purpose reaching a later privileged interpreter, object identifiers detaching authorization from ownership, read-like validation routes mutating privileged component behavior, policy flags failing to bind secret-returning functions, and device-adoption protocols failing to bind provisioning material to a unique controller/device ceremony.

Primary sources:

- Shlink visit-export formula injection [GHSA-ghrv-q878-w45x / CVE-2026-18738](https://github.com/advisories/GHSA-ghrv-q878-w45x), title-resolution SSRF [GHSA-c6g4-pfhg-gvmp / CVE-2026-18736](https://github.com/advisories/GHSA-c6g4-pfhg-gvmp), and tag-statistics `ORDER BY` injection [GHSA-2jhc-j623-f52p / CVE-2026-18737](https://github.com/advisories/GHSA-2jhc-j623-f52p);
- Apache NiFi Parameter Context asset ownership [GHSA-xq5v-6pm7-4qw9 / CVE-2026-68980](https://github.com/advisories/GHSA-xq5v-6pm7-4qw9), component-impact authorization [GHSA-p3jm-q7cw-g645 / CVE-2026-68979](https://github.com/advisories/GHSA-p3jm-q7cw-g645), and validation-route authorization [GHSA-m6hg-5m93-2wrv / CVE-2026-62354](https://github.com/advisories/GHSA-m6hg-5m93-2wrv);
- DuckDB AWS extension secret-policy bypass [GHSA-g2r8-97m7-62w9 / CVE-2026-58139](https://github.com/advisories/GHSA-g2r8-97m7-62w9);
- Deloitte AI Assist RAG corpus access [GHSA-85qw-gwgm-xj6w / CVE-2026-57476](https://github.com/advisories/GHSA-85qw-gwgm-xj6w) and inert configuration additions [GHSA-23xg-h5j2-8fcf / CVE-2026-57475](https://github.com/advisories/GHSA-23xg-h5j2-8fcf);
- Emlog Pro AI transport trust [GHSA-j63f-h5jj-qrf5 / CVE-2026-67598](https://github.com/advisories/GHSA-j63f-h5jj-qrf5);
- Serverless Devs `s init` command construction [GHSA-rm7q-w9c9-27rj / CVE-2026-51190](https://github.com/advisories/GHSA-rm7q-w9c9-27rj), ClearOS Log Viewer command construction [GHSA-pfmm-hj96-f74x / CVE-2026-67599](https://github.com/advisories/GHSA-pfmm-hj96-f74x), and GL.iNet native-plugin command fields [GHSA-r4vc-wqp8-j499 / CVE-2026-18614](https://github.com/advisories/GHSA-r4vc-wqp8-j499), [GHSA-39jx-5rpr-2f33 / CVE-2026-18616](https://github.com/advisories/GHSA-39jx-5rpr-2f33), [GHSA-hh6h-4vwh-4vhf / CVE-2026-18615](https://github.com/advisories/GHSA-hh6h-4vwh-4vhf), [GHSA-j682-xx2h-hv5m / CVE-2026-18684](https://github.com/advisories/GHSA-j682-xx2h-hv5m), [GHSA-frjc-j2mw-rv29 / CVE-2026-18685](https://github.com/advisories/GHSA-frjc-j2mw-rv29), and [GHSA-7892-84cj-c35c / CVE-2026-18686](https://github.com/advisories/GHSA-7892-84cj-c35c); and
- Omada adoption shared certificates [GHSA-8mhg-76f5-54fp / CVE-2025-15628](https://github.com/advisories/GHSA-8mhg-76f5-54fp), hard-coded trust keys [GHSA-wwx9-ww39-c5vg / CVE-2025-15627](https://github.com/advisories/GHSA-wwx9-ww39-c5vg), predictable session keys [GHSA-5wj2-44xm-2hrq / CVE-2025-15629](https://github.com/advisories/GHSA-5wj2-44xm-2hrq), weak credential protection in transit [GHSA-9469-xx96-p5v2 / CVE-2025-15544](https://github.com/advisories/GHSA-9469-xx96-p5v2), and adoption-race identity binding [GHSA-xmx9-537g-pr66 / CVE-2025-15630](https://github.com/advisories/GHSA-xmx9-537g-pr66).

!!! warning "Disposable systems and inert sinks only"
    Use locally built applications, synthetic tenants, fake cloud credentials, owned HTTP/TLS endpoints, patched query/process/tool recorders, and disconnected network-device labs. Never query production data, contact metadata/internal services, open an active spreadsheet formula, capture provider tokens, execute shell input, recover credentials/session keys, or race adoption of an operational device.

## Boundary map

| Surface | Trusted decision | Detached selector or later interpreter | Safe positive |
| --- | --- | --- | --- |
| Shlink title resolution | submitted long URL is allowed | redirects choose the final title-fetch destination | owned redirect ends at an owned canary service and its title returns |
| Shlink statistics | API key may sort tag statistics | caller-controlled direction crosses into `ORDER BY` grammar | SQL recorder shows structure beyond an allowlisted direction token |
| Shlink export | visit metadata is inert telemetry | spreadsheet import treats a leading cell character as a formula | exported bytes preserve the trigger-shaped canary in a formula-capable cell |
| NiFi asset | caller may modify Parameter Context A | caller supplies asset ID owned by context B | delete recorder receives B's synthetic asset after authorization against A |
| NiFi parameter update/validation | caller may read or modify a context | proposed values affect a component the caller cannot modify | validation recorder sees the canary value under the weaker role |
| DuckDB AWS | SQL execution is allowed but unredacted secrets are disabled | function argument requests an unredacted credential chain | result recorder receives only fake sentinel fields despite policy `false` |
| AI corpus/transport | public route or configured provider is trusted | caller-selected corpus object or unverified TLS peer reaches privileged AI state | synthetic corpus marker crosses tenant/auth boundary, or fake token reaches owned TLS peer |
| Command wrappers | field looks like URL/filter/port/key data | raw string is reparsed by a shell | patched process recorder shows a metacharacter changing argv or shell grammar |
| Device adoption | device/controller is participating in adoption | shared material, weak key derivation, or race selects peer/provisioning recipient | synthetic provisioning marker is accepted by the wrong lab peer or ceremony |

## 1. Trace Shlink data through fetch, query, and export interpreters

Use one local Shlink tenant, one API key with only the documented minimum role, one short URL, two owned HTTP listeners, a SQL recorder, and a CSV parser that never evaluates formulas.

### Final-destination title fetch

1. Establish a direct public-looking owned URL whose page title is a random canary.
2. Configure a second owned listener to return one redirect to the first. Vary only the final destination class in the lab: normal owned hostname, an owned hostname resolving to a loopback-bound canary service, and a blocked malformed control.
3. Create the short URL with title auto-resolution enabled. Record initial URL, every redirect hop, resolved IP, final socket destination, response title, and whether the title appears in the API response.
4. Repeat with auto-resolution disabled and with the corrected build or locally applied fix.

The positive is **approved initial URL -> redirect changes final destination -> owned loopback canary receives GET -> its synthetic title returns to the caller**. Do not request metadata addresses, private services, or production loopback ports. A redirect accepted by a generic client is not enough; prove the application's actual title resolver and returned title channel.

### `ORDER BY` direction grammar

Replace the Doctrine/database execution boundary with a recorder that captures generated DQL/SQL, bound values, and AST if available, then returns empty synthetic statistics.

Test the accepted direction tokens, mixed case, whitespace, a delimiter-shaped canary, and an invalid ordinary word. The reportable result is **API direction field -> unbound structural text in the recorded `ORDER BY` clause -> patched path rejects or maps to a fixed enum**. Do not add delay functions, boolean extraction, unions, comments, or database-specific file/network functions. Query construction proves the boundary without extracting a row.

### Export as a second interpreter

Send one request to the disposable short URL for each controllable visit field, placing a unique inert value beginning with `=`, `+`, `-`, or `@` in only one field per request. Export visits and inspect raw CSV bytes plus parser output with formula evaluation disabled.

Record source field, decoded value, serialized cell, quoting/escaping, and whether a spreadsheet would classify it as formula text. Do not open the file in Excel/LibreOffice or use DDE, URL, process, or external-workbook functions. Positive evidence is the trust transition **unauthenticated request metadata -> stored visit -> exported formula-capable cell**, not successful execution on an administrator workstation.

## 2. Bind NiFi Parameter Context authority to every affected object

Use two synthetic Parameter Contexts, `A` and `B`; one asset in each; one stopped component referencing each context; and roles with read-only A, write A, write B, and no component-write permission. Replace asset deletion, component validation, script evaluation, controller-service connection, and process launch with no-op recorders.

### Parent/child asset ownership matrix

For every combination of authorized context ID and requested asset ID, capture:

- caller and effective policies;
- request context ID;
- asset's stored context ID;
- authorization object selected;
- object passed to the delete sink; and
- affected versus 2.11.0 result.

A positive is **write permission on A + asset ID from B -> authorization checks A -> B asset reaches the no-op delete sink**. Never delete a real asset; the recorder should abort before persistence.

### Parameter update versus referencing-component authority

1. Give the test role write permission on context A but no write permission on stopped component X that references A.
2. Propose a random inert marker for one parameter used by X. Patch every component-specific validator to record component ID and proposed value, then return a fixed validation result.
3. Compare ordinary context update, validation-only request, and direct component modification under the same role.
4. Repeat with read-only context permission and with 2.11.0.

Report the edges separately:

- **context write -> changed parameter -> unauthorized referencing component's validation/evaluation recorder**, and
- **context read -> proposed override through validation route -> component validator invoked**.

Do not place script syntax in a parameter, start a component, contact a datasource, or claim code execution from a marker reaching a patched evaluator. The key issue is authorization composition: a context decision must include every component whose behavior the proposed value can influence.

## 3. Test secret-policy enforcement at the final DuckDB function

Create a disposable DuckDB/`pg_duckdb` fixture with a patched AWS credential provider that can return only obvious fake fields such as `AKIA_TEST_SENTINEL`, `secret-test-sentinel`, and `session-test-sentinel`. Deny all outbound network access.

1. Set `allow_unredacted_secrets=false` and verify the ordinary secret-display path redacts the fake fields.
2. Under a low-privilege SQL role, invoke only the documented credential-loading function with default options, explicit redaction enabled, and explicit redaction disabled.
3. Record role, database policy, function arguments, credential-provider invocation, and returned field-presence booleans. Do not print even synthetic values in a public report.
4. Repeat with the corrected extension revision while preserving the fake provider and SQL grants.

The bounded positive is **database-wide unredacted-secret policy disabled + ordinary SQL role + function-level override -> fake credential fields returned in plaintext -> corrected build denies or redacts**. Never allow the fixture to reach IMDS, IRSA, ECS, environment credentials, profiles, or a real cloud account.

## 4. Separate AI route authentication, corpus authority, TLS trust, and tool execution

### RAG corpus object matrix

For the AI Assist pattern, use a local or vendor-provided lab with two synthetic corpora containing only `TENANT_A_CANARY` and `TENANT_B_CANARY`. Enumerate routes from the lab UI/API schema rather than guessing against a hosted deployment.

Build a matrix of unauthenticated, tenant A, tenant B, and admin callers against list/read/add/delete-like corpus operations. Replace retrieval and mutation with recorders where possible. A positive is **unauthenticated or tenant A request + caller-selected corpus B parameters -> B's synthetic marker reaches a response/recorder, or an inert marker is queued for B**. The companion configuration advisory states that some unauthenticated additions were not consumed; record that as route exposure without inflating it into runtime impact.

### Provider TLS versus downstream tool authority

For Emlog Pro, configure an owned TLS endpoint presenting a lab-only CA certificate not trusted by the host. Patch tool-call handlers such as configuration update or database query to record the proposed tool name and inert arguments, then abort.

1. Configure only a fake bearer token and synthetic prompt.
2. Exercise each affected AI request path and record certificate validation result, negotiated peer identity, Authorization-header presence, response parser, and tool recorder.
3. Return one inert ordinary model response and one synthetic tool-call-shaped response from the owned endpoint.
4. Repeat with certificate verification enabled and a trusted lab certificate.

Report **untrusted certificate accepted -> fake provider token delivered to owned peer** separately from **owned peer response -> tool-call recorder reached**. Do not capture real API keys, update configuration, query a database, or claim arbitrary tool execution unless the exact application handler and authorization decision are independently proven.

## 5. Replace every command wrapper with an argv/grammar recorder

The Serverless Devs, ClearOS, and GL.iNet records all describe fields that appear structured,repository URL, log filter, port, WireGuard public key, or private key,but reach shell-backed helpers. Do not reproduce published command payloads.

1. Use an isolated CLI/application/appliance lab and patch the final `spawn`, shell, or native-plugin process boundary to log executable, argv elements, shell mode, working directory, effective role, and environment key names, then abort.
2. Send one valid field, one invalid ordinary value, whitespace, a quoting character, and a harmless metacharacter-plus-random-marker token. The marker must never name a command or path.
3. For `s init`, show that a URL satisfying the `.git` suffix check is still forwarded with `shell: true`; do not clone an untrusted repository.
4. For ClearOS, keep the log file synthetic and separate webconfig authorization from later sudo capability. Reaching the first process recorder does not prove root execution.
5. For GL.iNet, use only a disconnected MT3000 lab and test `s2s.enable_echo_server`, `server.set_peer`, and public-key-generation paths independently. Do not enable listeners, alter WireGuard peers, or persist configuration.

Positive evidence is **structured field -> shell-enabled command string -> recorder shows grammar/argv change -> fixed path uses direct argv plus field-specific validation**. Never execute a shell, invoke `sudo`, or leave an appliance service/configuration changed.

### August 4 GL.iNet RPC-wrapper follow-up

Three adjacent records extend the same MT3000 command-construction audit to `modem.so` profile removal, `modem.so` upgrade configuration, and the `nas-web.add_user` RPC wrapper. Keep these as additional field-to-process paths on this page rather than treating each sparse record as a standalone exploit.

1. Snapshot a disconnected 4.4.5 lab and patch the native-plugin process boundary to record method name, field name, executable, argv boundaries, shell mode, effective user, and persistence attempt, then abort.
2. Build an RPC inventory from the local UI bundle and plugin schema. Test `remove_profile`, `set_upgrade`, and `nas-web.add_user` independently with valid values, invalid ordinary values, whitespace, quoting, and a harmless metacharacter-plus-random-marker token.
3. For every request, record authentication state, role, CSRF/session requirement, exact RPC method, parsed argument object, and process-recorder output. The advisory statement that an issue is remotely reachable does not establish unauthenticated reachability.
4. Restore the snapshot between methods and compare against a corrected firmware build when one is available.

The bounded positive is **structured profile/upgrade/user field -> affected RPC wrapper -> recorder shows the random marker changing shell grammar or argv structure**. Do not remove profiles, initiate upgrades, create NAS users/shares, invoke a command, or retain appliance configuration. Keep endpoint authorization and command construction as separate findings.

## 6. Treat device adoption as a multi-party identity protocol

The Omada records are sparse and describe a cluster of weaknesses rather than request-level proofs. Use them to shape a protocol audit, not to guess credentials or impersonate deployed controllers.

In a disconnected lab with reset devices and a disposable controller, instrument or proxy the adoption channel to record message types, non-secret transcript hashes, certificate/key identifiers, nonce lengths, peer IDs, and state transitions. Use only random provisioning markers.

Test these bindings independently:

1. **Deployment uniqueness:** determine whether two lab devices/controller installations present identical embedded certificate or key identifiers. Do not extract or publish private material.
2. **Peer identity:** replace one lab peer with a recorder using only generated keys and observe whether shared trust material is sufficient to reach the next adoption state.
3. **Session freshness:** compare key/nonce derivation metadata across repeated reset adoptions; stop at a statistical collision/predictability observation and do not recover a session key.
4. **Credential protection:** feed only a generated canary credential into adoption and record whether the transcript exposes a weak, offline-testable verifier. Do not crack even the canary; demonstrate the construction with known inputs in the lab.
5. **Race binding:** place deterministic barriers around device registration and provisioning dispatch. Start two lab ceremonies for the same reset device identity and record which authenticated channel receives the random provisioning marker.

The strongest safe race result is **legitimate and competing lab ceremonies share device identity -> competing authenticated recorder wins state transition -> controller sends synthetic provisioning marker to the wrong ceremony**. Keep certificate reuse, weak hashing, key predictability, and race behavior as separate findings unless the lab proves a chain. Never adopt, reset, intercept, or impersonate an operational device.

## Reporting checklist

- [ ] Advisory review status, exact package/build, role, and feature configuration are recorded.
- [ ] Shlink evidence identifies the final socket destination, generated query structure, or exported cell without contacting internal services, querying data, or evaluating a formula.
- [ ] NiFi authorization records both the request-supplied parent and the object's stored parent, plus every referencing component affected by a proposed value.
- [ ] DuckDB uses a patched fake credential provider with outbound network disabled and reports only field presence.
- [ ] AI corpus, provider TLS, bearer delivery, response parsing, and tool dispatch are proven as separate edges with synthetic data.
- [ ] Command-wrapper evidence stops at a process recorder and distinguishes first process reachability from later privilege.
- [ ] Device-adoption evidence uses reset lab hardware, random provisioning markers, and no key/credential recovery.
- [ ] No production rows, visits, cloud credentials, corpus content, API keys, commands, device keys, or provisioning data appears in evidence.
