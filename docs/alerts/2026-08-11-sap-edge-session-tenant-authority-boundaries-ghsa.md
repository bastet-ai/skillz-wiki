---
title: SAP edge session, tenant, and backend authority boundaries
---

# SAP edge session, tenant, and backend authority boundaries

An August 11 GitHub advisory wave exposes a reusable enterprise-edge testing pattern: SAP Approuter accepts browser, token, certificate, tenant, header, and WebSocket input before forwarding requests to higher-trust backends. Test each identity and routing claim at the final backend decision. A correct outer login is not proof that session loading, tenant selection, callback identity, backend scope, or upgraded connections preserve the same authority.

Adjacent SAP records add two useful downstream checks: spreadsheet external references becoming BusinessObjects server-file reads, and unauthenticated SAP MII servlet or scheduling routes reaching business-data operations.

Primary records:

- request-header forwarding and limited information access: [GHSA-h7cr-m88c-98m3 / CVE-2026-66778](https://github.com/advisories/GHSA-h7cr-m88c-98m3);
- session-header integrity bypass and another user's session context: [GHSA-2x68-8jqv-5gp3 / CVE-2026-66776](https://github.com/advisories/GHSA-2x68-8jqv-5gp3);
- login CSRF and attacker-identity session binding: [GHSA-397p-hh8q-gwmh / CVE-2026-66775](https://github.com/advisories/GHSA-397p-hh8q-gwmh);
- protected backend-resource authorization bypass: [GHSA-94ww-hmrp-6w4f / CVE-2026-66777](https://github.com/advisories/GHSA-94ww-hmrp-6w4f);
- callback client-certificate identity mismatch: [GHSA-x986-f697-6r4v / CVE-2026-66760](https://github.com/advisories/GHSA-x986-f697-6r4v);
- tenant-context spoofing: [GHSA-w69g-xj7m-rmrv / CVE-2026-58239](https://github.com/advisories/GHSA-w69g-xj7m-rmrv);
- token content steering credential material to an attacker-controlled destination: [GHSA-vhh6-v828-x62f / CVE-2026-58230](https://github.com/advisories/GHSA-vhh6-v828-x62f);
- WebSocket authorization drift: [GHSA-pf62-cqrr-jr3r / CVE-2026-58237](https://github.com/advisories/GHSA-pf62-cqrr-jr3r);
- BusinessObjects spreadsheet external-reference file disclosure: [GHSA-xpjj-rh44-8gf9 / CVE-2026-58248](https://github.com/advisories/GHSA-xpjj-rh44-8gf9);
- SAP MII unauthenticated scheduling functions: [GHSA-jc2h-p8j7-x9g5 / CVE-2026-44765](https://github.com/advisories/GHSA-jc2h-p8j7-x9g5); and
- SAP MII Cost Servlet backend operations: [GHSA-jggc-v6c7-qw59 / CVE-2026-44764](https://github.com/advisories/GHSA-jggc-v6c7-qw59).

These GitHub records were unreviewed when scanned and do not disclose exact request shapes or all affected configurations. Confirm the product, component, route topology, authentication mode, tenant model, certificate policy, enabled WebSocket routes, affected build, and vendor fix before reporting. Treat the behaviors above as test hypotheses, not proof that an observed SAP deployment is vulnerable.

!!! warning "Owned tenants, synthetic sessions, and denied sinks only"
    Use an isolated SAP lab or customer-approved test environment, two disposable users and tenants, synthetic session markers, a private test CA, owned no-content callback peers, mock backends, harmless WebSocket messages, synthetic spreadsheets, and patched file/business-operation sinks. Never collect real sessions or credentials, access another customer's tenant, read server files, change scheduling or cost data, relay authentication material, or use production users as CSRF victims.

## Boundary map

| Surface | Caller-controlled authority | Final sink | Bounded positive |
| --- | --- | --- | --- |
| forwarded HTTP request | duplicate, alternate-case, hop-by-hop, identity, or routing header | backend-visible request and authorization | forbidden canary header survives normalization and changes a no-op backend decision |
| session restore | session-related header values | loaded principal and session object | A request selects B's synthetic session marker after integrity verification should fail |
| authentication flow | cross-site navigation and attacker login state | browser session binding | victim browser ends authenticated only as the disposable attacker account |
| backend route | method, path, scope, destination, or rewrite input | protected resource handler | A reaches B's denied no-op handler through the edge while direct authorization denies it |
| callback mTLS | certificate chain, subject fields, SANs, and callback parameters | internal-component identity | different test certificate from the trusted CA is accepted as the expected component |
| tenant selection | host, token claim, path, query, header, or routing metadata | backend tenant context | A request selects B's marker-only tenant at a denied resolver |
| token processing | token content and configured destination fields | credential-bearing outbound request | fake credential marker would target an owned recorder but the send is denied |
| WebSocket upgrade | HTTP identity plus upgrade headers and destination | message-level operation | HTTP upgrade succeeds and A reaches a B-only no-op operation without a message check |
| spreadsheet data source | external-reference path or URI | server-side file resolver | sibling canary path reaches a denied open sink; no bytes are returned |
| MII alternate route | servlet, scheduler action, IDs, and method | business-data read/write/delete operation | unauthenticated request reaches a denied operation recorder after route dispatch |

## 1. Build one identity-and-routing trace

Instrument the entire path rather than testing each proxy response in isolation:

```text
TCP peer and browser origin
-> TLS/client-certificate identity
-> raw HTTP headers and request target
-> Approuter normalization and authentication
-> selected session and tenant
-> route/rewrite and backend destination
-> backend-visible principal, headers, method, and path
-> resource or operation authorization
-> response assignment
```

For every request, preserve the raw request, normalized header multimap, duplicate-header precedence, authenticated principal, selected tenant, session identifier hash, route name, final backend authority tuple, and denied sink result. Redact bearer material; synthetic fixtures should need no reusable secret.

A proxy-side `200`, `101`, or error difference is only a lead. The reportable positive is a caller-controlled value changing the final session, tenant, backend, or operation without the corresponding authorization.

## 2. Diff raw headers against backend-visible authority

Put an owned recorder behind Approuter. It should return only a random request ID and record header names plus synthetic values. Do not place credentials in the fixture.

Compare:

- one ordinary header against duplicate, comma-joined, empty, whitespace, mixed-case, and underscore variants;
- headers documented as edge-generated against caller-supplied copies;
- hop-by-hop and forwarding headers named both in `Connection` and directly;
- original versus percent-encoded or normalized request targets;
- direct HTTP and WebSocket upgrade paths; and
- affected and corrected builds with the same route configuration.

Record whether Approuter strips, overwrites, merges, renames, or forwards each value. A bounded positive is **unauthenticated or low-privilege request -> forbidden synthetic header survives -> mock backend selects a restricted no-op branch**. Header survival alone is insufficient if no downstream decision trusts it.

## 3. Separate session integrity from login CSRF

Create disposable accounts A and B with visibly different random profile markers and no data. Patch every mutating application action. Use fresh browser profiles and record cookies only as one-way hashes.

For session-header integrity, vary one field at a time across valid A values, valid B values observed only inside the lab, mismatched tuples, missing fields, duplicates, stale values, and random values. A positive requires the backend-visible principal or session marker to change to B despite a failed or absent integrity proof. Do not retrieve B-owned objects.

For login CSRF, start with a browser that is logged out and contains no retained application state. Initiate the authentication flow using attacker account A, transfer only the documented cross-site navigation artifact to the test-victim browser, and complete the flow without exposing any reusable code or token in evidence. The bounded result is **victim browser is bound to disposable account A when the flow should require victim intent or CSRF state**. Do not perform any action from that session.

Keep these as separate findings: session substitution abuses server-side context selection; login CSRF binds a browser to an attacker's identity.

## 4. Bind mTLS callbacks to the complete certificate identity

Use a private CA and issue certificates with controlled differences:

| Certificate | Chain | Subject | SAN | Key | Expected |
| --- | --- | --- | --- | --- | --- |
| intended component | trusted | expected | expected | K1 | allow control |
| same subject, different SAN | trusted | expected | alternate | K2 | deny |
| different subject, same SAN | trusted | alternate | expected | K3 | deny |
| same displayed fields, different registered component | trusted | expected | expected | K4 | deny unless explicitly enrolled |
| expired or wrong EKU | trusted | expected | expected | K5 | deny |
| untrusted chain | untrusted | expected | expected | K6 | deny |

Patch the callback handler after certificate validation so it records the selected synthetic component and denies the operation. Capture the verified chain, SAN, subject, EKU, fingerprint, expected component identity, and binding decision. A positive is not merely “the CA is trusted”; it is **a certificate not enrolled for component B is accepted as B because matching fields replace a complete certificate-to-component binding**.

## 5. Resolve tenant authority once, then preserve it

Seed tenants A and B with random marker IDs. Enumerate every possible tenant selector: SNI/Host, route, path, query, headers, session state, token claims, callback parameters, and backend destination metadata. Patch tenant lookup and all data access.

Run a pairwise matrix where one selector says A and another says B. Include omitted, duplicate, stale, encoded, mixed-case, and unknown tenant values. Record which selector wins at authentication, routing, session load, backend lookup, and response generation.

The secure result derives one authorized tenant from authenticated context and rejects conflicts. A bounded positive is **caller A -> conflicting untrusted selector B -> final backend tenant resolver selects B's synthetic marker**. Stop before any B object is opened.

## 6. Keep token validation and outbound destination policy coupled

The token-content record suggests a high-complexity configuration where crafted token data can cause credential material to be sent to an attacker-controlled destination. Prove only the authority transition.

Use fake credentials, a locally signed canary token, an owned no-content HTTPS peer, and a network client patched before connect. Vary issuer, audience, key URL, callback URL, destination-like claims, duplicates, scheme, host case, userinfo, port, redirects, and resolved peer. Record token-validation result, trusted configuration, derived destination, redirect hops, final authority tuple, and whether credential headers would be attached.

A bounded positive is **untrusted token field -> derived owned destination -> fake credential header present at the denied send sink**. Do not send even fake credential bytes if a patched request recorder can prove the result. Do not probe metadata, loopback services, private ranges, or unowned hosts.

## 7. Reauthorize after WebSocket upgrade

Authentication at `GET ... Upgrade: websocket` does not authorize every later destination or message. Use users A and B, separate route markers, and an inert message schema whose handler only records operation name and tenant before denying.

Test:

- unauthenticated, A, B, expired, and logged-out sessions at upgrade time;
- session invalidation after upgrade;
- A upgrade followed by B-scoped subscription or operation identifiers;
- route, subprotocol, origin, cookie, and token disagreements;
- reconnect and resume identifiers; and
- direct backend WebSocket reachability versus the documented edge path.

A bounded positive is **A obtains a connection -> sends B-scoped inert message -> B-only operation recorder is selected without message-level authorization**. Do not subscribe to real topics or retain messages from other users.

## 8. Treat spreadsheet references as server-side file selectors

Create a disposable BusinessObjects report environment and a spreadsheet containing ordinary cells plus one external reference to a synthetic canary file. The canary contains no secret. Patch file open and external-link resolution so the sink records the canonical path and always denies.

Vary relative and absolute paths, URI forms, encoded separators, platform separators, symlinked in-root paths, nonexistent files, and references changed after upload. Record upload owner, parser, workbook relationship, raw target, canonical target, process identity, and first file sink.

A positive is **low-privilege spreadsheet -> external reference -> server process attempts to open the sibling canary path**. Do not return file bytes in the report and do not test system files. Distinguish upload acceptance from processing reachability and final file access.

## 9. Enumerate alternate MII route families before operation scope

The MII records describe unauthenticated scheduling functions and Cost Servlet requests reaching backend operations. Build a route inventory from application descriptors, client code, API documentation, and lab traffic. For each function, compare UI, servlet, scheduler, API, and versioned aliases using safe `OPTIONS`, denied-sink requests, and synthetic IDs.

Patch read, create, update, and delete handlers independently. Run this matrix:

| Identity | Route family | Synthetic object | Secure result |
| --- | --- | --- | --- |
| none | documented public status | public canary | allow only if intended |
| none | scheduler or Cost Servlet | nonexistent marker | deny before operation dispatch |
| A | A object | no-op operation | allow control if authorized |
| A | B object | any operation | deny before lookup or mutation |
| A | alternate route | same A operation | same policy as primary route |

A bounded positive is **no identity -> alternate route -> denied business-operation recorder receives an action and object ID**. Never create, modify, delete, schedule, or retrieve retained business data.

## Evidence and reporting checklist

- [ ] Advisory status, exact component, route topology, configuration, affected build, and corrected build are explicit.
- [ ] Raw request, edge normalization, selected identity/session/tenant, final backend request, and denied sink are correlated by one random ID.
- [ ] Header forwarding is tied to a downstream authorization effect, not reported from reflection alone.
- [ ] Session-substitution and login-CSRF findings use disposable accounts and perform no post-login action.
- [ ] Certificate proof records chain, SAN, subject, EKU, fingerprint, and expected component binding.
- [ ] Tenant tests stop at a synthetic resolver and never open another tenant's object.
- [ ] Token-destination proof uses fake credentials, an owned peer, and a denied network sink.
- [ ] WebSocket authorization is tested at both upgrade and message dispatch.
- [ ] Spreadsheet proof stops at a denied canonical file path and returns no bytes.
- [ ] MII proof stops at a denied operation recorder and mutates no scheduling, cost, or business data.
- [ ] Claims do not exceed the demonstrated boundary; do not infer arbitrary file read, account takeover, SSRF, or code execution without the corresponding final sink.

## October 13 follow-up: SAP October Patch Day legs (published 2026-10-13 03:30Z)

- **[GHSA-v27c-xfw8-q954 / CVE-2026-89108](https://github.com/advisories/GHSA-v27c-xfw8-q954) (critical, SAP MII): MII administrator submits a crafted request in administrative functionality to provision an account with elevated privileges on the underlying Java application server → administrative control of the substrate beyond the vulnerable application.** New row for this page's model: *app-admin → platform-admin elevation*. Application-level "admin" is never the ceiling — enumerate what accounts, roles, or objects the application can create on its substrate (Java EE realm, embedded DB users, OS service accounts) and test the provisioning verbs as the app-admin principal in a lab. MII now anchors both this page's unauthenticated-route section (§9) and the admin-to-runtime elevation class.
- **[GHSA-m3j7-wp2j-mhc3 / CVE-2026-89111](https://github.com/advisories/GHSA-m3j7-wp2j-mhc3) (critical, SAP Cloud SDK for Python): OAuth2 SSRF — attacker-controlled `tenant_subdomain` redirects OAuth2 token requests to an attacker server, exfiltrating client credentials in multi-tenant BTP apps.** Tenant *name/slug* used to build the token-endpoint URL breaks §5's "resolve tenant authority once, then preserve it": the tenant selector picks the **credential destination**, not just the data partition. Sweep every SDK/middleware that derives `https://<slug>.<domain>` auth endpoints from request- or claim-supplied values; proof = fake client credential marker observed at your owned recorder instead of the real IAS host.
- **[GHSA-mw39-66pq-v675 / CVE-2026-89107](https://github.com/advisories/GHSA-mw39-66pq-v675) (critical, S/4HANA Manage Substitution/Validation Rules): rule DSL input interpreted as executable ABAP by rule-processing logic → full system compromise for a holder of specific business privileges.** Business-DSL-to-runtime parity: any "safe" configuration scripting surface that a lower-layer interpreter re-reads as code is an authorization bypass by design. Audit question for any product with rule/formula/flow DSLs: what does the DSL compile/interpret into, and can input reach constructs beyond the DSL's declared grammar?
- **[GHSA-hxp9-cq3v-3qr5 / CVE-2026-89120](https://github.com/advisories/GHSA-hxp9-cq3v-3qr5) (high, ABAP Platform): API-change regression *reintroduces* a previously fixed authorization weakness — session manager openable in single-transaction mode incl. from FLP, low-privilege crafted requests bypass restrictions.** Durable rule: patched ≠ re-tested. After any SAP upgrade (and patch days especially), re-run previously reported authorization probes — regression is a first-class re-test trigger, and "previously fixed" advisories signal the vendor's own regression pipeline misses.
- **[GHSA-2v6r-vpfh-4h7c / CVE-2026-89105](https://github.com/advisories/GHSA-2v6r-vpfh-4h7c) (medium, cloud-security-services-integration-library): HybridTokenAuthenticator accepts tokens from unintended ambient IAS/XSUAA bindings → unauthorized access.** Ambient-issuer acceptance: the auth library collects trust anchors from environment/config bindings, not only the intended issuer. Audit = enumerate every issuer the deployed library will *actually* accept (env vars, service bindings, mounted config), then test cross-issuer token acceptance with synthetic tokens from a binding you control.
- Inventory without new axes: Commerce Cloud SQLi (m5h4 high), NetWeaver EP unauth restricted-resource read + reflected-XSS pair (7v2g/92g9), EP attacker-link content-in-trusted-context (v6h2), GUI-for-HTML/UI5 stored XSS (69q3/crmc), MII stored XSS (p86p), S/4HANA instance-authz modification check (hj55), customs-catalog info disclosure (6jgh), Cloud Connector adjacent-network info leak (j3v6), NetWeaver/Web Dispatcher internal-protocol memory-corruption DoS (f9wm — availability-only; watch for KEV).
