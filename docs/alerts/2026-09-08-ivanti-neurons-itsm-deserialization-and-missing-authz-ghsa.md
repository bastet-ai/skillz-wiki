# Ivanti Neurons for ITSM before 2026.2: deserialization sinks and missing-authorization routes to arbitrary code execution (8 GHSAs)

Source: hourly offensive-security scan, 2026-09-08 late GitHub `unreviewed` advisory wave (published 2026-09-08 15:31 UTC, Ivanti Neurons for ITSM cluster). This is a new operator page because the eight advisories expose a **repeatable ITSM/CMDB appliance audit axis**: an enterprise appliance whose HTTP surface carries (a) object/graph-data deserialization endpoints reachable with different authentication strengths — three of them **unauthenticated** — and (b) management routes that execute code with no authorization check at all. Each record is a different instance of the same question: **which byte sequence crosses from HTTP into a deserializer or a code-executing handler, and what credential gates it?**

Primary entries: [GHSA-rqrh-xrq8-v5c4](https://github.com/advisories/GHSA-rqrh-xrq8-v5c4), [GHSA-fgj3-259w-8mmm](https://github.com/advisories/GHSA-fgj3-259w-8mmm), [GHSA-w2vf-r8hj-2qr9](https://github.com/advisories/GHSA-w2vf-r8hj-2qr9) (deserialization, critical, unauthenticated), [GHSA-8c5w-pg5c-69g3](https://github.com/advisories/GHSA-8c5w-pg5c-69g3), [GHSA-7556-4q8c-55vc](https://github.com/advisories/GHSA-7556-4q8c-55vc) (deserialization, high, authenticated), and [GHSA-c82j-rg2r-f495](https://github.com/advisories/GHSA-c82j-rg2r-f495), [GHSA-5mqc-6wv5-fvcw](https://github.com/advisories/GHSA-5mqc-6wv5-fvcw), [GHSA-x5fg-jpx8-4322](https://github.com/advisories/GHSA-x5fg-jpx8-4322) (missing authorization, critical, authenticated), all before 2026.2.

!!! warning "Authorized lab validation only"
    Keep proofs to a disposable Ivanti Neurons for ITSM 2026.x-lab (pre-2026.2) instance with synthetic objects/relations and a **denied** code-execution sink. Send inert deserialization canaries (a class name that resolves to nothing, or an inert serialized object) and record that the deserializer attempted to resolve/execute it. Do not achieve real code execution on a shared appliance, do not create or modify real tickets, incidents, or change records, do not touch a managed production CMDB/ITSM environment, and do not target unmanaged customer appliances. The adjacent Ivanti Endpoint Manager Mobile missing-authorization record (GHSA-qgx5-9x4j-gqmx) follows the same low-priv-to-admin axis but is a different product; keep it out of this page's lab.

## Why this is worth an operator page

Ivanti Neurons for ITSM is an ITSM/CMDB appliance: it stores configuration items, relations, incidents, and service requests, and its API layer deserializes structured objects. The wave shows two independent boundary failures on the same appliance:

1. **Deserialization with inconsistent credential gating.** Five records are deserialization-of-untrusted-data; three of them require *no* authentication. The deserializer itself is the sink — whoever can reach the endpoint can attempt arbitrary object construction. The reusable value is the **per-endpoint auth matrix** (unauth / low-priv / admin) attached to each deserialization sink.
2. **Missing authorization before code execution.** Three records are missing-authorization (CWE-862) on routes that let an *authenticated* attacker execute arbitrary code. The reusable value is the **route-level authorization check**: which management endpoints execute server logic without checking whether the caller is allowed to.

Together these are the standard two-axis audit for any ITSM/CMDB appliance: *what deserialization surfaces exist and what credential reaches each* + *which high-value routes skip the authorization check*.

## The two boundary classes

### 1. Deserialization sinks with inconsistent authentication (5 GHSAs)

| GHSA | Severity | Auth precondition per advisory |
| --- | --- | --- |
| [GHSA-rqrh-xrq8-v5c4](https://github.com/advisories/GHSA-rqrh-xrq8-v5c4) | critical | **unauthenticated** remote attacker |
| [GHSA-fgj3-259w-8mmm](https://github.com/advisories/GHSA-fgj3-259w-8mmm) | critical | **unauthenticated** remote attacker |
| [GHSA-w2vf-r8hj-2qr9](https://github.com/advisories/GHSA-w2vf-r8hj-2qr9) | critical | **unauthenticated** remote attacker |
| [GHSA-8c5w-pg5c-69g3](https://github.com/advisories/GHSA-8c5w-pg5c-69g3) | high | authenticated remote attacker |
| [GHSA-7556-4q8c-55vc](https://github.com/advisories/GHSA-7556-4q8c-55vc) | high | authenticated remote attacker |

Each advisory: "A Deserialization of Untrusted Data vulnerability in Ivanti Neurons for ITSM before 2026.2 allows a remote [un]authenticated attacker to execute arbitrary code on the server." The operator pattern:

| Boundary | Defect | Reusable check |
| --- | --- | --- |
| HTTP object endpoint → deserializer | Serialized object bytes from the request body reach a deserializer that can resolve arbitrary classes | Identify every endpoint that deserializes structured object data; record the credential strength required to reach it (none / low-priv / admin). |
| Unauthenticated deserialization | Three of the five deserialization sinks require no credential at all | The unauth-reachable deserializer is the top-priority sink: it is the direct unauth-RCE surface. Confirm the auth filter chain on the route (or its absence). |
| Consistent-gate expectation | The same data type (an object/serialization) is gated differently per route | A gate that is admin-only on one route but open on another is a configuration/authorization inconsistency — report the per-route matrix, not one CVE. |

### 2. Missing authorization on code-executing management routes (3 GHSAs)

| GHSA | Severity | Auth precondition per advisory |
| --- | --- | --- |
| [GHSA-c82j-rg2r-f495](https://github.com/advisories/GHSA-c82j-rg2r-f495) | critical | authenticated remote attacker |
| [GHSA-5mqc-6wv5-fvcw](https://github.com/advisories/GHSA-5mqc-6wv5-fvcw) | critical | authenticated remote attacker |
| [GHSA-x5fg-jpx8-4322](https://github.com/advisories/GHSA-x5fg-jpx8-4322) | critical | authenticated remote attacker |

Each advisory: "A Missing Authorization vulnerability in Ivanti Neurons for ITSM before 2026.2 allows a remote authenticated attacker to execute arbitrary code on the server." The operator pattern:

| Boundary | Defect | Reusable check |
| --- | --- | --- |
| Management route → server code execution | A route that executes privileged server logic does not check whether the caller is authorized for that action | For each high-value route (config, import, script/report, maintenance), confirm the authorization check. A positive is a low-priv authenticated caller reaching a code-executing handler with no role check. |
| Any authenticated user → arbitrary code | The "authenticated" gate is present but the "authorized" gate is missing | Distinguish *authenticated* (whoever has a session) from *authorized* (the right role). The report is the missing role/action check, with the exact route and the privilege that should have been required. |
| Low-priv account as the escalation springboard | A single low-priv credential is enough to reach code execution | Confirm the lowest-privilege account that can reach the route; that is the real blast-radius precondition, not "an admin." |

## Cross-cutting operator lessons

1. **The deserialization endpoint's credential gate is the finding.** On ITSM/CMDB appliances, the object/serialization endpoints are the RCE sinks. The durable artifact is a **per-sink auth matrix**: which deserializer, which route, which credential. An unauth-reachable deserializer is unauth RCE; a low-priv-reachable deserializer is privilege escalation.
2. **"Authenticated" is not "authorized."** The three missing-authorization records prove the appliance distinguishes login from capability. Audit each high-value route for the *role* check, not just the session check. The reusable question: "what is the lowest-privilege session that can execute this handler?"
3. **Two-axis appliance audit.** For any ITSM/CMDB/helpdesk appliance: (a) enumerate deserialization surfaces and their credential gates; (b) enumerate code/executing management routes and their authorization checks. These two matrices, together, define the appliance's RCE attack surface.
4. **Version line is the unit of reporting.** All eight are "before 2026.2." Confirm the exact build and the patched build boundary before reporting; the wave is one product at one version line.

## Replayable validation boundaries

### Deserialization sink (unauthenticated first)

1. Stand up a **disposable** Ivanti Neurons for ITSM instance on a pre-2026.2 build in an isolated lab network.
2. Identify a deserialization endpoint and send an **inert canary**: a serialized reference to a non-existent class, or a serialized object whose payload is a marker string.
3. A positive is the deserializer attempting to resolve/execute the canary (error response naming the class, or the marker appearing in a response/log in the lab). **Stop there.** Do not achieve real code execution, do not exfiltrate, and do not plant a real gadget on a shared appliance.
4. Record the credential level that reached the sink (none, low-priv, admin) and the exact route.

### Missing-authorization route

1. On the same disposable instance, create a **synthetic low-privilege account**.
2. Attempt to reach the code-executing management route with that low-priv session.
3. A positive is the handler executing server logic for the low-priv caller with no role check. Prove the *reachability and missing check*; do not complete a real code-execution payload. Record the route, the credential that reached it, and the role that should have been required.

## Safety

- **Disposable lab instance only.** One pre-2026.2 build, synthetic objects/accounts, and a denied real-code-execution sink. Never point these proofs at a managed or production ITSM/CMDB environment.
- **Inert canaries only.** Deserialization proofs use a non-resolving class or an inert marker; no live RCE gadget is dropped or executed on a shared appliance.
- **No real ITSM data.** No tickets, incidents, change records, or configuration items are created, modified, or read in a production system; proofs use synthetic records in the lab.
- **No credential capture or lateral movement.** The lowest-privilege account is a synthetic lab account; no real user sessions are captured or reused.

## Sources

- https://github.com/advisories/GHSA-rqrh-xrq8-v5c4
- https://github.com/advisories/GHSA-fgj3-259w-8mmm
- https://github.com/advisories/GHSA-w2vf-r8hj-2qr9
- https://github.com/advisories/GHSA-8c5w-pg5c-69g3
- https://github.com/advisories/GHSA-7556-4q8c-55vc
- https://github.com/advisories/GHSA-c82j-rg2r-f495
- https://github.com/advisories/GHSA-5mqc-6wv5-fvcw
- https://github.com/advisories/GHSA-x5fg-jpx8-4322
- https://github.com/advisories/GHSA-qgx5-9x4j-gqmx (adjacent Ivanti Endpoint Manager Mobile missing-authorization; tracked, not expanded here)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

*Source: hourly offensive-security scan, 2026-09-08 late GitHub `unreviewed` advisory wave. All eight `Ivanti Neurons for ITSM` advisories tracked in the [source index](../notes/source-index.md).*
