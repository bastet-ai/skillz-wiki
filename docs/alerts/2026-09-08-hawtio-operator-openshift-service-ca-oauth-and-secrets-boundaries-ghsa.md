# hawtio-operator: OpenShift Service-CA private-key minting, tenant-controlled OAuth redirect, and cluster-wide secret exposure (3 GHSAs)

Source: hourly offensive-security scan, 2026-09-08 late GitHub `unreviewed` advisory wave (OpenShift `hawtio-operator` cluster). This is a new operator page because the three advisories expose a **repeatable Kubernetes/OpenShift operator trust-boundary audit axis** that is durable well beyond the individual CVEs: an operator controller that (a) holds a cluster-scoped signing key and mints certificates with a caller-supplied subject, (b) registers a public OAuth client whose redirect URIs are tenant-controlled, and (c) carries a `ClusterRole` that reads every `Secret` in the cluster. Each leg is a standing, reusable check for any cluster operator or admission controller that bridges a tenant namespace into cluster-level authority.

Primary entries: [GHSA-hvx2-xh3r-xcr6](https://github.com/advisories/GHSA-hvx2-xh3r-xcr6) / CVE-2026-78234, [GHSA-7xpg-hm9r-chmf](https://github.com/advisories/GHSA-7xpg-hm9r-chmf) / CVE-2026-80219, and [GHSA-r6x8-cqxr-wwp4](https://github.com/advisories/GHSA-r6x8-cqxr-wwp4) / CVE-2026-77968.

!!! warning "Authorized validation only"
    Keep proofs to a disposable OpenShift/OpenShift-style cluster (OKD) with a synthetic `hawtio-operator`, one synthetic namespace, synthetic `Hawtio` custom resources, and a lab peer that trusts the Service CA for client authentication. Use a marker certificate subject, a marker OAuth redirect on an owned no-content peer, and denied `Secret`/KMS/Jolokia sinks. Do not read or dump real cluster `Secret`s (bootstrap tokens, cloud credentials, other operators' secrets), do not mint a live certificate that authenticates against a real in-cluster service, do not target real OAuth users or capture real access tokens, and do not touch production key material or shared cluster traffic.

## Why this is worth an operator page

These three advisories are not three isolated bugs; they are one **operator-as-trust-bridge** pattern repeated across three control planes (certificate authority, OAuth authorization, and `Secret` storage). The operator is a privileged controller whose inputs originate in a *tenant namespace* (a `Hawtio` CR) while its sinks operate at *cluster scope*. The reusable question for any red-team or bug-bounty assessment of a cluster add-on is: **what cluster-level authority does a namespaced input reach?** Each of the three legs answers that question for a different authority type.

## The three boundaries

### 1. Service-CA private-key minting with attacker-controlled subject (GHSA-hvx2-xh3r-xcr6 / CVE-2026-78234, critical 9.9, CWE-295)

The `hawtio-operator` reads the **OpenShift Service CA private signing key** from the `openshift-service-ca` namespace and uses it to mint client certificates whose **Subject Common Name (CN) is supplied by the author of a namespaced `Hawtio` custom resource**. Because the operator's `ClusterRole` aggregates `Hawtio` CR permissions into the `edit` and `admin` roles, **any user with `edit` access in any namespace can obtain a Service-CA-signed certificate with an arbitrary subject.** That certificate authenticates the holder to any in-cluster peer that trusts the Service CA for client authentication — including Jolokia agents and other Service-CA-trusting components — as **any** service identity.

| Boundary | Defect | Reusable check |
| --- | --- | --- |
| Operator mints certs from the cluster Service CA | The CN field of the issued cert is taken verbatim from tenant CR input | Confirm whether the operator constrains the CN/subject to a fixed set of service accounts or allows caller-supplied values. A positive is a cert issued with an operator-chosen CN distinct from the operator's own identity. |
| Tenant → cluster identity | A namespaced input produces a cluster-scoped cryptographic identity | Trace the CR field that becomes the cert subject; the reusable value is "namespaced field → cluster CA subject," not a specific CVE. |

### 2. Tenant-controlled OAuth redirect on an auto-grant public client (GHSA-7xpg-hm9r-chmf / CVE-2026-80219, high 8.7, CWE-1390)

When deploying `Hawtio` in cluster mode, the operator creates a **cluster-scoped `OAuthClient`** with `GrantMethod: auto` (automatic grant approval) and **no client secret** (a public client). The **redirect URIs are derived from the operator-created `Route`, whose hostname is tenant-controlled** via the `Hawtio` CR `spec.routeHostName` field. A malicious tenant can therefore **register an arbitrary hostname as a valid OAuth redirect target** and, because grants are auto-approved, **obtain the OpenShift access token of any cluster user who visits the crafted authorization URL without a consent prompt.**

| Boundary | Defect | Reusable check |
| --- | --- | --- |
| Operator registers a public OAuth client | `GrantMethod: auto` + no client secret = consentless token issue | Confirm the `OAuthClient` grant method and secret; a positive is `auto`/public combined with a tenant-writable redirect URI. |
| Tenant CR → OAuth redirect URI | `spec.routeHostName` (or the `Route` hostname it drives) becomes the redirect host | Trace which CR field reaches the `OAuthClient` `redirectURIs`; the reusable value is "tenant field → OAuth redirect authority." |

### 3. `ClusterRole` reads every `Secret` in the cluster (GHSA-r6x8-cqxr-wwp4 / CVE-2026-77968, high 8.2, CWE-269)

The operator's `ClusterRole` grants `secrets: [create, get, list, update, watch]` **across all namespaces**. Although the operator uses a controller-runtime label-selector cache as a memory optimization, the **ServiceAccount token authorizes read access to every `Secret` in the cluster**, and the operator also bypasses the cache via direct API calls. **Compromise of the operator pod yields read access to every `Secret` in the cluster, including bootstrap tokens, cloud credentials, and other operators' secrets.**

| Boundary | Defect | Reusable check |
| --- | --- | --- |
| Operator `ClusterRole` over `secrets` | All-namespace `get/list/watch` on `secrets` | Audit the operator `ClusterRole`/`Role` for `secrets` verbs; a positive is cluster-scoped or all-namespace read on `Secret` that is not narrowly label-scoped to the objects the operator actually manages. |
| Operator pod = cluster secret dump | One compromised controller reads every tenant's secrets | Record the blast radius: which namespaces' `Secret`s the operator token can read; the reusable value is the token's `Secret` read scope, not a CVE. |

## Cross-cutting operator lessons

1. **Namespaced input → cluster-scope authority is the operator audit axis.** Every cluster add-on controller is a trust bridge: tenant objects in namespace A drive actions at cluster scope. Inventory, per operator, the three authority types a namespaced input can reach: **certificate/signing identity**, **OAuth/identity tokens**, and **`Secret`/credential storage**. This wave proves all three in one operator.
2. **Caller-supplied certificate subject is a standing identity-forgery primitive.** Any component that signs certificates and takes the CN/SAN from external input is an identity-minting surface. Confirm the subject is constrained to a fixed service-identity set; treat "CR field → cert CN" as the enabler, and the Service-CA-trusting peer list as the blast radius.
3. **Tenant-controllable OAuth redirect + auto-grant + public client = consentless token theft.** The three legs (redirect host, auto-grant, no secret) must be checked *together*: any one is not the bug, the combination is. Trace the CR/Route field that reaches `OAuthClient.redirectURIs` and confirm the grant method and secret.
4. **`ClusterRole` `secrets` read scope is a blast-radius report.** For any operator, dump the effective `Secret` read scope of its `ServiceAccount` token (cluster-wide vs. label-scoped vs. namespace-scoped) and report it as the impact surface. A cache does not shrink the token's authority — the RBAC, not the in-memory optimization, is the control.
5. **The `ClusterRole` that aggregates a CR into `edit`/`admin` is the precondition for legs 1 and 2.** If a namespaced object is writable by `edit`, and that object's fields reach a signing key or an OAuth client, the low-priv write becomes a cluster-level read. Re-check which roles the add-on's CR verbs are aggregated into.

## Replayable validation boundaries

### Service-CA minting (GHSA-hvx2-xh3r-xcr6)

1. Stand up a disposable OKD/OpenShift cluster with the `hawtio-operator` installed and a synthetic namespace in which you hold `edit`.
2. Create a `Hawtio` CR whose author-controlled subject field contains a **marker CN** (e.g., `skillz-hawtio-canary`).
3. Trigger the operator's certificate-minting path and capture the issued certificate (in the lab namespace only). A positive is a cert whose CN is your marker, signed by the Service CA.
4. Prove sink reach by presenting the marker cert to a **lab peer that trusts the Service CA** and confirming it is accepted for client authentication. **Stop at the marker peer.** Do not use the cert against a real in-cluster service (Jolokia, API server, service accounts), do not read its `Secret`, and do not enumerate Service-CA-trusting components for live identity spoofing.

### OAuth redirect (GHSA-7xpg-hm9r-chmf)

1. In the disposable cluster, create a `Hawtio` CR in cluster mode whose `spec.routeHostName` points to an **owned no-content peer** you control.
2. Inspect the resulting `OAuthClient`: confirm `GrantMethod` and whether a client secret is set. A positive is `auto`/public with your peer's hostname in `redirectURIs`.
3. Construct the crafted authorization URL against a **synthetic (non-real) user** and confirm your peer receives the token-bearing redirect **in the lab only**. Use a synthetic token; do not target a real cluster user, do not capture a real access token, and do not visit the URL in a real browser session.

### `Secret` read scope (GHSA-r6x8-cqxr-wwp4)

1. Using the operator's `ServiceAccount` token in the disposable cluster, run a read of `secrets` in one namespace and in a *second, unrelated* namespace.
2. A positive is that the token reads `Secret` objects outside its own namespace (i.e., the all-namespace `get/list/watch` is live). Capture **only that the read succeeded** (object count / names, redacted); do not dump `Secret` data, do not read bootstrap/cloud-credential `Secret`s, and do not use any returned value.
3. Record the `ClusterRole` binding that authorizes this as the blast-radius evidence.

## Safety

- **Disposable cluster only.** One synthetic namespace, one synthetic `Hawtio` CR, a lab Service-CA-trusting peer, an owned no-content OAuth redirect peer, and denied `Secret`/KMS/Jolokia sinks.
- **No real identity forgery.** The marker certificate authenticates only against the lab peer; never against a real in-cluster service, service account, or API server.
- **No real token capture.** OAuth proofs use a synthetic user and a synthetic token against an owned peer; no real cluster user is targeted, no real access token is captured or used.
- **No `Secret` data disclosure.** The all-namespace `Secret` read is proven by the read succeeding (names/count, redacted), not by reading or exfiltrating `Secret` contents.
- **No production cluster mutation.** Do not modify live `ClusterRole`/`OAuthClient`/Service-CA key material or intercept shared cluster traffic.

## Sources

- https://github.com/advisories/GHSA-hvx2-xh3r-xcr6 (CVE-2026-78234)
- https://github.com/advisories/GHSA-7xpg-hm9r-chmf (CVE-2026-80219)
- https://github.com/advisories/GHSA-r6x8-cqxr-wwp4 (CVE-2026-77968)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

*Source: hourly offensive-security scan, 2026-09-08 late GitHub `unreviewed` advisory wave. All three `hawtio-operator` advisories tracked in the [source index](../notes/source-index.md).*
