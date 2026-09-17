---
title: AI feature-store and cluster control-plane tenant boundaries
---

# AI feature-store and cluster control-plane tenant boundaries

An August 10 GitHub advisory wave exposes a reusable AI-platform attack-path pattern: feature repositories, UDFs, workflow specifications, service-account selectors, Secret references, gateway identity headers, and database connection options cross from tenant-controlled objects into higher-trust feature servers or Kubernetes operators. Test every transition at its final deserializer, pod builder, Secret client, token minter, database connector, or backend route rather than assuming namespace RBAC or an outer gateway covers the inner service.

Primary records:

- Feast missing-auth default and exposed service APIs: [GHSA-2xfw-wg76-86w9 / CVE-2026-18941](https://github.com/advisories/GHSA-2xfw-wg76-86w9);
- Feast `dill` UDF deserialization: [GHSA-gg2p-37pv-v7fq / CVE-2026-18948](https://github.com/advisories/GHSA-gg2p-37pv-v7fq);
- Feast Operator feature-repository execution: [GHSA-55p8-2553-ch47 / CVE-2026-18942](https://github.com/advisories/GHSA-55p8-2553-ch47);
- Feast materialization authorization when `feature_views` is omitted: [GHSA-mvxh-8c54-7fwx / CVE-2026-18947](https://github.com/advisories/GHSA-mvxh-8c54-7fwx);
- OpenShift AI MaaS identity-header trust: [GHSA-6vf6-rmwh-84qg / CVE-2026-14450](https://github.com/advisories/GHSA-6vf6-rmwh-84qg);
- `odh-model-controller` cross-namespace Secret selector: [GHSA-w7qg-jg9c-w9mm / CVE-2026-16456](https://github.com/advisories/GHSA-w7qg-jg9c-w9mm);
- Data Science Pipelines Operator MySQL DSN option injection: [GHSA-g6qh-932v-chpq / CVE-2026-18617](https://github.com/advisories/GHSA-g6qh-932v-chpq);
- Data Science Pipelines V1 workflow-policy bypass: [GHSA-6wxg-hpw6-m2x7 / CVE-2026-18621](https://github.com/advisories/GHSA-6wxg-hpw6-m2x7);
- Data Science Pipelines caller-selected ServiceAccount: [GHSA-g68c-wmxr-x3rh / CVE-2026-18620](https://github.com/advisories/GHSA-g68c-wmxr-x3rh);
- TrustyAI LMEvalJob sidecar-policy bypass: [GHSA-qw34-v3jw-3crv / CVE-2026-15467](https://github.com/advisories/GHSA-qw34-v3jw-3crv);
- TrustyAI backend reachable behind the intended gateway: [GHSA-7rjm-5cpg-vwpq / CVE-2026-15581](https://github.com/advisories/GHSA-7rjm-5cpg-vwpq); and
- OpenShift AI MaaS gateway traffic-interception authority: [GHSA-335x-vvmj-55qx / CVE-2026-13717](https://github.com/advisories/GHSA-335x-vvmj-55qx).
- OpenShift AI dashboard internal-listener token impersonation: [GHSA-h5q4-fjj4-4792 / CVE-2026-16745](https://github.com/advisories/GHSA-h5q4-fjj4-4792).
- OpenShift Console webhook-helper response-reflecting SSRF: [GHSA-c4v8-c9cj-xrmr / CVE-2026-50236](https://github.com/advisories/GHSA-c4v8-c9cj-xrmr); and
- OpenShift Console tenant-supplied Helm repository fetch and catalog trust: [GHSA-5mvj-m7fw-m49w / CVE-2026-50237](https://github.com/advisories/GHSA-5mvj-m7fw-m49w).

These records were unreviewed when scanned and do not all identify affected or corrected package versions. Confirm the exact OpenShift AI distribution, operator image digest, API generation, enabled component, route topology, authentication mode, and vendor fix before reporting. Do not infer internet reachability, cluster-admin impact, or code execution from a source record alone.

!!! warning "Disposable multi-tenant clusters and denied sinks only"
    Use an isolated cluster with namespaces A and B, fake service accounts and Secrets, marker-only feature data, inert UDF/repository fixtures, mocked databases, no-content backend Services, and patched deserialization, process, file, token, Secret, pod-create, workflow, and database sinks. Never deserialize unknown code, mint a real token, read a Kubernetes Secret, enable MySQL `LOCAL INFILE` against a live server, create a privileged pod, intercept prompts or keys, mutate retained features, or submit production workflows.

## Boundary map

| Surface | Tenant-controlled authority | Higher-trust sink | Bounded positive |
| --- | --- | --- | --- |
| Feast service deployment | network request reaches feature, registry, or offline API | authentication and service operation | anonymous canary request reaches a no-op operation recorder in a configuration expected to require identity |
| Feast UDF | serialized UDF is stored in registry state | `dill` load/reconstruction | inert canary type reaches a denied deserializer before authorization |
| Feast repository | tenant supplies feature-repository content | operator automation imports/runs repository under its service account | inert module marker reaches a denied import/process sink under operator identity |
| Feast materialize | request omits or changes `feature_views` | cross-tenant materialization planner | no-op planner receives tenant B views under A or no identity |
| MaaS API | pod can send identity-looking headers | API-key operation or token minting | forged A/B canary headers reach a denied B-scoped operation without authenticated peer identity |
| Model controller | custom resource names a Secret namespace | controller `Secrets.get` | B's synthetic Secret identity reaches a denied read under A's object |
| DSPO database options | `customExtraParams` extends a MySQL DSN | database client capability negotiation | forbidden option reaches a mocked connector while fixed options remain authoritative |
| DSP V1 workflow | tenant submits a workflow through an alternate API generation | pod security policy and pod creation | forbidden synthetic security field reaches a denied pod-create sink only through V1 |
| DSP run | caller supplies a ServiceAccount | workload identity and pod builder | B's synthetic service account reaches a denied pod spec under A |
| LMEvalJob | caller adds sidecar fields | controller-generated pod and remote-code setting | forbidden sidecar/capability reaches denied pod creation |
| TrustyAI backend | cluster pod reaches Service directly | backend CRUD API | unauthenticated pod reaches a no-op backend recorder while gateway path denies it |
| MaaS Gateway | low-privilege object can affect gateway placement/config | model request and response stream | synthetic request marker reaches an untrusted canary gateway recorder without exposing content |
| Dashboard internal listener | cluster pod supplies an arbitrary access-token value | dashboard identity and Kubernetes API client | fake token selects synthetic user B at a denied API recorder from pod A |

## 1. Separate Feast network exposure, object authorization, and deserialization

### September 16 follow-up: Feast JWT signature never verified before identity

[GHSA-4rxv-8f9g-9h5w](https://github.com/advisories/GHSA-4rxv-8f9g-9h5w) / CVE-2026-92787: Feast through 0.66.0 **establishes user identity from an unverified JWT** — the signature is never checked — so any caller presenting a token with the right hardcoded claim obtains trusted internal identity and unchecked read/write over all entities, feature views, data sources, and permission policies. This is the strongest identity edge on this page: it subsumes every authorization matrix above, because the gateway's RBAC now gates only callers who bother to be honest.

Operator check on any Feast (or gateway-fronted feature store) deployment with auth supposedly enabled: decode a valid cluster token, copy the payload, re-encode with an **invalid signature** (flip the sig bytes), and call one read-only registry endpoint. Positive: 200 with privileged identity. The forged-token-accepted result is the whole finding; capture the claim set, not tenant data. This is the same "parse-before-verify" identity class as the Sept 16 ZITADEL/Keycloak page and the earlier JWT alg-confusion entries — add it to any IdP-adjacent audit list.

Do not begin with an executable UDF. Build a local Feast deployment containing two projects or tenants, each with random feature-view names and no sensitive source data. Instrument authentication middleware, registry writes, UDF reconstruction, materialization planning, and feature reads independently.

Run this decision matrix against each enabled service:

| Caller | Object | Operation | Secure result |
| --- | --- | --- | --- |
| no identity | public health/version canary | read-only status | allowed only if intentionally public |
| no identity | A registry/UDF marker | create or read | denied before object lookup/deserialization |
| A | A marker | authorized no-op operation | allowed control |
| A | B marker | read, store, load, or materialize | denied by tenant binding |
| A | omitted `feature_views` | materialize recorder | defaults only to A-authorized views or rejects |
| A | inert serialized canary | UDF load | policy checks occur before reconstruction |

Use a custom fake serializer whose reconstruction callback only records a random type name and raises. A bounded UDF positive is **anonymous or insufficiently authorized request -> registry stores/selects the inert UDF -> `dill` reconstruction recorder runs before authorization**. That proves unsafe deserialization reachability without a command, import side effect, environment read, or network callback.

For feature repositories, patch Python import, subprocess, package installation, and cloud-client construction. Submit an ordinary repository as the control and a second repository containing only a module-level inert marker that the import recorder recognizes but never executes. Record repository owner, revision, checkout path, operator service account, generated job/pod, effective environment, and first loader sink. Do not place credentials in the environment merely to demonstrate they could be read.

Treat missing authentication, cross-tenant object selection, deserialization, and elevated operator execution as separate edges. Combine them into a chain only when one authorized lab deployment proves every edge with the same configuration and denied final sinks.

## 2. Require cryptographic peer identity before trusting gateway headers

`X-MaaS-Username` and `X-MaaS-Group` are safe only when an authenticated, authorized gateway overwrites them and the backend rejects every alternate network path. A deny list of external clients is not equivalent to authenticating the immediate peer.

Create namespaces A and B, a low-privilege pod in A, and fake MaaS users/groups with no real provider credentials. Replace API-key revoke, configuration read, and ServiceAccount token creation with no-op recorders. Compare:

- the documented gateway route with gateway-generated identity headers;
- direct backend Service and pod-IP routes with no headers;
- direct routes with caller-supplied identity headers;
- duplicate, mixed-case, comma-joined, empty, and conflicting identity headers;
- gateway route where the client also supplies the same header names; and
- fixed topology where backend ingress is limited to the authenticated gateway identity.

Capture TCP peer, mTLS or workload identity, ingress policy, original client headers, gateway overwrite/strip behavior, backend-visible headers, selected tenant, and first operation sink. A bounded positive is **ordinary A pod -> direct backend route -> forged B identity header survives -> B-scoped no-op recorder is selected**. Never allow a real ServiceAccount token to be minted or a provider key to be returned.

Apply the same topology test to TrustyAI: gateway success is not evidence that its backend Service is protected. Test direct Service reachability with harmless status and no-op CRUD recorders only; do not read, alter, inject, or delete retained monitoring data.

### August 11 follow-up: bind dashboard identity to the authenticated listener

The `odh-dashboard` record adds a listener-specific control: an authenticated external route can coexist with an incorrectly bound internal endpoint that accepts a caller-supplied access token and constructs a Kubernetes client under the asserted identity. Do not begin by calling the live Kubernetes API. In a two-namespace lab, replace token review, user-info lookup, and Kubernetes client methods with denied recorders, then compare:

- documented ingress versus every pod-reachable dashboard listener and port;
- no token, invalid random token, a valid synthetic A token, and an arbitrary B-looking marker;
- `Authorization`, cookie, query, WebSocket/bootstrap, and any product-specific token channel;
- loopback, pod IP, Service, and ingress peers; and
- affected and corrected image digests under the same network policy.

Capture TCP peer, listener address, route middleware, token source and normalization, whether cryptographic validation ran, selected user, generated client identity, and the first denied Kubernetes API operation. A bounded positive is **ordinary pod A -> internal dashboard listener -> arbitrary marker accepted as user B -> denied Kubernetes client records B authority**. A reachable listener or a changed error body alone is insufficient. Never submit a real bearer token, list cluster objects, create a workload, or read another namespace's data.

## 3. Bind controller references to the originating namespace

### August 11 follow-up: console fetch authority and Helm catalog provenance

Run a disposable cluster with an ordinary namespace user, an owned external callback, and a synthetic cluster-local no-content Service. Patch the console HTTP connector and response relay. For webhook helpers, vary raw/encoded path components, redirects, resolved peers, and response types; record initial URL, all resolutions, final peer, selected route, response-byte count, and denied relay. A bounded positive is **tenant URL -> console-pod final peer is the synthetic internal Service -> denied relay would return its marker**. Never target metadata, Kubernetes APIs, registries, or operational Services.

For `ProjectHelmChartRepository`, use an owned repository serving an inert chart and unique metadata marker. Patch fetch, catalog persistence, and install/render/apply sinks. Trace **namespace object -> console fetch -> catalog/UI representation -> administrator selection -> denied chart operation**. Separate SSRF from supply-chain impact: a callback proves fetch authority; privilege escalation requires proof that attacker-controlled catalog identity/content survives into an admin-mediated install decision. Do not install a chart, create a workload, read credentials, or capture administrator tokens.

For `odh-model-controller`, seed one synthetic Secret per namespace. Each Secret should contain only a random marker key name; patch the Kubernetes client so `get Secret` records namespace/name and returns no value. Submit the same custom resource while varying omitted namespace, own namespace, foreign namespace, nonexistent namespace, malformed namespace, and a namespace alias if the API supports one.

The secure controller should derive the namespace from the originating object or require an explicit, authorized cross-namespace grant. A positive is **namespace A object -> caller-controlled namespace B -> controller identity attempts `Secrets.get(B, marker)` at the denied client**. Do not return Secret bytes. Confirm that create and update admission paths enforce the same rule and that reconciliation of pre-existing objects does not bypass a newly added webhook.

For DSP run creation, repeat the pattern with service accounts. Patch pod creation, then vary omitted, own, foreign, privileged-looking-but-synthetic, nonexistent, and deleted ServiceAccount selectors. Record route generation, authenticated user, run namespace, requested account, account actually inserted into the pod, authorization decision, and denied create call. A reportable result is the unexpected pod spec, not a running pod or token read.

## 4. Trace structured database options to protocol capability

The DSPO record is valuable beyond MySQL: an operator may validate the database host and credential but append tenant-controlled query options that alter the driver's file, TLS, authentication, or local-protocol behavior.

Use a mock MySQL connector and fake DSN. Patch the connector before any socket opens. Compare omitted options, documented harmless options, duplicate keys, key casing, delimiter/encoding variants, and a synthetic forbidden `LOCAL INFILE` capability marker. Record the raw custom field, generated DSN, parsed driver options, duplicate-key precedence, and connector configuration.

A bounded positive is **namespace editor's custom field -> generated operator DSN -> mocked driver receives local-file capability enabled despite the fixed operator policy**. Do not run a server that asks for a file, do not read a service-account token, and do not infer file disclosure merely because the option reaches the connector. If impact must be established, replace the local-file callback with a recorder that returns only the candidate canonical path and always denies the read.

Variant-search every operator field that is concatenated into JDBC/DSN URLs, command arguments, environment variables, object-store endpoints, TLS options, plugin names, or generated configuration.

## 5. Diff API generations and pod-security transforms

Security filters often cover one workflow route but not a legacy or versioned sibling. Build one inert Argo-style workflow and submit byte-equivalent specifications through every enabled DSP API generation and UI path. The workflow must perform no action; patch pod/workflow creation and inspect only the generated object.

Vary one policy-relevant field at a time: service account, host namespace flags, host path, privilege bit, capabilities, runAs user, seccomp, sidecar, init container, volume type, and image pull secret. Use synthetic names and no host mounts or privileged images.

A bounded positive is **same tenant and semantic workflow -> hardened route removes/rejects a field -> alternate V1 route preserves it into the denied pod-create sink**. Record router, API version, conversion/defaulting webhook, admission decisions, final pod spec, and fixed-build result. Do not submit the object to a real scheduler.

Apply the same matrix to TrustyAI `LMEvalJob` sidecars. Test create, update, reconciliation, retry, and clone paths because a create-time admission rule may not constrain a controller-generated sidecar after defaulting or later reconciliation.

## 6. Treat gateway configuration as traffic authority

A user who can create or influence gateway resources may gain authority over traffic well beyond their namespace even without reading Kubernetes Secrets directly. Build two no-content model backends and an owned recorder proxy. Send only random request/response markers; no prompts, API keys, model output, or reusable credentials should exist in the fixture.

Trace:

```text
tenant-controlled Gateway/Route/model-serving object
-> controller watch and namespace selection
-> generated listener and route
-> backend attachment and filter chain
-> request/response path
-> log/export destination
```

Compare an ordinary tenant-local route, a route selecting another namespace, wildcard/shared gateway attachment, listener/filter changes, and status-only fixed controls. A bounded positive is **low-privilege A object -> shared MaaS route attaches to A's canary recorder -> synthetic B traffic marker would traverse that recorder**. Stop at routing configuration and marker presence. Never capture headers, payloads, model requests, access keys, or another tenant's traffic.

## Evidence and reporting checklist

- [ ] Advisory status, product/distribution, image digest, enabled component, API generation, auth mode, and corrected build are explicit.
- [ ] Network reachability, authentication, tenant authorization, deserialization, controller identity, and final runtime sink are separate findings.
- [ ] Feast UDF and repository proofs use inert reconstruction/import recorders and execute no supplied code.
- [ ] MaaS header tests record authenticated peer identity and gateway overwrite behavior; they mint no token and return no key.
- [ ] Dashboard-listener tests use fake tokens and stop at a denied identity/API-client sink.
- [ ] Secret proofs stop at a denied namespace/name lookup and contain no Secret bytes.
- [ ] ServiceAccount and workflow proofs stop before pod creation and never schedule privileged workloads.
- [ ] DSN proofs stop at parsed mock connector options and never request a local file.
- [ ] Gateway interception proofs contain only random no-content markers and no prompts, outputs, or credentials.
- [ ] Findings state the exact tenant-to-controller transition and do not claim cluster-admin or RCE unless every edge is independently proven in the authorized lab.
