# Rancher Fleet, Kyverno policy SSRF, JWKS cache, QUIC client, and SDK parameter boundary checks

Source: hourly offensive-security scan, 2026-07-01, with a July 5 Kyverno follow-up. Primary entries: GitHub Advisory Database [GHSA-vx8h-4prv-g744](https://github.com/advisories/GHSA-vx8h-4prv-g744) / CVE-2026-41052, [GHSA-4j6x-2764-m8gh](https://github.com/advisories/GHSA-4j6x-2764-m8gh) / CVE-2026-41053, [GHSA-xr65-5cpm-g36x](https://github.com/advisories/GHSA-xr65-5cpm-g36x) / CVE-2026-44935, [GHSA-hx4v-cxpf-vh8m](https://github.com/advisories/GHSA-hx4v-cxpf-vh8m) / CVE-2026-44936, [GHSA-mhc6-2gfq-xx62](https://github.com/advisories/GHSA-mhc6-2gfq-xx62) / CVE-2026-44939, [GHSA-jmf4-m7j9-g72r](https://github.com/advisories/GHSA-jmf4-m7j9-g72r) / CVE-2026-44937, [GHSA-864g-863m-vcvq](https://github.com/advisories/GHSA-864g-863m-vcvq) / CVE-2026-44938, [GHSA-rggm-jjmc-3394](https://github.com/advisories/GHSA-rggm-jjmc-3394) / CVE-2026-4789, [GHSA-g6vg-wj8f-48cj](https://github.com/advisories/GHSA-g6vg-wj8f-48cj) / CVE-2026-49998, [GHSA-2r8v-p65x-3663](https://github.com/advisories/GHSA-2r8v-p65x-3663) / CVE-2026-49457, and [GHSA-hhx9-57xq-r5rw](https://github.com/advisories/GHSA-hhx9-57xq-r5rw) / CVE-2026-48819.

These advisories are durable because they map to reusable operator workflows: GitOps and admission-policy controllers consuming tenant-controlled declarations into cluster or network authority, multi-tenant Kubernetes dashboards expanding identity and namespace authority, token verifiers caching keys across issuers, protocol clients skipping TLS peer verification, and generated SDK parameter builders treating object keys as trusted structure.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-vx8h-4prv-g744](https://github.com/advisories/GHSA-vx8h-4prv-g744) / CVE-2026-41052 | Rancher Manager project ownership | Project Owner and Cluster Member permissions could mutate namespace Pod Security Admission labels into host-level privilege paths | Test Rancher role matrices with namespace-label and workload-admission effects, not only visible UI permissions. |
| [GHSA-4j6x-2764-m8gh](https://github.com/advisories/GHSA-4j6x-2764-m8gh) / CVE-2026-41053 | Rancher GitHub App auth provider | cached GitHub team data could expand a user into all organization teams | Treat IdP group/team mapping as authorization data; prove with disposable org teams and route-access deltas only. |
| [GHSA-xr65-5cpm-g36x](https://github.com/advisories/GHSA-xr65-5cpm-g36x) / CVE-2026-44935 | Rancher Fleet Helm deployer | unvalidated `valuesFrom` references could read Secrets/ConfigMaps across namespaces on downstream clusters | GitOps bundle specs are cluster-resource selectors; test namespace scoping with synthetic Secrets and never read live service tokens. |
| [GHSA-hx4v-cxpf-vh8m](https://github.com/advisories/GHSA-hx4v-cxpf-vh8m) / CVE-2026-44936 | Rancher Fleet bundle reader | `fleet.yaml` `helm.repo` could redirect Helm BasicAuth to attacker-controlled repository URLs when no allowlist is set | Include GitOps repository-controlled dependency URLs in credential-forwarding reviews with fake tokens and owned endpoints. |
| [GHSA-mhc6-2gfq-xx62](https://github.com/advisories/GHSA-mhc6-2gfq-xx62) / CVE-2026-44939 | Rancher cluster import YAML endpoint | query-controlled `authImage` material could inject YAML into generated cluster-import manifests | Treat generated Kubernetes manifest endpoints as template-injection boundaries; prove with inert manifest fields in labs only. |
| [GHSA-jmf4-m7j9-g72r](https://github.com/advisories/GHSA-jmf4-m7j9-g72r) / CVE-2026-44937 | Rancher Fleet webhook | unauthenticated webhook mode plus unsanitized repository URL regex construction could trigger unintended repository processing | Webhook routes need secret, repository, and path binding tests; evidence should be a harmless reconciliation marker, not cluster resource changes. |
| [GHSA-864g-863m-vcvq](https://github.com/advisories/GHSA-864g-863m-vcvq) / CVE-2026-44938 | Rancher Fleet agent deployer | `namespaceLabels` from `fleet.yaml` or `BundleDeployment` options could override Pod Security Standards labels | Git-pushed label metadata can be a privilege boundary; test only with disposable namespaces and marker workloads. |
| [GHSA-rggm-jjmc-3394](https://github.com/advisories/GHSA-rggm-jjmc-3394) / CVE-2026-4789 | Kyverno `policies.kyverno.io` CEL HTTP library | namespace-scoped policy authors could call unrestricted `http.Get()` / `http.Post()` from the Kyverno admission controller | Admission policies can become cluster-network SSRF gadgets; prove only with canary services, owned callbacks, and synthetic error-message markers. |
| [GHSA-g6vg-wj8f-48cj](https://github.com/advisories/GHSA-g6vg-wj8f-48cj) / CVE-2026-49998 | Centrifugo dynamic JWKS | key cache was keyed only by `kid`, allowing key reuse across allowed issuers | Multi-issuer JWT tests must vary issuer, JWKS endpoint, audience, and `kid` collisions, with disposable keys and claims only. |
| [GHSA-2r8v-p65x-3663](https://github.com/advisories/GHSA-2r8v-p65x-3663) / CVE-2026-49457 | Erlang `quic` / HTTP/3 client | TLS 1.3 server authentication was effectively not enforced | Client-library reviews should include active MITM negative controls: wrong chain, wrong hostname, and invalid `CertificateVerify` signatures. |
| [GHSA-hhx9-57xq-r5rw](https://github.com/advisories/GHSA-hhx9-57xq-r5rw) / CVE-2026-48819 | `@hey-api/openapi-ts` generated SDK params | `$query___proto__`-style keys could alter generated parameter object prototypes | Generated API clients need object-key fuzzing for path/query/header/body builders; evidence should be local object-shape changes, not live API abuse. |

## Operator triage

1. **Map who controls the declarative input.** In Rancher/Fleet/Kyverno-style controllers, the important inputs are project roles, GitHub teams, `GitRepo`, `fleet.yaml`, Helm values references, webhook requests, cluster-import query parameters, namespace labels, and namespaced admission-policy bodies.
2. **Separate GitOps reconciliation from direct cluster access.** A user may lack direct Kubernetes RBAC to read a Secret or modify namespace labels but still influence a controller that performs those actions.
3. **Treat controller egress as a separate trust boundary.** A namespace-scoped policy author may not have Pod exec or Service read permissions, but the admission controller may have routable egress to sibling namespaces, cluster services, or metadata endpoints.
4. **Use fake credentials and owned endpoints.** Helm repository BasicAuth, Kyverno SSRF callbacks, JWKS documents, QUIC server certificates, and generated SDK request parameters can all be proven without real tokens or production services.
5. **Record negative controls.** Show expected denial for direct namespace access, direct Secret read, direct Service fetch, wrong issuer, wrong TLS certificate, or sanitized parameter keys before demonstrating the alternate path.
6. **Skip availability-only siblings.** The same scan reviewed a Mailpit sibling-endpoint memory-exhaustion advisory but did not promote it because it adds no non-availability operator workflow.

## Replayable validation boundaries

### Rancher/Fleet GitOps and namespace-control harness

- Preconditions: isolated Rancher/Fleet lab, disposable downstream cluster, no production kubeconfigs, two test users/teams, and synthetic namespaces, Secrets, ConfigMaps, and workloads.
- Build a matrix for Project Owner, Cluster Member, GitHub team membership, Git push access, webhook access, and Fleet controller service-account reach.
- For `valuesFrom`, seed a synthetic Secret/ConfigMap in a sibling namespace and verify whether a tenant-controlled `Bundle` or `HelmOp` can reference it. Positive evidence is only marker value presence in rendered manifests or controller logs.
- For Helm repo credentials, configure fake BasicAuth and an owned repository URL; prove whether the owned endpoint receives fake credentials when `fleet.yaml` changes `helm.repo`.
- For namespace-label paths, test only disposable namespaces and marker workloads. Capture label diff, admission decision, and fixed-version rejection.
- For generated import YAML, inject only inert YAML fields or annotations that write a visible canary into the generated manifest; do not deploy production import manifests or run privileged containers.

### Webhook and identity-provider binding checks

- For Fleet webhooks, compare secret-protected and secretless configurations with repository URL/path variations. Positive evidence is unintended reconciliation of a marker repo or path.
- For Rancher GitHub App authentication, create a disposable GitHub organization or mock provider with two teams and two users. Validate Rancher route/project access for actual team membership versus expanded cached memberships.
- Do not trigger production repository syncs, cluster deployments, or real organization membership changes.

### Kyverno CEL HTTP egress harness

- Preconditions: isolated Kubernetes lab, Kyverno version in scope, `policies.kyverno.io` CRDs enabled, one low-privilege user allowed to create namespaced policies, and explicit approval to test controller egress.
- Seed a same-namespace canary Service, a sibling-namespace canary Service, and an owned external callback endpoint. If metadata-service behavior is in scope, use an explicit mock metadata endpoint inside the lab instead of cloud metadata.
- Create only inert CEL policy expressions that call `http.Get()` or `http.Post()` against canary URLs and reflect a marker value in the admission result or policy error path. Do not request real Secrets, service-account tokens, kubelet endpoints, cloud metadata, or internal production services.
- Capture a decision table: direct low-privilege user access to each target, Kyverno controller egress result, namespace of the policy object, URL requested, marker received, and patched-version or configured-deny result.
- Useful positive evidence is a marker callback or synthetic response body crossing from a namespaced policy into the admission controller's network context.

### Multi-issuer JWKS cache collision harness

- Configure a lab Centrifugo instance with at least two allowed issuers and disposable JWKS endpoints.
- Generate tokens for issuer A and issuer B using controlled keys that intentionally share a `kid` value.
- Exercise issuer A first to populate the cache, then issuer B with claims signed by the wrong issuer's key. Positive evidence is authentication or authorization using the cached cross-issuer key.
- Evidence should include issuer, audience, JWKS endpoint, `kid`, and accepted/denied decision tables with all tokens redacted.

### QUIC/HTTP/3 TLS client verification harness

- Use a lab `quic` client and a controlled QUIC/HTTP/3 server. Do not intercept production traffic.
- Present three negative controls: self-signed untrusted certificate, valid chain for the wrong hostname, and a handshake with invalid certificate proof where tooling allows it.
- Positive evidence is the client completing the handshake or sending application data when server authentication should fail.
- Record library version, `verify` settings, SNI/hostname, certificate subject/SAN, and patched-version refusal.

### Generated SDK parameter object-key fuzzing

- Generate a disposable SDK with `@hey-api/openapi-ts`, or call the generated `buildClientParams` helper directly in a local harness.
- Supply normal `$query_`, `$headers_`, `$path_`, and `$body_` keys, then keys such as `$query___proto__` or nested unknown slot keys.
- Positive evidence is prototype or object-shape mutation in the returned params object, paired with fixed-version rejection or inert own-property handling.
- Do not aim generated requests at production APIs; the useful proof is local builder behavior and downstream request-shape confusion.

## Reporting notes

- Lead with the exact boundary: **Project Owner to PSA label mutation**, **GitHub App team-cache expansion**, **Fleet `valuesFrom` to cross-namespace Secret**, **Fleet Helm repo URL to credential forwarding**, **cluster-import query to YAML injection**, **secretless webhook to reconciliation trigger**, **namespaceLabels to PSS downgrade**, **Kyverno namespaced policy to admission-controller SSRF**, **JWKS `kid` cache to cross-issuer token acceptance**, **QUIC client to unauthenticated TLS peer**, or **SDK parameter key to prototype substitution**.
- Keep evidence synthetic: disposable namespaces, fake Helm credentials, marker Secrets, Kyverno canary Services, owned callbacks, lab GitHub teams, disposable JWT keys, lab QUIC certificates, and local SDK object traces.
- Do not read Kubernetes service-account tokens, deploy privileged production workloads, harvest Helm registry credentials, collect live JWTs, query real cloud metadata, intercept user traffic, or mutate production Rancher/Kyverno clusters.
