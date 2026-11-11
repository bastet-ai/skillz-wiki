# Cluster control-plane secret and impersonation boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where Kubernetes/GitOps control planes and container agents crossed secret, identity, and filesystem boundaries.

## Advisories covered

- **Argo CD ServerSideDiff Kubernetes Secret extraction**, [GHSA-3v3m-wc6v-x4x3](https://github.com/advisories/GHSA-3v3m-wc6v-x4x3): diff/render functionality can become a read path for Secrets when it runs with broader cluster privileges than the requesting principal.
- **Fleet Helm impersonation bypass**, [GHSA-765j-qfrp-hm3j](https://github.com/advisories/GHSA-765j-qfrp-hm3j): template rendering retained a `cluster-admin` REST client despite intended impersonation boundaries.
- **Rancher Extensions path traversal**, [GHSA-5v3h-x4wf-5c35](https://github.com/advisories/GHSA-5v3h-x4wf-5c35) / CVE-2026-25705: a malicious `UIPlugin` can abuse `compressedEndpoint` path traversal and Cluster Repo icon paths unless Rancher forces all resolved files to stay inside the extension cache/repository root.
- **Amazon ECS Container Agent for Windows information disclosure**, [GHSA-fc67-c4hg-q653](https://github.com/advisories/GHSA-fc67-c4hg-q653): host/container metadata boundaries can leak sensitive operational data when agent paths are exposed too broadly.

## Why this is durable

GitOps and container control planes are high-trust automation engines. Any helper that renders templates, computes diffs, loads extensions, or exposes agent state must execute as the requester, not as the operator's most privileged service account.

## Immediate triage

1. Patch Argo CD, Fleet, Rancher, and ECS Windows agents where present; prioritize shared clusters and internet-reachable management planes.
2. Review Argo CD ServerSideDiff usage and disable or restrict it for untrusted projects until patched.
3. Hunt for reads of Kubernetes Secret objects through diff/render endpoints and audit `impersonate` headers or service-account usage during Helm rendering.
4. Patch Rancher extension-capable managers to fixed trains: 2.14.1, 2.13.5, 2.12.9, or 2.11.13. Treat extension deployment rights as admin-equivalent until patched.
5. Inventory Rancher `UIPlugin` and Cluster Repo sources; remove unknown, writable, tenant-supplied, or non-vendor extension roots, and review extension install history for writes outside the cache/repository directory.
6. On Windows ECS hosts, review agent exposure, local access paths, and logs for unexpected metadata reads.

## Durable controls

- Enforce requester-scoped authorization at every render, diff, dry-run, and extension-read boundary.
- Use separate low-privilege service accounts for template/diff helpers; never reuse reconciler `cluster-admin` credentials for preview operations.
- Canonicalize extension file paths after decoding and symlink resolution, reject `../` before extraction, and verify `compressedEndpoint` artifacts and repo icons remain under immutable package/cache roots.
- Treat host agents as privileged daemons: bind locally, limit ACLs, redact metadata, and monitor unexpected local callers.

## August 10 follow-up: bind cross-hub messages and migration material to the authenticated hub

Two unreviewed GitHub records for Red Hat multicluster-global-hub add a reusable multi-cluster authority workflow:

- [GHSA-q5c4-r3vh-f379 / CVE-2026-71576](https://github.com/advisories/GHSA-q5c4-r3vh-f379) reports that the manager accepts a self-asserted CloudEvent source identity on Kafka status topics after authenticating only the managed hub's Kafka client certificate. A compromised hub can therefore attribute compliance, inventory, or health messages to another hub and influence that hub's database rows.
- [GHSA-v7q5-q7p3-9vjm / CVE-2026-71577](https://github.com/advisories/GHSA-v7q5-q7p3-9vjm) reports that `ManagedClusterMigration` grants all managed hubs read access to a shared communication topic containing bootstrap kubeconfigs intended for particular hubs.

Treat these records as leads until the Red Hat primary advisory, exact image digest, topic ACLs, and observed behavior confirm them. The first path requires authority already obtained on one managed hub. The second requires an active migration and access to the relevant shared topic. Neither is an unauthenticated Kubernetes API path.

!!! warning "Authorized validation only"
    Use a disposable multi-cluster lab with two synthetic hubs, fake cluster IDs, marker-only status rows, a local Kafka fixture, and bootstrap tokens that authorize no Kubernetes action. Patch database mutation, topic delivery, and token-use sinks to record and deny. Never consume production status topics, collect kubeconfigs, replay service-account tokens, alter real compliance/inventory data, or migrate operational clusters.

### CloudEvent source-to-certificate binding matrix

Create two lab identities, `hub-a` and `hub-b`, with separate Kafka client certificates. Publish inert status events through the same code path used by the manager and capture the authenticated certificate identity, topic, key, event `source`, cluster ID, selected database row, and mutation decision.

| Kafka principal | Event source | Row selected | Required result |
| --- | --- | --- | --- |
| `hub-a` | `hub-a` | `hub-a` marker | normal control |
| `hub-a` | `hub-b` | `hub-b` marker | reject before database mutation |
| `hub-a` | missing source | none | reject |
| `hub-a` | case, encoding, or path-like `hub-a` variant | none | reject unless canonical identity is exactly defined |
| `hub-b` | `hub-b` | `hub-b` marker | normal control |

A bounded positive is **authenticated Kafka principal for hub A -> event claims hub B -> manager selects hub B state -> denied database sink records the foreign row**. Do not falsify or delete a real row. Distinguish control of event content from successful cross-hub attribution; an accepted message is not enough unless the foreign object selected at the final sink is proven.

### Migration-topic audience matrix

Seed the migration controller with a fake kubeconfig-shaped object whose token is a random, nonfunctional marker. Instrument authorization and message delivery, then compare:

| Subscriber | Migration target | Expected visibility |
| --- | --- | --- |
| source hub | source-to-destination migration | only protocol fields required by its role |
| destination hub | source-to-destination migration | its synthetic bootstrap marker through the intended handoff |
| unrelated hub | source-to-destination migration | no marker and no message body |
| same unrelated hub after migration completion | none | no retained marker or topic access |

Capture topic ACLs before, during, and after migration; the authenticated subscriber identity; message key and audience fields; delivery decision; and cleanup/revocation state. A positive is **unrelated hub principal -> shared migration topic -> broker or consumer delivers another hub's synthetic bootstrap marker**. Stop at delivery metadata or a patched body recorder. Do not use the marker against an API server, and report topic-read exposure separately from any cluster access claim.

Test retries, concurrent migrations, controller restart, and failed migration cleanup. Temporary broad grants that survive an error path are a distinct finding even if the happy path revokes them.

### Reporting checklist

- exact multicluster-global-hub version and image digest;
- prerequisite authority on the compromised managed hub;
- Kafka certificate subject/principal, topic, event source, and cluster ID;
- claimed identity versus object selected at the denied database sink;
- migration source, destination, unrelated subscriber, and topic ACL timeline;
- synthetic marker only, with proof that it authorizes no action;
- affected-versus-corrected behavior and negative controls;
- separate conclusions for message attribution, message visibility, and credential usability.

## August 20 follow-up: bind cross-cluster objects, endpoints, and controller credentials to the authenticated cluster

Five GitHub records for Red Hat Advanced Cluster Management components add the spoke-to-broker/peer authority surface of federated Kubernetes. The shared pattern: an object created inside one cluster (spoke) selects a destination, namespace, network range, or credential, that is derived from attacker-controlled fields rather than from the authenticated cluster's identity.

- [GHSA-264j-8377-4hmm / CVE-2026-66788](https://github.com/advisories/GHSA-264j-8377-4hmm) (critical, Lighthouse): the destination namespace for resource injection is derived from an attacker-controlled label or annotation on the broker object, letting a compromised spoke inject EndpointSlices and ServiceImports into any namespace on peer clusters, including `kube-system` and `openshift-*`.
- [GHSA-7fh9-j94v-w42j / CVE-2026-66787](https://github.com/advisories/GHSA-7fh9-j94v-w42j) (high, Lighthouse): advertised IP addresses in EndpointSlice objects are insufficiently validated, so a spoke can make other clusters' lighthouse DNS redirect service traffic to attacker-chosen endpoints (transparent MITM of cross-cluster service communication).
- [GHSA-37mq-728j-5q43 / CVE-2026-66785](https://github.com/advisories/GHSA-37mq-728j-5q43) (critical, Submariner): a spoke can publish a network endpoint declaring arbitrary subnets; peer-cluster traffic destined for those ranges is rerouted through the attacker's tunnel.
- [GHSA-gf3r-gm67-jgrv / CVE-2026-67567](https://github.com/advisories/GHSA-gf3r-gm67-jgrv) (critical, multicloud-operators-subscription): a tenant that can create HelmRelease CRs gets the HelmRelease controller to process chart templates with its elevated ServiceAccount and insufficient validation, enabling arbitrary resource deployment cluster-wide.
- [GHSA-rf6j-x765-j4p2 / CVE-2026-73137](https://github.com/advisories/GHSA-rf6j-x765-j4p2) (high, multicloud-operators-subscription): manipulating `secretRef.Namespace` lets `GetSecret()` fetch credentials from any namespace, which are then sent to an attacker-controlled Helm repository.

!!! warning "Authorized lab validation only"
    Use a two-namespace marker-only cluster pair with fake hub/spoke identities, synthetic charts, and fake nonfunctional kubeconfigs. Patch deserializer, Secret-read, token-use, DNS resolution, and tunnel-forward sinks to record and deny. Never deploy real workloads to system namespaces, exfiltrate real Secrets, point DNS or traffic at operational services, or use bootstrap material against a real API server.

### Authority map

| Boundary | Advisory signal | Safe proof target |
| --- | --- | --- |
| broker-object label/annotation to injection namespace | namespace derived from spoke-controlled metadata | denied create sink records an injection target inside `kube-system` for a synthetic object |
| EndpointSlice IPs to cross-cluster DNS answer | advertised IPs not validated against spoke ownership | lab DNS recorder answers with the attacker-chosen marker IP for a canary service name |
| published endpoint subnets to peer traffic routing | arbitrary subnet declaration accepted | tunnel-forward recorder captures a canary packet for an attacker-declared range |
| HelmRelease CR to controller service-account | tenant CR processed with elevated SA and unvalidated templates | patched chart renderer records a canary resource outside the tenant namespace |
| `secretRef.Namespace` to cross-namespace Secret read | `GetSecret()` honors caller-chosen namespace | denied Secret sink records a marker Secret in a namespace the tenant cannot otherwise read |

### Workflow

1. Build the lab federated pair: one "broker/hub" cluster and one "spoke" cluster, both disposable, with the affected ACM components installed. Give the spoke exactly the minimum CR creation rights the advisory describes (broker object write, EndpointSlice publish, or HelmRelease create) and no more.
2. For the namespace-derivation path, create broker objects whose labels/annotations select the canary marker namespace, the system namespace, and an unrelated namespace. Instrument the peer-side creation sink to log (object kind, target namespace, source cluster ID) and deny all creation. A positive is **spoke-owned object -> peer sink records target namespace outside the spoke's granted set**.
3. For the DNS/MITM path, publish EndpointSlices advertising owned-lab marker IPs for a canary service name, then resolve the service from a peer cluster against a patched DNS responder that only records queries and answers. Capture which IP the resolver would return. Do not redirect real service traffic.
4. For the Submariner path, publish an endpoint declaring an attacker-chosen subnet containing an owned-lab IP; patch the peer tunnel-forward path to record what would be sent where. A positive is the forward decision selecting the attacker-declared range.
5. For the HelmRelease paths, use a synthetic chart whose templates reference a canary Secret in a namespace the tenant has no right to read. Patch `GetSecret()` and the renderer to log the requested namespace/name and return a marker; patch the Helm repository client to record URLs and deny egress. A positive is **tenant HelmRelease -> cross-namespace Secret marker selected** or **repository URL = attacker-controlled endpoint**.
6. Repeat on corrected components and require: namespace fixed to the authenticated cluster's binding, IP/subnet validation against the spoke's declared ranges, controller execution as the requesting tenant's identity, and `secretRef` namespace locked to the HelmRelease's own namespace.

Report each edge as a separate finding with **authenticated spoke identity -> attacker-controlled field -> denied sink decision**. Do not infer full cluster compromise from a single object injection, and do not combine the five records into one chain unless every transition is observed on the same lab topology.

## August 26 follow-up: MCE hub controllers derive cross-cluster authority from labels, names, and URL paths

Seven GitHub records for OpenShift Multicluster Engine (MCE) add the same hub/spoke trust-boundary family on a second control plane. The shared pattern: hub-side controllers and routes select privileged destinations from **caller-controlled labels, resource naming conventions, and URL path segments** instead of the authenticated cluster's identity.

- [GHSA-9855-9cch-x8mw / CVE-2026-66794](https://github.com/advisories/GHSA-9855-9cch-x8mw) (critical, `cluster-proxy-addon`): the user-facing route accepts unauthenticated requests and lets path-segment manipulation proxy to arbitrary services in any managed cluster, an authentication and authorization bypass with cross-cluster service reach.
- [GHSA-w9c6-w29v-4vp6 / CVE-2026-66795](https://github.com/advisories/GHSA-w9c6-w29v-4vp6) (critical, `managedcluster-import-controller`): CSR auto-approval does not inspect the signer name or decode the PEM-encoded x509 CSR, so a privileged service account on a spoke can submit a malicious CSR and obtain hub administrative credentials.
- [GHSA-h2w9-5qx3-frqq / CVE-2026-73269](https://github.com/advisories/GHSA-h2w9-5qx3-frqq) (critical, `cluster-curator-controller`): a ClusterCurator resource matching a specific naming convention triggers creation of a cluster-scoped `ClusterRoleBinding`, escalating a namespace-local user to cluster-wide control.
- [GHSA-6c6p-j4gf-mj2c / CVE-2026-73268](https://github.com/advisories/GHSA-6c6p-j4gf-mj2c) (critical, `cluster-curator-controller`): `CreateJob()` does not validate `spec.install.overrideJob` raw extension input, so a tenant with ClusterCurator create/update rights can inject an arbitrary Job spec that runs with the controller's elevated privileges.
- [GHSA-xp42-v53j-r9gh / CVE-2026-73266](https://github.com/advisories/GHSA-xp42-v53j-r9gh) (high, `clusterclaims-controller`): manipulating ClusterClaim labels forces a cluster to join another tenant's `ManagedClusterSet`, enabling policy and workload injection into other tenants' clusters.
- [GHSA-3vwx-g7ch-f3wg / CVE-2026-19130](https://github.com/advisories/GHSA-3vwx-g7ch-f3wg) (medium, `provider-credential-controller`): manipulating `copiedFrom` labels on a hub, with knowledge of a prior credential value, intercepts newly rotated provider credentials.
- [GHSA-77qj-pc4h-hxwh / CVE-2026-75569](https://github.com/advisories/GHSA-77qj-pc4h-hxwh) (high, `mce-operator-bundle`): the build process fetches and executes scripts from a remote repository without commit pinning or signature verification, a build-time script-supply boundary for anyone trusting MCE operator bundles.

Treat the proxy-addon record as the most operationally interesting one: it is the only unauthenticated entry point and it turns the MCE route into a user-directed cross-cluster forwarder, which is an SSRF-shaped primitive at cluster scale. The CSR, naming-convention, overrideJob, and label records each require authority already present on a spoke or hub tenant.

!!! warning "Authorized lab validation only"
    Use a two-cluster (hub + spoke) disposable MCE lab with fake managed clusters, synthetic ClusterCurator/ClusterClaim objects, fake CSR material, and fake provider credentials. Patch Job creation, ClusterRoleBinding creation, credential rotation, and proxy-forward sinks to record and deny. Never obtain or replay real hub admin credentials, point the proxy at operational clusters or internal services, rotate or read live provider credentials, or install real workloads into managed clusters.

### Authority map

| Boundary | Advisory signal | Safe proof target |
| --- | --- | --- |
| proxy route path segments to managed-cluster services | unauthenticated route forwards to arbitrary cross-cluster endpoints | patched forwarder records a canary destination in an unrelated managed cluster from a no-identity request |
| spoke CSR to hub auto-approval | signer name unvalidated, PEM not decoded | denied signer/serializer sink records a canary CSR with a foreign signer that the auto-approver would accept |
| ClusterCurator name to cluster-scoped ClusterRoleBinding | naming convention triggers cluster-scoped binding | denied create sink records a `cluster-admin`-shaped binding request for a synthetic curator name |
| ClusterCurator `overrideJob` to controller-privileged Job | raw extension unvalidated at `CreateJob()` | patched Job creator records an out-of-schedule, out-of-scope Job spec under the controller service account |
| ClusterClaim labels to foreign ManagedClusterSet | labels steer cluster join decision | denied cluster-set mutation sink records a join request into another tenant's set |
| `copiedFrom` labels to rotated provider credential | label confusion selects the wrong credential copy | denied credential-rotation sink records the canary credential selected for a foreign label |
| operator-bundle build script fetch | unverified remote script execution at build time | pinned/unsigned script fixtures in a throwaway build workspace; diff executed-vs-pinned script, no live remote execution |

### Workflow

1. Build the lab MCE topology: one hub cluster and one spoke cluster, both disposable, with the affected MCE controllers deployed at the vulnerable versions. Give the spoke/tenant exactly the minimum rights the advisory names (proxy route reach, privileged SA on the spoke, ClusterCurator or ClusterClaim create) and nothing more.
2. For the proxy route, send requests with path segments that name a canary service in the spoke, in an unrelated managed cluster, and in a system namespace. Patch the forwarder to record (source identity, selected cluster, selected service) and deny all egress. A positive is **unauthenticated request -> forwarder records a cross-cluster canary destination**. Keep probes to the route and canary services; do not scan managed clusters.
3. For the CSR path, craft a lab CSR with a canary signer name that the auto-approver is reported to miss, plus a negative control with the correct signer. Patch the signer-check and PEM-decode points to record and deny. A positive is **foreign-signer canary CSR -> auto-approval decision records accept**. Do not complete signing or mint hub credentials.
4. For the curator paths, create synthetic ClusterCurator resources: one matching the trigger naming convention, one not, and one carrying an `overrideJob` extension with an inert canary spec (image = nonfunctional marker, command = no-op). Patch the binding-creation and Job-creation sinks to record and deny. A positive is **trigger name -> cluster-scoped binding request recorded** or **overrideJob extension -> Job creation recorded under the controller SA**.
5. For the claims path, set ClusterClaim labels that name a second tenant's ManagedClusterSet in the two-tenant lab; patch the cluster-set join mutation to record and deny. A positive is **tenant-A claim labels -> join decision recorded against tenant-B set**.
6. For the credential path, use two fake provider credential values and `copiedFrom` labels selecting the other tenant's value; patch the rotation-copy sink to record which canary value would be copied. A positive is **foreign `copiedFrom` label -> canary credential B selected for tenant A**. Never capture or replay a real rotated credential.
7. For the operator bundle, run a throwaway build against pinned and unpinned script fixtures and record which script bytes execute. Frame it as a build-integrity check (commit pin / signature), not as remote code execution.

Report each edge separately as **caller identity (or absence) -> attacker-controlled field -> denied sink decision**, and state the prerequisite authority for every record except the proxy route. Do not claim hub compromise from the label/CSR records without observing the final sink decision in the same lab topology.
