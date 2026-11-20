---
title: Route, trusted-context, and controller-authority boundaries
---

# Route, trusted-context, and controller-authority boundaries

Thirteen records expose a reusable operator pattern: an early policy decision validates one representation or principal, while a later router, controller, object resolver, filesystem helper, or process sink acts on something stronger. The durable workflow is to record every transition and deny the final side effect.

Discovery and primary-source seeds:

- audiobookshelf encoded-route authentication/file boundary [GHSA-8885-9f28-m6p3](https://github.com/advisories/GHSA-8885-9f28-m6p3), [CVE-2026-71209](https://nvd.nist.gov/vuln/detail/CVE-2026-71209), and the upstream [project advisory](https://github.com/advplyr/audiobookshelf/security/advisories/GHSA-pg8v-5jcv-wrvw);
- Aerie/PlanDev body-supplied Hasura role and unauthenticated dictionary routes [GHSA-x4pc-pqfq-54j2](https://github.com/advisories/GHSA-x4pc-pqfq-54j2), [CVE-2026-71214](https://nvd.nist.gov/vuln/detail/CVE-2026-71214), and the [PlanDev repository](https://github.com/NASA-AMMOS/plandev);
- Multicluster Engine `ClusterCurator` service-account authority [GHSA-f7c4-3r82-969w](https://github.com/advisories/GHSA-f7c4-3r82-969w) / [CVE-2026-10059](https://nvd.nist.gov/vuln/detail/CVE-2026-10059);
- Advanced Cluster Management Channel/Subscription controller authority [GHSA-g9vp-wj77-5767](https://github.com/advisories/GHSA-g9vp-wj77-5767) / [CVE-2026-10090](https://nvd.nist.gov/vuln/detail/CVE-2026-10090);
- KubeSphere `Cluster` CR outbound destination selection [GHSA-w56j-p32j-vmh4](https://github.com/advisories/GHSA-w56j-p32j-vmh4) / [CVE-2026-71208](https://nvd.nist.gov/vuln/detail/CVE-2026-71208);
- Shiori stale JWT-embedded account authority [GHSA-m8xp-ww9g-3j6j](https://github.com/advisories/GHSA-m8xp-ww9g-3j6j) / [CVE-2026-71206](https://nvd.nist.gov/vuln/detail/CVE-2026-71206);
- PocketFlow coding-agent work-directory escape [GHSA-8v55-7p5p-6r5c](https://github.com/advisories/GHSA-8v55-7p5p-6r5c) / [CVE-2026-55747](https://nvd.nist.gov/vuln/detail/CVE-2026-55747);
- Crater customer-to-company scope drift [GHSA-j2xj-x8wc-f6xg](https://github.com/advisories/GHSA-j2xj-x8wc-f6xg) / [CVE-2026-55739](https://nvd.nist.gov/vuln/detail/CVE-2026-55739);
- OpenStack Ironic project-reader Portgroup scope drift [GHSA-x4h6-wf22-px84](https://github.com/advisories/GHSA-x4h6-wf22-px84), [CVE-2026-71201](https://nvd.nist.gov/vuln/detail/CVE-2026-71201), and [Launchpad bug 2162715](https://bugs.launchpad.net/ironic/+bug/2162715); and
- HashBrown CMS branch-to-shell command construction [GHSA-h9gr-58w4-64cq](https://github.com/advisories/GHSA-h9gr-58w4-64cq) / [CVE-2026-70375](https://nvd.nist.gov/vuln/detail/CVE-2026-70375).
- Apache Answer single-answer state and avatar-cleanup ownership records: [GHSA-x73g-vq9w-776v / CVE-2026-60023](https://github.com/advisories/GHSA-x73g-vq9w-776v) and [GHSA-536r-pphc-ghq8 / CVE-2026-48912](https://github.com/advisories/GHSA-536r-pphc-ghq8); and
- KubeVirt `safepath` final-syscall link-following record: [GHSA-rcfc-7m3g-h5xh / CVE-2026-13201](https://github.com/advisories/GHSA-rcfc-7m3g-h5xh).

Most entries were unreviewed GitHub/NVD mirrors when this page was written. Treat them as validation seeds, confirm behavior against the linked project revision, and do not infer package ranges or fixed versions not stated by a primary source.

!!! warning "Disposable fixtures and denied final sinks only"
    Use owned labs, synthetic tenants, random marker files, fake cluster resources, owned HTTP listeners, and patched file/process/controller sinks. Never read host files, request cloud metadata, mint real cluster-admin tokens, apply cluster-scoped resources, alter spacecraft command data, execute commands, or retrieve another tenant's records.

## 1. Record the policy representation and the handler representation

The audiobookshelf record is a compact fixture for parser-order bugs. An authentication exemption evaluates the still-encoded request path, while Express later decodes a route parameter before a cache path is built. Testing only either representation misses the boundary.

Instrument these stages independently:

1. raw request target bytes;
2. framework `req.path` used by the exemption;
3. matched route template;
4. decoded route parameters;
5. joined and canonicalized cache path;
6. database ownership lookup, if any; and
7. patched file-open sink.

Use a disposable media/cache root and a sibling directory containing only `ABS-<uuid>_100x100.jpg`. Generate a matrix of ordinary IDs, percent-encoded separators, mixed-case encodings, double encodings, dot segments, and benign encoded characters. Do not point the fixture at `/etc`, home directories, media libraries, or credentials.

A bounded positive is **encoded path matches the public-route exemption -> router emits a different decoded ID -> canonical cache path leaves the cache root -> denied file sink records the synthetic sibling marker path**. A `200`, route match, or traversal-looking string alone is not proof of file read. The secure comparator must authorize the canonical resource selected by the handler, not a pre-decoding path shape.

Apply the same recorder to static files, avatar/cover endpoints, download aliases, CDN rewrites, and reverse-proxy route exceptions. Compare every parser that handles percent encodings, separators, Unicode, and dot segments.

## 2. Never accept client-supplied trusted session context

Aerie/PlanDev provides a reusable trusted-proxy test: middleware accepts a Hasura-shaped `session_variables` object from the JSON body and prefers it over authenticated claims. Build a local sequencing-server fixture with expansion and dictionary writes replaced by append-only recorders.

Exercise this decision table:

| Authorization header | Body session context | Route family | Required result |
| --- | --- | --- | --- |
| absent | absent | protected expansion route | deny before resolution |
| low-role synthetic JWT | absent | protected expansion route | enforce the JWT role |
| absent | claimed admin role | protected expansion route | ignore body role and deny |
| low-role synthetic JWT | conflicting admin body role | protected expansion route | authenticated claim wins; deny |
| absent | any body | dictionary/write allowlist route | deny unless explicitly public and side-effect free |

Record the transport peer, trusted-proxy marker, authenticated JWT subject/role, body-supplied role, selected effective role, route allowlist decision, and no-op write target. The evidence chain is **untrusted direct request -> attacker-shaped session object selected as effective context -> privileged no-op expansion/dictionary sink reached**. Never insert an expansion rule or command dictionary.

Generalize this to reverse-proxy identity headers, GraphQL/Hasura session variables, service-mesh claims, webhook context envelopes, and internal RPC metadata. A trusted shape is not proof of a trusted hop.

## 3. Test declarative controllers as confused deputies

Kubernetes operators often convert a namespace-scoped object into cluster-wide API calls, credentials, or outbound requests. The three controller records suggest one common harness rather than product-specific exploitation.

Create an isolated test cluster with a tenant namespace, a tenant service account, and patched reconcilers. Replace token creation, Helm apply, discovery HTTP, and cluster-scoped writes with recorders. Do not grant the fixture internet access or access to real cloud metadata.

| Input object | Tenant-controlled field | Privileged effect to record | Secure invariant |
| --- | --- | --- | --- |
| `ClusterCurator` | namespaced reconciliation request | service-account token/principal selected | tenant cannot select or mint a stronger principal |
| ACM `Channel` + `Subscription` | owned Helm repository and chart resources | cluster-scoped resource apply | creator's permission and namespace constrain every rendered object |
| KubeSphere `Cluster` | kubeconfig/API endpoint | controller-originated discovery request | final destination is authorized after DNS/IP normalization |

For the subscription case, use an owned local chart repository whose rendered output contains only a uniquely named inert `ClusterRoleBinding` canary. The recorder may parse and classify it, but must deny the apply. Capture creator identity, admission result, rendered object GVK/namespace, controller service account, authorization result for that exact object, and denied final API call.

For outbound discovery, use owned listeners on ordinary, loopback, private, and mapped-address fixtures. Record the parsed URL, DNS answers, selected socket peer, redirect hops, and credential/header forwarding. Never query metadata or internal production services.

A reportable controller boundary requires **tenant-authorized input -> controller assumes stronger authority -> exact token/object/destination escapes the tenant's permitted set -> denied sink records the stronger effect**. Merely creating a CR or causing reconciliation is not privilege escalation.

## 4. Revalidate signed claims when account state can change

Shiori's JWT record illustrates a state-snapshot problem: signature verification can succeed while the embedded role no longer matches the database account. In a disposable lab, issue tokens for an owner and regular user, then record decisions before and after demotion, deletion, password change, and explicit logout.

Patch privileged handlers to no-op recorders. Capture token issue time/expiry, embedded account ID/role, current account existence/role/session epoch, and effective authorization. The bounded positive is **valid old token -> account is now deleted or demoted -> stale embedded owner role reaches a privileged recorder**. Never use a real session or perform the privileged action.

Distinguish cryptographic validity from current authority. Test both short-lived and remembered tokens, and avoid claiming a revocation bypass if the product explicitly documents immutable offline tokens with no revocation promise.

## 5. Bind object lookup to tenant scope

Crater and Ironic extend the object-scope matrix on the existing signed-request workflow. Use two synthetic companies/projects and patch serializers, updates, deletes, and cascade handlers.

| Surface | Low-privilege caller | Foreign marker object | Evidence sink |
| --- | --- | --- | --- |
| Crater customer routes/bulk operations | company B user with the ordinary customer ability | A-owned customer linked only to synthetic invoices/payments | read projection, reassignment, delete, and cascade recorder |
| Ironic Portgroup query | project B reader | Portgroup attached to A-owned or A-leased Node | result-set/project-filter recorder |

Record the caller tenant, blanket ability/role, route or query parameters, resolved object ID, parent object's owner/lease project, and object-level policy. Stop at the first foreign marker ID; do not return customer fields, invoices, payments, node details, or Portgroup data.

The positive is **valid low-role permission -> foreign object or foreign parent resolves -> tenant predicate is absent or applied to the wrong relation -> patched sink records the marker ID**. Compare list, detail, bulk, and parent-child variants because scope is often present in one family and omitted in another.

Apache Answer adds both lifecycle state and caller-selected cleanup targets to this matrix. In a two-user disposable forum, seed only synthetic public, pending, deleted, and private answer markers under public and non-public parent questions. Patch the single-answer serializer and avatar deletion sink.

| Test family | Variable to isolate | Bounded positive |
| --- | --- | --- |
| answer list versus detail | answer state and parent visibility | list denies a pending/deleted marker but detail serializer receives the same marker |
| parent/child policy | public parent with non-public child | parent visibility substitutes for the child's independent state check |
| avatar cleanup | caller-owned versus foreign synthetic file URL | authenticated user selects another user's marker and the denied delete sink receives its object/path |
| URL aliases | canonical URL, equivalent owned alias, unrelated canary URL | resolver binds cleanup to the authenticated owner's stored object before deletion |

Capture route family, caller, object ID, parent ID, child lifecycle state, owner, resolved storage key, policy result, and patched sink. Stop at marker IDs and hashes; never retrieve answer text or delete an uploaded file. Version `2.0.2` is the corrected comparator identified by the Apache records.

## 6. Revalidate no-follow guarantees at the final syscall

KubeVirt's `safepath` record shows why obtaining an `O_PATH|O_NOFOLLOW` descriptor is not the end of a symlink proof. A later helper can address that descriptor through `/proc/self/fd/N` and call a link-following ownership or mode syscall, causing the kernel to act on the leaf target that the earlier open intentionally did not follow.

Use a disposable mount/user namespace with an in-root symlink to a synthetic sibling canary. Patch or interpose `chown`, `chmod`, and equivalent final operations so they record and deny the call. Preserve this trace:

```text
requested path and allowed root
-> component-walk lstat/open flags
-> returned descriptor and /proc/self/fd alias
-> leaf type and readlink result
-> final helper and follow/no-follow syscall semantics
-> canonical object that would receive metadata
```

Compare regular files, directories, an in-root symlink to an in-root target, an in-root symlink to the sibling canary, a swapped leaf at a deterministic barrier, and a corrected build. A bounded positive is **no-follow open accepts a descriptor to the symlink itself -> downstream helper uses a link-following descriptor alias -> denied metadata sink identifies the outside-root canary target**. Opening a symlink with `O_PATH|O_NOFOLLOW` is expected behavior and is not the finding; the authority change occurs only at the later syscall.

Keep the stated precondition: the cited path requires access from a `virt-launcher` pod into a `virt-handler` operation. Do not test on a shared cluster, alter host ownership or modes, or treat pod access as host compromise without the final privileged target evidence.

## 7. Treat agent paths and command fields as structured data

PocketFlow and HashBrown expose two ends of the same problem: a structured tool/config field reaches a stronger filesystem or shell interpreter.

For copied PocketFlow coding-agent examples, replace `ReadFile`, `ListFiles`, `PatchRead`, and `PatchApply` with path recorders. Test relative in-root paths, `..` segments, absolute paths, symlinked parents, and platform-specific separators. Resolve the final parent and require containment immediately before the denied read/write syscall. Use only a temporary sibling marker.

For HashBrown Git deployer configurations, patch `AppService.exec` to capture argv-like intent without invoking a shell. Vary branch names across ordinary Git refs and inert shell-metacharacter canaries. A bounded positive is **accepted branch value -> deploy operation constructs a shell command -> recorder shows the branch altered command grammar**. Do not execute a command or trigger a production deploy.

Prefer direct argv execution with an end-of-options boundary for process wrappers. Validation that rejects one quote character is not a shell grammar or Git-ref policy.

## November 20 follow-up: KubeVirt CDI cross-namespace clone authorization skipped when the DataVolumeTemplate carries the static-volume annotation (CVE-2026-133879 / [GHSA-3mg7-wf33-wpf5](https://github.com/advisories/GHSA-3mg7-wf33-wpf5), high)

A tenant creates a VirtualMachine whose embedded DataVolumeTemplate carries the `cdi.kubevirt.io/storage.checkStaticVolume` annotation plus a cross-namespace clone source. That annotation flips CDI down a code path where the **service-account clone-authorization check is bypassed**, so a PVC from another namespace clones into the tenant's namespace without any permission on the source. Cross-tenant data disclosure from an ordinary tenant VM-create request.

Operator rules for Kubernetes multi-tenancy assessments (extends this page's request-context-to-resource-authority map):

- **Optional annotations/flags that select code paths are authorization gates in disguise.** On any CRD-driven controller: enumerate the annotation/label keys the controller branches on (`grep -r "annotations\[" pkg/` in the operator source), then for each key run the privileged-vs-unprivileged decision matrix *with and without* the annotation. The vulnerability shape is "check exists on the default path, absent on the special path," which per-route auth review of the default path never sees.
- **Embedded-template nesting is a scope-confusion amplifier.** The clone auth check was written for DataVolume objects created directly; when the DataVolume is *embedded inside a VM spec* and created by the VM controller on the tenant's behalf, the SA context that reaches the check differs. Test every "parent resource spawns child resource" flow (VM->DVD, Deployment->Pod, Ingress->EndpointSlice) with a cross-namespace/cross-tenant target in the child spec.
- Proof boundaries: two disposable namespaces you own, synthetic marker content in the source PVC, your own tenant SA; never clone real customer volumes.

## Reporting boundaries

- Preserve raw, decoded, canonical, and final path forms; do not call a route match a file read.
- Record authenticated and body/proxy-derived identities separately; do not trust a Hasura-shaped object by name.
- For controllers, identify the creator, controller principal, rendered object/destination, and denied final API/network sink.
- A valid JWT is not current authorization evidence when account state is mutable.
- Cross-tenant findings require a synthetic foreign marker reaching a patched read/write/query sink, not just a guessed ID.
- Never include real tokens, kubeconfigs, customer data, file contents, command output, or operational endpoint details in evidence.
