# Kyverno `generator.apply()` cross-namespace authority, operator validation

**Date reviewed:** 2026-08-27  
**Advisory:** [GHSA-79gf-7frw-68m9](https://github.com/advisories/GHSA-79gf-7frw-68m9) / CVE-2026-54523  
**Severity:** Critical  
**Affected:** `github.com/kyverno/kyverno` >= 1.18.0, <= 1.18.1 (patched 1.18.2)  
**Boundary class:** tenant CEL `generator.apply(namespace, …)` → unvalidated namespace → background-controller `RoleBinding` creation in **any** namespace including `kube-system`

## What is durable here

Kyverno is a Kubernetes admission-control / policy engine that many clusters
run with per-tenant policy scopes. This advisory exposes a **tenant-to-cluster
authority escalation** through the policy DSL itself:

A tenant who can create a `NamespacedMutatingPolicy` in their own namespace
reaches a CEL expression that can call `generator.apply("<target-namespace>",
[...])`. The `namespace` string argument is **not validated** against the
tenant's own namespace. The Kyverno background controller then generates the
requested resources, including a `RoleBinding`, in the attacker-named
namespace, which can be `kube-system` or any other privileged namespace.

The affected code path is `pkg/cel/libs/context.go:177`
(`GenerateResources(namespace string, dataList []map[string]any)`): the
namespace arrives straight from the CEL expression with no containment check.
In 1.18.0/1.18.1 the `nmpol` CEL compiler unintentionally exposes the
`generator` library to `NamespacedMutatingPolicy` bodies, so the namespace
argument is reachable by a tenant policy author.

This is a clean, replayable **cluster tenancy boundary break**: the primitive is
"who can write a policy that tells the cluster to create a RoleBinding where?"
The durable operator lesson is that **a DSL function's namespace argument is an
authority surface**, not a routing hint, if a tenant expression can name any
namespace, the tenant has a path into cluster-privileged namespaces.

## Recon

- Identify the Kyverno version on the cluster. Only 1.18.0 / 1.18.1 are in
  range; 1.18.2 fixes it. Confirm via the kyverno controller deployment image
  or `kubectl get pods -n kyverno -o jsonpath='{.items[*].spec.containers[*].image}'`.
- Determine which namespaces can create `NamespacedMutatingPolicy` objects
  (the `namespacedmutatingpolicies` resource). That is the tenant surface.
- Note whether the cluster enforces a global
  `namespacedmutatingpolicies.kyverno.io` RBAC scope or relies on
  per-namespace policy authoring.

## Validation workflow (authorized lab / customer-approved)

### Prove the namespace-argument boundary (no privileged writes)

1. In an isolated cluster with Kyverno 1.18.0/1.18.1, create a throwaway
   tenant namespace with a policy-authoring service account.
2. As that tenant, create a `NamespacedMutatingPolicy` whose CEL body calls
   `generator.apply()` with a namespace string **different from the tenant's
   own namespace** (e.g. a second disposable namespace).
3. Observe the Kyverno background controller. The expected secure result is
   that the generated resources are confined to the tenant's namespace or the
   call is rejected. The vulnerable result is a generated resource, in the
   real flaw, a `RoleBinding`, appearing in the attacker-named namespace.
4. To bound the proof, name a **disposable** second namespace in the
   `generator.apply()` argument, not `kube-system`. The demonstration is
   "a tenant can direct generation to a namespace they do not own," not
   "we bound a cluster-admin role in `kube-system`."

### Negative evidence to record

- Generation confined to the tenant namespace → namespace argument is
  validated; the boundary holds.
- A CEL/permission error on a foreign-namespace `generator.apply()` → the
  library is not exposed or the argument is gated.

## Reporting heuristic

- Lead with the **tenant policy → `generator.apply(namespace, …)` →
  cross-namespace `RoleBinding` generation** transition. Name the exact CEL
  call and the exact unvalidated argument (`context.go:177`).
- Distinguish this from the cluster-scope policy cases: here a
  **namespaced** policy author reaches a **cluster-wide** generation target.
- Do not demonstrate a real `kube-system` `RoleBinding`. The proof is the
  foreign-namespace generation differential in a lab.

## Safety constraints

- No `RoleBinding` or RBAC object in `kube-system` or any real namespace.
- Use two disposable namespaces and a disposable policy-authoring identity.
- Do not grant or mutate cluster roles in a customer cluster.
- No policy changes beyond the lab `NamespacedMutatingPolicy`.
