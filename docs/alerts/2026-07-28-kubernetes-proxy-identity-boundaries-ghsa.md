---
title: Kubernetes proxy impersonation and agent-auth boundaries from July 28 GHSA updates
---

# Kubernetes proxy impersonation and agent-auth boundaries from July 28 GHSA updates

Two Red Hat advisories expose a reusable Kubernetes control-plane testing pattern: a trusted proxy may preserve caller-supplied identity headers, while an agent-facing proxy listener may accept a connection without proving agent identity. Test the identity transition at each proxy hop instead of treating TLS reachability or a hub login as sufficient authorization.

Sources:

- [GHSA-vr7g-637m-v9mm / CVE-2026-17107: cluster-proxy caller-supplied impersonation group](https://github.com/advisories/GHSA-vr7g-637m-v9mm)
- [Red Hat CVE-2026-17107 record](https://access.redhat.com/security/cve/CVE-2026-17107)
- [NVD record for CVE-2026-17107](https://nvd.nist.gov/vuln/detail/CVE-2026-17107)
- [GHSA-43hh-68v6-mf36 / CVE-2026-16242: Konnectivity agent listener missing client authentication](https://github.com/advisories/GHSA-43hh-68v6-mf36)
- [HyperShift pull request 9031](https://github.com/openshift/hypershift/pull/9031)
- [Red Hat CVE-2026-16242 record](https://access.redhat.com/security/cve/CVE-2026-16242)
- [NVD record for CVE-2026-16242](https://nvd.nist.gov/vuln/detail/CVE-2026-16242)

The GitHub entries are unreviewed. CVE-2026-17107 names the `cluster-proxy` service-proxy used by Red Hat Advanced Cluster Management for Kubernetes (RHACM) and multicluster-engine (MCE). CVE-2026-16242 concerns Konnectivity proxy-server configuration for hosted control planes. Confirm the exact component image, deployment mode, listener flags, network reachability, service-account permissions, and fixed-build behavior before reporting.

!!! warning "Authorized validation only"
    Use disposable hub, spoke, and hosted-control-plane clusters with synthetic identities and marker resources. Never inject `system:masters` or another real privileged group, join a production agent pool, inspect control-plane traffic, read Kubernetes Secrets, capture service-account tokens, or alter shared cluster networking.

## Map both proxy trust chains first

Record the actors and credentials at every edge.

```text
Platform / release:
Component image digest:
Client -> hub authentication:
Caller-controlled headers preserved by ingress:
Hub proxy service account:
Hub proxy impersonation permissions:
Hub -> spoke credential:
Spoke API authorization result:

Agent listener address / reachability:
TLS server identity verified:
Client certificate requested / required:
Configured cluster CA:
Token authentication configured:
Agent registration event:
Fixed-build control:
```

Also capture the ingress or service-mesh behavior in front of each component. A caller cannot exploit an identity header that a trusted edge always removes, and a missing listener check is not remotely reachable when the endpoint is confined to an inaccessible network. Those are deployment-specific negative controls, not reasons to omit the component-level test.

## Cluster-proxy: test replace-versus-append behavior for impersonation headers

CVE-2026-17107 says service-proxy appended its own impersonation group headers without first removing values supplied by the authenticated hub caller. The spoke service account reportedly held unrestricted impersonation permission. Together, those edges could let a hub principal select an additional group on every managed cluster.

Prove arbitrary group adoption with a harmless custom group rather than an administrative one.

### Synthetic-group authorization matrix

1. In a disposable spoke, create a namespace and one ConfigMap containing only a random marker. Do not use `default`, platform, operator, or application namespaces.
2. Create a narrow read-only role that permits `get` on that single ConfigMap. Bind it only to a synthetic group such as `skillz-proxy-boundary-probe`.
3. Create a low-privilege hub principal that can reach the proxy but has no spoke permission to read the marker.
4. Establish controls through the normal proxy route:
   - no `Impersonate-Group` header;
   - an unrelated synthetic group;
   - the marker-bound synthetic group;
   - duplicate and case variants only if the HTTP stack preserves them;
   - a legitimate higher-privilege hub identity as a positive route control, without caller-supplied identity headers.
5. Capture the raw request as received at the hub edge, the normalized headers emitted by service-proxy, the identity seen by the spoke API server, and the final authorization decision. Redact bearer material.
6. If source or lab instrumentation is available, log whether inbound impersonation headers are removed before trusted identity is constructed. Do not infer replacement from a helper function that the request path may not call.
7. Repeat on the fixed component. It should reject or remove the caller-supplied value before adding proxy-controlled identity.

A decisive positive is **low-privilege authenticated hub caller -> caller-selected synthetic group survives service-proxy -> spoke authorizes only the single marker read because of that group**. The custom role proves group injection without granting cluster administration. If the header reaches the proxy but not the spoke, preserve that as a parser or ingress negative control.

### Separate the two required edges

Report these independently:

1. **Header ownership failure:** untrusted caller input remains in an identity-bearing `Impersonate-*` field after the trusted proxy transition.
2. **Impersonation authority:** the proxy credential is permitted to impersonate the selected group on the spoke.

Header survival alone does not prove privilege escalation if the spoke rejects the proxy's impersonation request. Broad service-account impersonation alone is not caller-controlled if the proxy constructs all identity fields from trusted state.

## Konnectivity: test agent admission before any traffic forwarding

CVE-2026-16242 says an agent-facing Konnectivity listener for hosted control planes started without `--cluster-ca-cert` and without token-based agent authentication. A network-reachable client could reportedly join the routing pool without proving agent identity. The durable question is whether TLS protects only the server side or also authenticates the connecting agent.

### Isolated listener decision table

1. Deploy a disposable hosted control plane with no workloads, tenant data, external routes, or shared node networks. Give the test listener a dedicated address and security group.
2. Record the proxy-server command line, mounted CA files, token-auth settings, listener address, and component image digest. Configuration evidence establishes the expected gate but does not replace a connection test.
3. Prepare four lab clients:
   - no client certificate or token;
   - a self-signed certificate from an unrelated lab CA;
   - a certificate signed by the expected cluster CA but with an invalid or unrecognized agent identity;
   - the legitimate disposable agent.
4. Connect one client at a time. Stop after TLS/authentication and agent-registration state; do not advertise production destinations or forward arbitrary streams.
5. Capture whether the listener requests a client certificate, whether certificate-chain and identity validation occur, whether token validation occurs, and whether an agent-session or routing-pool registration event is created.
6. Use only a synthetic route identifier with a local no-op backend if registration cannot be observed without route setup. Send a fixed marker and discard it locally; do not proxy Kubernetes API, node, metadata, or tenant traffic.
7. Repeat against the fixed configuration. Unauthenticated and unrelated-CA clients should fail before registration, while the legitimate disposable agent remains functional.

The strongest safe proof is **network-reachable agent listener -> client with no valid cluster identity completes the protocol admission step -> isolated routing-pool registration appears**. Do not intercept, modify, delay, or drop real control-plane traffic to demonstrate impact.

## Cross-layer variants worth checking

Apply the same matrices to authorized proxy systems that carry identity or routing authority:

- `Impersonate-User`, `Impersonate-Group`, `Impersonate-Extra-*`, and vendor-specific identity headers;
- headers duplicated across HTTP/1.1, HTTP/2, ingress, service mesh, and application parsing;
- trusted proxy credentials whose impersonation verbs, resources, users, or groups are broader than the route requires;
- mTLS listeners that validate a certificate chain but do not bind the certificate identity to an enrolled agent;
- listeners that require authentication on one port or deployment mode but omit it on an alternate agent, metrics, or compatibility endpoint;
- reconnect, failover, and rolling-upgrade paths that start with different authentication flags.

Vary one layer at a time. A front-end rejection can hide a vulnerable backend path, while a direct backend test can exaggerate reachability if the deployed edge is mandatory and correctly strips the input.

## Reporting checklist

Include:

- exact platform release, component image digest, deployment mode, and network path;
- authenticated hub role, ingress normalization, raw and forwarded identity headers;
- proxy service-account impersonation scope and the spoke identity/authorization decision;
- synthetic group, narrow role binding, marker resource, and negative controls;
- agent-listener address, TLS client-auth behavior, configured CA/token flags, and registration evidence;
- affected-versus-fixed decision tables;
- redacted requests and logs with no live tokens, Secrets, tenant objects, or control-plane payloads.

Bound impact carefully. A preserved header is not escalation until the spoke accepts the proxy's impersonation and grants a permission. A TLS connection is not agent admission until the application creates authenticated agent state. An isolated registration proves the missing identity boundary; it does not prove traffic interception unless that later routing edge is separately and safely demonstrated.

## Follow-up (Oct 5 18:34Z): HyperShift operator copies user kubeconfigs — with `exec` plugins — into the privileged control-plane namespace (CVE-2026-101919 / [GHSA-9pmf-w27v-pwpg](https://github.com/advisories/GHSA-9pmf-w27v-pwpg), high)

**HyperShift operator** copies user-provided kubeconfig Secrets straight into the privileged hosted-control-plane namespace **without validation or sanitization**. A user who can create clusters and Secrets supplies a kubeconfig containing an `exec:` credential plugin; when a downstream controller in the control plane loads that kubeconfig and runs the command, the attacker has arbitrary code execution **inside the control plane**.

Why it earns a fold on this page (same "trusted-consumer boundary" thesis): the kubeconfig file is an *input format that executes*. Kubernetes treats `exec` plugins as first-class auth machinery, so every component that loads a user-influenced kubeconfig — operators, importers, sync controllers, CI runners — is a code-execution sink for whoever can write that Secret.

Operator axes:

1. **`exec`/`auth-provider` stanzas in any user-influenced kubeconfig are an RCE gadget, not a config quirk.** On authorized platform engagements with hosted-control-plane or multi-tenant cluster products (HyperShift, Cluster API, Crossplane-style composites, managed-control-plane SaaS), test: create a Secret-shaped kubeconfig whose `users[].user.exec` points at a lab PATH binary that writes a marker file, attach it as the field the operator consumes, and watch for the marker in the consuming pod. Bounded positive = marker written *inside* the privileged pod; report the consuming controller and required RBAC (here: cluster-create + secret-create), not the marker content.
2. **Grep fingerprint for white-box review**: `clientcmd.NewClientConfigFromBytes`, `clientcmd.Load`, `clientcmd.BuildConfigFromFlags`, or `client-go` kubeconfig parsing applied to Secret/configmap payloads that originate from lower-privilege namespaces — then check whether `CmdPath`/`exec` fields are stripped or rejected before client construction.
3. **Same-shape siblings to sweep**: kubeconfig-in-a-Secret conventions (cluster-api providers, Rancher/Anthos-style import secrets, `kubeconfig`-typed Crossplane resources, GitOps repos storing kubeconfigs), plus any product that accepts "external cluster credentials" uploads. The exec-plugin leg is often missed because the *validation* leg (YAML parses, server URL reachable) passes while nobody looks at the credential plugin stanza.
4. Proof discipline: synthetic clusters on lab infrastructure only, marker-only exec payloads (`touch /tmp/...`), never commands against a live customer control plane; capture pod-name/namespace evidence with no control-plane tokens.
