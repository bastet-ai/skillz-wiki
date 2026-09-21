---
title: Automation-platform credential-test exfiltration and FQDN-endpoint metadata SSRF
---

# Automation-platform credential-test exfiltration and FQDN-endpoint metadata SSRF

A September 21 GitHub advisory-enrichment wave surfaced detailed descriptions for several previously terse Red Hat platform advisories. Three carry durable offensive operator axes that generalize past the specific products:

- **AAP Controller HashiCorp Vault credential plugin service-account exfiltration** — [GHSA-p5f2-j2p5-7p7v / CVE-2026-12564](https://github.com/advisories/GHSA-p5f2-j2p5-7p7v) (CVSS 9.6): `kubernetes_auth()` in `awx_plugins/credentials/hashivault.py` reads the **controller pod's own Kubernetes service-account token** and POSTs it to a URL taken from the credential definition when that credential is *tested*. An authenticated user with credential-creation privileges points a Vault Secret Lookup credential (kubernetes_role auth) at an attacker listener and receives the controller's SA token, which the advisory reports carries Kubernetes API access to control-plane namespaces with full pod CRUD and secret read — including database credentials and the Django `SECRET_KEY`.
- **OpenShift Router FQDN EndpointSlice → cloud metadata SSRF** — [GHSA-76ww-43j5-78x5 / CVE-2026-42965](https://github.com/advisories/GHSA-76ww-43j5-78x5): a user with EndpointSlice write access creates a Service backed by an **FQDN-type** EndpointSlice endpoint that resolves to a cloud metadata endpoint; the router proxies requests there, disclosing instance credentials. The advisory explicitly frames this as **bypassing prior IP-address validation** — the denylist covers IPs, and hostname endpoints were the unextended leg.
- **Quay `GLOBAL_READONLY_SUPER_USERS` robot-token disclosure** — [GHSA-x8x8-qp2x-c2mj / CVE-2026-18255](https://github.com/advisories/GHSA-x8x8-qp2x-c2mj): a user configured as *read-only* superuser can view **robot account tokens for repositories they are not a member of**, then impersonate any robot account. "Read-only" gated resource reads but not the credential-view surface.

!!! warning "Disposable platforms and owned listeners only"
    Use a disposable controller/registry/router deployment, an owned no-content HTTPS listener as the credential-test sink, a synthetic service-account token whose value is a random marker, a lab-only DNS name that resolves to an owned denied canary (never `169.254.169.254`, metadata hostnames, or any live internal address), synthetic repositories and robot accounts, and patched token-send/proxy/lookup sinks that record and deny. Never test against a production controller, capture live tokens, route real traffic at metadata endpoints, or read real robot credentials.

## 1. Treat every "test this credential" button as an outbound-fetch primitive

Credential plugins in automation controllers (AWX/Ansible Automation Platform and siblings) accept **operator-supplied connection material and then actively connect somewhere** to validate it. The finding class: the test path authenticates with the *platform's own* identity — pod SA token, instance role, mTLS client cert — to a URL the unprivileged credential author chose.

Operator checklist on any controller/CICD platform with pluggable credentials:

1. Enumerate credential types whose "verify/test" action performs a network request (Vault, CyberArk, HashiCorp-consul, custom `awx_plugins/credentials/*`, and equivalent runner-side plugins).
2. For each, identify **what identity material rides along**: read the plugin source (these platforms are open-source — `kubernetes_auth()`, `requests.post`, `service-ca.crt`, `/var/run/secrets/kubernetes.io/serviceaccount/token` are the grep targets).
3. In an authorized lab, create a credential with the auth URL pointed at your owned listener and press Test. A bounded positive is **the listener receives a bearer token that matches the pod's SA token marker** while the credential author holds no cluster permission beyond `credential_create`.
4. Prove token scope without using it destructively: `kubectl auth can-i --list --token=<captured marker>` against the lab API, or record the API's self-review response. Do not replay captured tokens against any live cluster.

Durable rule: **a form field that names a URL plus a plugin that authenticates = exfiltration channel for the platform's identity**, independent of whether the platform's UI gates cluster access from the user. Chain to check when a token is captured: pod CRUD in control-plane namespaces → read every Secret (DB creds, app `SECRET_KEY`s) → impersonate the automation platform itself.

## 2. Sweep EndpointSlice/IP-validation designs for the hostname leg

The Router record is the cloud-metadata-SSRF sibling of every backend-IP denylist. The invariant to attack: **validators that check endpoint IPs cannot check names**.

| Endpoint type | Value | What the validator sees | Risk |
| --- | --- | --- | --- |
| `addresses: ["10.0.0.5"]` | literal IP | IP denylist applies | denied |
| `addresses: ["169.254.169.254"]` | literal metadata IP | denylist applies | denied |
| `addresses: ["metadata.internal.example"]` (FQDN type) | hostname | nothing to match against | resolves at proxy time → metadata |
| hostname with attacker-controlled DNS | rebinding | nothing | validation-time ≠ connect-time answer |

Validation workflow in a disposable cluster where you hold only EndpointSlice write (or can create a Service + slices):

1. Create a synthetic Service, attach an FQDN-type EndpointSlice pointing at an **owned lab hostname** that resolves to a denied canary listener (patched resolver records the lookup, socket is refused).
2. Route one inert request through the router for that Service. A bounded positive is **the router's proxy opens (or attempts) a connection to the hostname-resolved canary while the IP-literal control is still rejected** — that differential *is* the finding.
3. Also test the parameter-ABSENT/alternate-type matrix: endpoints with both address fields set, empty `targetRef`, and per-provider annotation flags that select the resolution path.

This generalizes to any proxy that resolves backend names (ingress controllers, API gateways, service meshes, registry mirrors): **grep the validation code for the parsed type — an IP-parsing call (`net.ParseIP`, `ipaddress.ip_address`) is itself evidence of a missing hostname leg.**

## 3. Enumerate credential-view surfaces under "read-only" global roles

Quay's record gives the reusable axis: platform-admin "super roles" are usually built by layering read grants over resource types, and **token/secret sub-resources are frequently forgotten** in the layering.

- On any registry/artifact platform with a read-only admin concept, list every sub-resource that returns long-lived material: robot/bot account tokens, replication passwords, security scanner configs, webhook secrets, `GET` endpoints returning credentials "for the owner."
- With a disposable read-only-superuser account, request each one against a repository the account does not belong to (the cross-scope leg), not just ones it can browse.
- A bounded positive is **a synthetic robot token string returned to the read-only principal for a foreign repository**. Report the token field name and scope; never retain or replay real robot credentials.

Pair with the recurring identity-drift family: `GLOBAL_READONLY_SUPER_USERS` is config-file-defined, so also check whether the role's power depends on *which* config key or list membership (parameter-ABSENT axis) rather than database-backed grants.

## Evidence and reporting checklist

- [ ] Exact product, distribution, and build are recorded; these are Red Hat-enriched GitHub mirrors — confirm against the Red Hat primary advisory before reporting.
- [ ] Credential-test proofs use a synthetic token marker; captured-marker equality is proven without API use against any live cluster.
- [ ] Metadata-SSRF proofs use owned hostnames + denied canaries only; no literal metadata IPs are routed in shared environments.
- [ ] Validation-bypass claims show the IP-literal control still denies while the hostname leg is reached on the same deployment.
- [ ] Read-only-role token findings state the exact endpoint and scope, and contain no live token material.
- [ ] Prerequisite authority (credential-create, EndpointSlice write, config-list membership) is stated per finding; none of these three are unauthenticated.

## Tracked from the same enrichment wave without publication

- libaom AV1 codec quartet (CVE-2026-56211 encoder SVC layer-ID overlap with crash-oracle base-address brute force in fork-based encode services, CVE-2026-56209 arbitrary-address write, CVE-2026-56208/56210 heap overflows): codec memory-safety class per parser precedent; the **crash oracle in fork-per-job workers is itself the reusable primitive** — revisit if a replayable service-level workflow lands.
- xdgmime `_xdg_mime_magic_parse_magic_line()` 2-byte OOB write when parsing an attacker-controlled magic file from `$XDG_DATA_HOME/mime/magic` (CVE-2026-16118): user-writable MIME-detection data files as attack surface is a durable desktop axis; local class, tracked.
- Ansible Automation Platform images group-writable `/etc/passwd` → container UID-0 add via root-group membership (CVE-2025-57847): container-hardening hygiene, tracked.
- ml-metadata statically-linked outdated gRPC H2 DoS (CVE-2026-18618) and Quay repository-mirror SSRF (CVE-2026-15927, already promoted on the August 6 Quay mirror page) re-surfaced in the same update batch.
