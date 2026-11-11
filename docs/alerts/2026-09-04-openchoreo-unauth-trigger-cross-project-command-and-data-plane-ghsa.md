# OpenChoreo

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (OpenChoreo cluster, 4 advisories). Durable because OpenChoreo is a cloud/Choreography orchestration service and the cluster exposes the **multi-project, multi-plane trust boundaries** this wiki flags for control/data-plane systems: an unauthenticated build/workflow trigger, a cross-project command-execution/wirelog leak, unauthenticated data-plane access, and an authenticated OS-command-injection leg.

Primary entries: [GHSA-c5f6-2rm9-2w8g](https://github.com/advisories/GHSA-c5f6-2rm9-2w8g) / CVE-2026-73840 (unauthenticated build/workflow trigger via git-push hook), [GHSA-52gf-6rpq-fgmx](https://github.com/advisories/GHSA-52gf-6rpq-fgmx) / CVE-2026-73841 (cross-project command execution and wirelog view), [GHSA-qh9r-j7rp-4x2m](https://github.com/advisories/GHSA-qh9r-j7rp-4x2m) / CVE-2026-73843 (unauthenticated access to data-plane operations), and [GHSA-2mw5-23gm-pccq](https://github.com/advisories/GHSA-2mw5-23gm-pccq) / CVE-2026-73667 (authenticated OS command injection).

!!! warning "Authorized validation only"
    Keep proofs to a disposable multi-project OpenChoreo lab with synthetic projects, a git-push canary, and inert command markers. Use denied process/network/file sinks. Do not trigger real production workflows, read real wirelogs containing credentials, execute real commands, or reach cloud/data-plane internal services.

## Boundary map

| GHSA | Boundary | Defect | Reusable check |
| --- | --- | --- | --- |
| [GHSA-c5f6-2rm9-2w8g](https://github.com/advisories/GHSA-c5f6-2rm9-2w8g) | Git-push → build/workflow trigger | the trigger endpoint is unauthenticated, so a crafted push can start a build/workflow | Confirm the trigger route's auth requirement; in a lab, a push canary should be able to start a synthetic workflow only if unauth. |
| [GHSA-52gf-6rpq-fgmx](https://github.com/advisories/GHSA-52gf-6rpq-fgmx) | Cross-project command + wirelog | a principal in project A can reach command execution and view wirelogs in project B | In a two-project lab, attempt the command and the wirelog read across the boundary; record the decision. |
| [GHSA-qh9r-j7rp-4x2m](https://github.com/advisories/GHSA-qh9r-j7rp-4x2m) | Data-plane operations | data-plane routes are reachable without authentication | Enumerate data-plane routes; test anonymous reachability against the control-plane auth model. |
| [GHSA-2mw5-23gm-pccq](https://github.com/advisories/GHSA-2mw5-23gm-pccq) | Authenticated OS command injection | an authenticated input reaches the OS command builder unescaped | As a low-priv authenticated user, submit a command canary; confirm the parse/escape gap with a denied sink. |

The unifying pattern is the **control-plane vs. data-plane vs. project-scope** split: each route should be gated by (a) authentication, (b) plane, and (c) project scope. This cluster shows one or more of those three missing per route.

## Replayable validation boundaries

### Unauthenticated git-push trigger

1. In a lab, identify the git-push/webhook trigger route that starts builds/workflows.
2. Determine the **auth requirement** on that route (token, signed webhook, anonymous). A positive is that an anonymous or low-trust push can enqueue a synthetic build/workflow.
3. Use an inert trigger (a no-op workflow) and record the enqueue decision, not a real build. Do not start production or secret-consuming workflows.

### Cross-project command execution + wirelog leak

1. Set up two projects, A and B, with distinct principals.
2. As project A's principal, attempt (a) the command-execution operation against a B object and (b) the wirelog view for a B run. Record the authorization decision for each.
3. A positive is either crossing the project boundary. Keep the wirelog to a synthetic run (no real credentials); do not capture live secrets from a real wirelog.
4. Negative control: the same request against a same-project object (should be allowed) to prove the scope check exists at all.

### Unauthenticated data-plane access

1. Enumerate the data-plane routes (as opposed to control-plane admin routes).
2. Test anonymous reachability against each. Record which data-plane operations are reachable without auth.
3. A positive is a data-plane operation reachable anonymously that the control-plane model assumes is gated. Do not mutate real data; a read/decision marker is enough.

### Authenticated OS command injection

1. As a low-privilege authenticated user, identify an input that feeds the OS command builder (a build arg, a plugin arg, a template value).
2. Submit an inert canary with command metacharacters; instrument the command wrapper to log argv and any substitution. A positive is command substitution or extra shell tokens.
3. Use a denied process sink and an inert marker (nonce to a controlled log); do not run real commands.

## Durable operator value

1. **Test all three gates per route.** For orchestration/control-plane systems, the reusable audit is: is this route gated by **auth**, by **plane** (control vs. data), and by **project scope**? Most multi-tenant orchestrator bugs are one of these missing on one route.
2. **Webhook/git-push triggers are a classic unauth entry.** Build/CI/webhook triggers that accept anonymous or weakly-signed pushes are a durable recon target: find the trigger route, confirm its auth, and (in lab) prove an enqueue.
3. **Wirelogs are a credential-bearing read.** Cross-project wirelog access is high-impact because wirelogs often carry runtime secrets; treat the *boundary proof* (synthetic run, boundary decision) as the report and never capture live secret material.
4. **Authenticated command injection on an orchestrator = the data-plane trust is already in your hand.** If you're authenticated and can reach the command builder, the boundary proof is expected-vs-observed trust level, not a payload.

## Safety

- **Multi-project disposable lab.** Synthetic projects, inert command canaries, denied process/network/file sinks.
- **No real production workflows.** No secret-consuming or mutating builds.
- **No live wirelog secret capture.** Synthetic runs only.
- **No internal/data-plane service probing** beyond the boundary decision.

## September 4 critical follow-up: unauthenticated cluster-gateway internal proxy (1 GHSA)

The 2026-09-04 late wave adds [GHSA-rh53-xvx2-j327](https://github.com/advisories/GHSA-rh53-xvx2-j327) / CVE-2026-73842, which closes the loop the first wave flagged as "the missing second authorization layer." The OpenChoreo control-plane **cluster-gateway** exposes internal management APIs (`/api/proxy/`, `/api/exec/`, `/api/wirelogs/`) that tunnel requests through to connected data planes' Kubernetes APIs, and the internal listener **authenticates no caller**. The request validator permits mutating HTTP methods and reads of Secrets in tenant namespaces (only `kube-system` Secrets are blocked), so although the client library documents these requests as "read-only," the server enforces no such restriction. Fixed in 1.0.3 / 1.1.3 / 1.2.0 (affected `< 1.0.3`).

### Why this is the strongest item in the cluster

| Leg | What the gateway listener allows | Boundary crossed |
| --- | --- | --- |
| Secret disclosure | Read any Secret outside `kube-system` in any tenant namespace, independent of workload ServiceAccount permissions | plane + project scope both absent; the "read-only" doc contract is not enforced server-side |
| Workload mutation | Create/modify/delete Deployments, Services, and other resources | mutating methods permitted by the request validator |
| Pod exec | `/api/exec/` into pods across every connected data plane | command execution with no caller identity |
| Compounding | The gateway provides **no compensating authorization**, so GHSA-52gf-6rpq-fgmx (the cross-project exec/wirelogs bypass) and any other authz gap or SSRF that reaches the internal API reach the data-plane Kubernetes API unchecked | missing second authorization layer |

Direct exploitability depends on the network isolation of the internal listener (not fixed in source). Where the internal port is reachable by untrusted workloads with no restrictive NetworkPolicy, impact lands in a separate data-plane cluster.

### Replayable validation boundary

1. In a two-plane lab (control plane + one connected data plane), map the internal cluster-gateway listener's bind address and which network segments can reach it. Record reachability; do not probe internal production segments.
2. From a second, untrusted principal in the lab, attempt against `/api/proxy/` and `/api/exec/` with a **synthetic** data-plane object: a `GET` for a synthetic Secret in a tenant namespace and a no-op create/delete on a synthetic workload. Use a synthetic K8s API with a canary Secret and a canary Deployment; never target a real cluster.
3. Confirm the request validator accepts a mutating method and a non-`kube-system` Secret read. The positive evidence is the accept/allow decision on the synthetic object, plus the `kube-system`-only Secret block as the (insufficient) negative control.
4. Confirm the "read-only" client-library contract is not enforced: record that the server path accepts a mutating verb even where the client wrapper labels it read-only.
5. Negative control: the patched 1.0.3/1.1.3/1.2.0 gateway should deny the same synthetic calls when the caller has no valid credentials.

### Durable operator value

1. **"Read-only" in the client docs is not a server-side control.** When a control plane tunnels a client's requests to a data plane, the security boundary is the *server* request validator and authentication, not the client library's documentation. Audit the server-side method/namespace/Secret allow-list.
2. **The internal tunnel listener is a second, hidden API surface.** Enumerate every internal/management listener on a control plane (proxy, exec, wirelogs, debug) and test its auth independently of the public API. An unauthenticated internal listener that reaches every connected data plane is a full plane-crossing primitive.
3. **The missing second layer compounds every other bug.** If the internal API has no compensating auth, then *any* SSRF, authz gap, or cross-project bypass that reaches it becomes data-plane-wide. Treat the internal listener's auth as the single most important control in the cluster.
4. **Secret reads are the highest-impact leg.** Reading a tenant-namespace Secret (DB creds, KMS keys, TLS keys) independent of ServiceAccount permissions is the report's headline; prove it with a synthetic Secret and stop at the read decision.

## Safety

- **Multi-project, multi-plane disposable lab.** Synthetic projects, synthetic data-plane cluster, inert command canaries, denied process/network/file sinks.
- **No real production workflows.** No secret-consuming or mutating builds.
- **No live wirelog/Secret capture.** Synthetic Secret and synthetic workload only.
- **No internal/data-plane service probing** beyond the boundary decision.

---

*Source: hourly offensive-security scan, 2026-09-04. All 5 OpenChoreo advisories (4 first-wave + 1 critical gateway follow-up) tracked in the [source index](../notes/source-index.md).*
