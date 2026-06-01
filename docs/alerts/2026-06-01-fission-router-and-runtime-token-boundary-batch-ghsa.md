# Fission router invocation and runtime token boundaries

Sources: [GHSA-3g33-6vg6-27m8](https://github.com/advisories/GHSA-3g33-6vg6-27m8), [upstream Fission advisory GHSA-3g33-6vg6-27m8](https://github.com/fission/fission/security/advisories/GHSA-3g33-6vg6-27m8), [GHSA-85g2-pmrx-r49q](https://github.com/advisories/GHSA-85g2-pmrx-r49q), [upstream Fission advisory GHSA-85g2-pmrx-r49q](https://github.com/fission/fission/security/advisories/GHSA-85g2-pmrx-r49q), [Fission v1.23.0](https://github.com/fission/fission/releases/tag/v1.23.0), and [MCP Registry GHSA-95c3-6vvw-4mrq](https://github.com/advisories/GHSA-95c3-6vvw-4mrq), updated on 2026-06-01.

Fission before `1.23.0` exposed two useful serverless-control-plane seams: public-router access to internal `/fission-function/<namespace>/<name>` invocation routes, and user function containers inheriting the `fission-fetcher` service-account token with namespace-wide secret/configmap read. The durable operator lesson is to treat serverless function platforms as both HTTP routing surfaces and Kubernetes identity surfaces: a function that is not intentionally published can still be reachable, and a function that looks data-scoped can still inherit pod-level credentials.

## Advisory signals

- **Internal route on public listener** — the Fission router registered `/fission-function/<name>` and `/fission-function/<namespace>/<name>` on the same public listener that served user `HTTPTrigger` routes. Any caller who could reach `svc/router` on port `8888` could try direct function invocation, independent of the configured host, path, or method rules on `HTTPTrigger` objects.
- **Trigger-bypass primitive** — functions intended only for timer, kubewatcher, message-queue, helper, or sample use could be invoked by guessed name/namespace. Published functions could also be called with methods or paths that the trigger did not allow.
- **Enumeration oracle** — response differences such as `404`, successful invocation, or cold-start / backend errors can disclose whether a function name exists, even when the intended HTTP route is absent.
- **Pod identity bleed** — runtime pods used the `fission-fetcher` service account, and the user function container could read the automounted Kubernetes token from `/var/run/secrets/kubernetes.io/serviceaccount/token`. That token was allowed to `get` secrets and configmaps namespace-wide, bypassing the apparent `Function.spec.secrets` allowlist boundary.
- **Patch shape** — Fission `1.23.0` separates public and internal listeners, keeps `/fission-function/...` on a ClusterIP-only internal listener with service HMAC verification, adds network-policy constraints, and suppresses token exposure to the user function container while preserving fetcher-side access.
- **Adjacent CI/registry cue** — MCP Registry `GHSA-95c3-6vvw-4mrq` is a lower-severity but useful analogue: GitHub Actions OIDC tokens used a shared audience string instead of a registry-instance-bound audience, creating cross-deployment replay risk for publisher workflows.

## Operator triage

1. Identify reachable Fission routers from the scoped network. Confirm whether an ingress, load balancer, gateway route, or internal pod network can reach the router public listener.
2. Inventory names without guessing blindly. Use authorized Kubernetes access, program documentation, error pages, sample app names, Git repositories, Helm values, CI logs, and public route names to build a short candidate list of function names and namespaces.
3. Compare intended and direct routes. For each in-scope candidate, compare the documented `HTTPTrigger` host/path/method with a controlled request to `/fission-function/<namespace>/<name>` on the same router. Evidence should show an authorization or routing boundary difference, not high-volume probing.
4. Check method and body handling. If a trigger only allows `POST /api/foo`, verify whether a harmless `GET` or alternate path against the internal-style route reaches the same function. Keep payloads inert and test-owned.
5. Validate runtime token exposure only in a lab or explicitly authorized tenant. If function deployment is in scope, deploy a minimal function that checks for the presence of the service-account token path and performs a read-only Kubernetes API call against a tester-owned or pre-approved secret/configmap name.
6. Scope the impact by namespace. The high-value question is whether function authors can read secrets/configmaps outside the declared `Function.spec.secrets`, not whether arbitrary Kubernetes API access exists.
7. For registry/OIDC publishing workflows, verify whether the audience is bound to the exact registry deployment. A valid finding shows that a token minted for one registry audience can be exchanged by another registry instance in the same trust model.

## Safe validation boundaries

- Do not brute-force function names or namespaces. Use a small, sourced candidate set and stop once the routing boundary is demonstrated.
- Use benign requests and tester-controlled functions where possible. Avoid invoking production functions that send email, modify state, bill third-party APIs, or trigger downstream jobs.
- Do not read real secrets. For the runtime-token boundary, coordinate a canary secret/configmap or use a lab namespace that mirrors the RBAC pattern.
- Capture minimal evidence: router URL, candidate function namespace/name, intended trigger rule, direct route response class, Fission version, and whether the direct route bypasses host/path/method restrictions.
- Keep Kubernetes tokens, secret names, and configmap values out of reports unless the program explicitly asks for them. Redact bearer tokens and use hashes or canary IDs for proof.
- Treat cross-tenant Fission clusters as sensitive. If a direct route appears to cross namespace or tenant boundaries, pause and coordinate before expanding impact testing.

## Reporting heuristics

- Frame router findings as serverless routing-boundary bypasses: “internal trigger route exposed on public listener,” not just “Fission outdated.”
- Include both the intended publication model and the observed direct invocation path. The contrast between `HTTPTrigger` policy and `/fission-function/<namespace>/<name>` reachability is the core proof.
- For token findings, map the declared secret allowlist to the effective Kubernetes RBAC. Show that function code can access namespace resources beyond what the function spec grants.
- Mention version and patch-shape checks: public/internal listener split, `svc/router-internal` on port `8889`, service HMAC verification, network policies, and user-container token suppression.
- For OIDC registry issues, report the audience-binding failure as a publish-identity boundary: the registry should verify a deployment-specific audience or issuer/subject contract, not accept a reusable global audience across registries.
