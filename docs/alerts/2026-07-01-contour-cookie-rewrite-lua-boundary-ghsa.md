# Contour cookie-rewrite Lua boundary check

Source: hourly offensive-security scan, 2026-07-01. Primary entry: GitHub Advisory Database [GHSA-x4mj-7f9g-29h4](https://github.com/advisories/GHSA-x4mj-7f9g-29h4) / CVE-2026-41246 for Contour cookie rewrite policy Lua code injection.

This is durable for operators because it exposes a recurring Kubernetes ingress-controller boundary: a tenant-controlled route object is converted into executable proxy policy on shared Envoy infrastructure. Treat this as a route-owner-to-shared-proxy trust-boundary test, not as a generic denial-of-service issue.

## What changed

Contour's cookie rewriting feature can interpolate `HTTPProxy` cookie path rewrite values into Envoy Lua source when affected versions render the internal Lua filter with insufficient escaping.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-x4mj-7f9g-29h4](https://github.com/advisories/GHSA-x4mj-7f9g-29h4) / CVE-2026-41246 | `github.com/projectcontour/contour` `>= 1.19.0, < 1.31.6`, `>= 1.32.0, < 1.32.5`, and `>= 1.33.0, < 1.33.4` | `spec.routes[].cookieRewritePolicies[].pathRewrite.value` and `spec.routes[].services[].cookieRewritePolicies[].pathRewrite.value` cross from Kubernetes `HTTPProxy` YAML into generated Envoy Lua | Ingress assessments should review generated proxy code/config when tenant route fields are templated into shared filters. |

The advisory states the injected code executes when traffic reaches the attacker's own route. The operator value is the shared-infrastructure blast radius: Envoy may hold xDS client credentials and route/TLS configuration for other tenants. Do not attempt to read those files during validation.

## Operator triage

1. **Confirm route-author permissions.** The finding requires RBAC that can create or mutate `HTTPProxy` resources; plain external HTTP access is not enough.
2. **Map shared Envoy tenancy.** Prioritize clusters where multiple namespaces or teams share the same Contour/Envoy data plane.
3. **Find cookie rewrite usage.** Search approved lab manifests for `cookieRewritePolicies`, `pathRewrite`, and templated route policies before attempting payloads.
4. **Capture generated config, not secrets.** If Envoy admin/config dumps are available in a lab, record whether route input appears inside Lua code. Do not collect xDS credentials, private keys, or other tenants' route data.

## Replayable validation boundary

Preconditions: isolated Kubernetes lab, affected Contour version, disposable namespace, test `HTTPProxy`, owned backend service, and no production Envoy credentials or tenant certificates mounted into evidence.

Safe proof shape:

1. Create a baseline `HTTPProxy` route with a benign cookie path rewrite value and confirm normal traffic reaches a canary backend.
2. Change only the path rewrite value to a harmless Lua syntax canary that produces an observable marker in the generated Envoy config or in a response/header on the attacker's own route. Use inert markers; do not read files or execute destructive operations.
3. Send a single request through the attacker's route to trigger the rewritten-cookie path.
4. Positive evidence should show the route-controlled value escaping its intended string/data context into Lua execution or Lua source structure.
5. Negative controls: patched Contour `1.31.6`, `1.32.5`, or `1.33.4`; route value escaped as data; and no `text/template` interpolation of untrusted route fields into Lua source.

## Reporting notes

Lead with the crossed boundary: **namespace route author to shared Envoy Lua filter execution**. Include Contour version, Envoy version if known, namespace/RBAC role, exact `HTTPProxy` field, canary-only evidence, and patched-version behavior.

Do not publish payloads that read Envoy filesystem paths, xDS credentials, TLS certificates, private keys, service-account tokens, or other tenants' configuration. Stop at inert execution/config-escape proof in a lab.
