# Contour cookie-rewrite Lua boundary check

Source: hourly offensive-security scan, 2026-07-01. Primary entry: GitHub Advisory Database [GHSA-x4mj-7f9g-29h4](https://github.com/advisories/GHSA-x4mj-7f9g-29h4) / CVE-2026-41246 for Contour cookie rewrite policy Lua code injection.

This is durable for operators because it exposes a recurring Kubernetes ingress-controller boundary: a tenant-controlled route object is converted into executable proxy policy on shared Envoy infrastructure. Treat this as a route-owner-to-shared-proxy trust-boundary test, not as a generic denial-of-service issue.

## What changed

Contour's cookie rewriting feature can interpolate `HTTPProxy` cookie path rewrite values into Envoy Lua source when affected versions render the internal Lua filter with insufficient escaping.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-x4mj-7f9g-29h4](https://github.com/advisories/GHSA-x4mj-7f9g-29h4) / CVE-2026-41246 | `github.com/projectcontour/contour` `>= 1.19.0, < 1.31.6`, `>= 1.32.0, < 1.32.5`, and `>= 1.33.0, < 1.33.4` | `spec.routes[].cookieRewritePolicies[].pathRewrite.value` and `spec.routes[].services[].cookieRewritePolicies[].pathRewrite.value` cross from Kubernetes `HTTPProxy` YAML into generated Envoy Lua | Ingress assessments should review generated proxy code/config when tenant route fields are templated into shared filters. |
| [GHSA-g3xr-5w5j-w4q4](https://github.com/advisories/GHSA-g3xr-5w5j-w4q4) / CVE-2026-50149 | Contour `HTTPProxy` virtual hosts with `.spec.virtualhost.tls.enableFallbackCertificate: true` and `.spec.virtualhost.jwtProviders` | TLS clients that omit SNI or send unrecognized SNI could route through fallback-certificate handling without the configured JWT verification | Ingress assessments should include SNI/no-SNI parser-path tests for every auth-bearing virtual host that also uses fallback certificate behavior. |

The advisory states the injected code executes when traffic reaches the attacker's own route. The operator value is the shared-infrastructure blast radius: Envoy may hold xDS client credentials and route/TLS configuration for other tenants. Do not attempt to read those files during validation.

The JWT follow-up is a different but related ingress boundary: Contour accepted an `HTTPProxy` configuration where fallback TLS certificate behavior and JWT providers were combined. In affected deployments, a raw TLS client that does not bind the request to a recognized SNI name can exercise a route-selection path that diverges from the authenticated virtual-host path. Treat this as a virtual-host/SNI/auth consistency test, not as a token-cracking exercise.

## Operator triage

1. **Confirm route-author permissions.** The finding requires RBAC that can create or mutate `HTTPProxy` resources; plain external HTTP access is not enough.
2. **Map shared Envoy tenancy.** Prioritize clusters where multiple namespaces or teams share the same Contour/Envoy data plane.
3. **Find cookie rewrite usage.** Search approved lab manifests for `cookieRewritePolicies`, `pathRewrite`, and templated route policies before attempting payloads.
4. **Capture generated config, not secrets.** If Envoy admin/config dumps are available in a lab, record whether route input appears inside Lua code. Do not collect xDS credentials, private keys, or other tenants' route data.
5. **Probe authenticated routes with SNI variants.** For JWT-protected `HTTPProxy` objects, compare normal SNI, omitted SNI, and unknown SNI behavior using the same harmless canary route and no valid JWT.

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

### JWT fallback-certificate/SNI boundary

Preconditions: isolated Kubernetes lab, affected Contour version, a disposable `HTTPProxy` with both fallback certificate and JWT providers configured, owned backend service, and a client capable of raw TLS/SNI control such as `openssl s_client` or `curl --connect-to` with explicit `--resolve` testing.

Safe proof shape:

1. Confirm the normal HTTPS request with the expected SNI and no JWT is rejected by the configured JWT policy.
2. Repeat the same request while omitting SNI, then while sending an unknown SNI that does not match any `HTTPProxy` FQDN.
3. Positive evidence is a decision table showing that the no-SNI or unknown-SNI request reaches only the attacker's canary backend while the expected-SNI request is JWT-rejected.
4. Negative controls: patched Contour `1.33.5` or later, invalid `HTTPProxy` status for the fallback-certificate plus JWT combination, and no backend hit for unauthenticated no-SNI/unknown-SNI requests.

Do not use production bearer tokens, enumerate unrelated virtual hosts, or test against admin/export/customer-data routes. Keep evidence to status codes, route names, and a marker response from an owned backend.
