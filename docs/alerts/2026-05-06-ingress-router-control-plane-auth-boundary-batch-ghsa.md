# Ingress, router, and control-plane auth boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced routing, signature, BGP, BasicAuth, ForwardAuth, and template/control-plane issues updated on **2026-05-06**.

## Advisories covered

- **Elastic Package Registry signature verification gap** — [GHSA-r727-5pf6-47r2](https://github.com/advisories/GHSA-r727-5pf6-47r2): package integrity decisions needed stronger cryptographic verification.
- **kube-router exposed GoBGP admin port** — [GHSA-v5mh-h5hx-7v92](https://github.com/advisories/GHSA-v5mh-h5hx-7v92): unauthenticated gRPC admin exposure on node primary IP could allow BGP route injection.
- **Mako Windows TemplateLookup traversal** — [GHSA-2h4p-vjrc-8xpq](https://github.com/advisories/GHSA-2h4p-vjrc-8xpq): backslash URI handling could escape template roots.
- **Valtimo SpEL admin RCE** — [GHSA-j7j9-5253-f7vh](https://github.com/advisories/GHSA-j7j9-5253-f7vh): `StandardEvaluationContext` allowed expression execution by admin users.
- **Traefik boundary batch** — [GHSA-6x2q-h3cr-8j2h](https://github.com/advisories/GHSA-6x2q-h3cr-8j2h), [GHSA-xhjw-95fp-8vgq](https://github.com/advisories/GHSA-xhjw-95fp-8vgq), [GHSA-6jwx-7vp4-9847](https://github.com/advisories/GHSA-6jwx-7vp4-9847), [GHSA-5m6w-wvh7-57vm](https://github.com/advisories/GHSA-5m6w-wvh7-57vm), [GHSA-6384-m2mw-rf54](https://github.com/advisories/GHSA-6384-m2mw-rf54): BasicAuth timing enumeration, cross-namespace middleware binding, StripPrefixRegex path/RawPath desync, forwarded-alias spoofing, and `X-Forwarded-Prefix` ForwardAuth bypass.

## Why this is durable

Routers and control-plane helpers often decide trust from headers, namespaces, signatures, and normalized paths. If those values are spoofable, cross-namespace, or parsed differently by adjacent layers, the perimeter silently moves inward.

## Immediate triage

1. Patch Traefik and audit all ForwardAuth, BasicAuth, StripPrefixRegex, and Kubernetes CRD middleware configurations.
2. Block kube-router/GoBGP admin interfaces from non-local and workload networks; require mTLS or authenticated control-plane access.
3. Verify package registry mirrors enforce signature verification on the exact artifact consumed, not only metadata presence.
4. Replace dangerous template/expression contexts with constrained evaluators; admin-only RCE is still RCE when admin panels are reachable.
5. Add tests for encoded path vs raw path, backslash separators, cross-namespace references, and forwarded-header spoofing.

## Durable controls

- Centralize path canonicalization before auth decisions and pass the canonical value downstream.
- Treat forwarded headers as untrusted unless they come from a pinned proxy hop and are overwritten at the edge.
- Scope Kubernetes middleware references to explicit namespaces and owners; deny cross-namespace binding by default.
- Keep package-signature verification and route-auth behavior observable with logs that expose the decision input.
