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

## October 7 follow-up: Express Gateway OAuth pair — refresh-token grant skips secret and client binding; default cipherKey makes datastore-read equal to any-user bearer tokens (CVE-2026-107162 / CVE-2026-107177, [GHSA-p6v9-9m69-qjxm](https://github.com/advisories/GHSA-p6v9-9m69-qjxm), [GHSA-rq2q-fwh6-p47r](https://github.com/advisories/GHSA-rq2q-fwh6-p47r), high, through 1.16.11)

- **Refresh-token grant validates neither the token secret nor the issuing client** ([GHSA-p6v9-9m69-qjxm](https://github.com/advisories/GHSA-p6v9-9m69-qjxm)): any attacker holding *valid client credentials* (any client in the gateway) plus the *identifier portion* of another user's refresh token mints that user's access token — impersonation against every oauth2-protected downstream API. Durable rule: **a token ID is not the token.** For every OAuth token store, test whether possession of the publicly-appearing identifier (the part that shows up in logs, URLs, client storage dumps) alone redeems — grant handlers that look up by ID without comparing secret/client binding make the identifier a bearer credential. Audit battery: refresh each grant type (refresh_token, authorization_code, client_credentials) *independently* — this bypass lives only in the refresh path, sibling of the per-branch webhook-verification rule.
- **Default `crypto.cipherKey` = `sensitiveKey`** ([GHSA-rq2q-fwh6-p47r](https://github.com/advisories/GHSA-rq2q-fwh6-p47r)): stored OAuth token secrets are encrypted under a *shipped default* key, so anyone who can read the backing Redis decrypts `tokenEncrypted` values and combines them with stored token IDs → valid bearer tokens for any user. Durable axis: encryption-at-rest in gateway/token-store products inherits the key's confidentiality; a documented default key means datastore-read = credential-plaintext for every unpatched-or-default deployment. Recon corollary: Express Gateway fingerprints as Redis with `tokenEncrypted`-shaped fields; on authorized red-team datastore access, check shipped-key defaults before breaking crypto.
- Both legs show the same product boundary from two directions: the gateway is the credential authority for all downstream APIs, so *any* datastore or grant-handler weakness is blast-radius-multiplied. Test gateway OAuth endpoints and their backing store as one system.
