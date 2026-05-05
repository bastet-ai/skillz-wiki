# Proxy, metadata, and token-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because it clusters around control-plane trust assumptions: path matchers, supply-chain metadata, token headers, request start-lines, cookie helpers, redirect state, secret-store namespaces, and network-policy encryption all need explicit validation before they influence security decisions.

## Advisories covered

- **S3-Proxy resource path matching** — [GHSA-rfgq-wgg8-662p](https://github.com/advisories/GHSA-rfgq-wgg8-662p): critical path-matching issues in resource authorization.
- **Antrea** — [GHSA-qcmw-8mm4-4p28](https://github.com/advisories/GHSA-qcmw-8mm4-4p28): missing encryption of sensitive data.
- **CI4MS profile/user management** — [GHSA-vr2g-rhm5-q4jr](https://github.com/advisories/GHSA-vr2g-rhm5-q4jr): stored DOM XSS account takeover and privilege escalation.
- **awslabs/tough delegated metadata validation** — [GHSA-4v58-8p28-2rq3](https://github.com/advisories/GHSA-4v58-8p28-2rq3): missing delegated metadata validation.
- **awslabs/tough delegated-role thresholds** — [GHSA-8m7c-8m39-rv4x](https://github.com/advisories/GHSA-8m7c-8m39-rv4x): delegated role signature-threshold bypass.
- **@workos/authkit-session** — [GHSA-vvvv-983w-r7pv](https://github.com/advisories/GHSA-vvvv-983w-r7pv): open redirect via state-derived redirect target.
- **External Secrets Operator** — [GHSA-wv26-88m5-6h59](https://github.com/advisories/GHSA-wv26-88m5-6h59): namespace isolation bypass in `CAProvider` ConfigMap resolution for `SecretStore`.
- **Microdot** — [GHSA-7wc8-wvc4-m498](https://github.com/advisories/GHSA-7wc8-wvc4-m498): HTTP response splitting in `Response.set_cookie()`.
- **PyJWT** — [GHSA-752w-5fwx-jx9f](https://github.com/advisories/GHSA-752w-5fwx-jx9f): unknown `crit` header extensions accepted.
- **Netty** — [GHSA-v8h7-rr48-vmmv](https://github.com/advisories/GHSA-v8h7-rr48-vmmv): start-line injection in `DefaultHttpRequest.setUri()` enabling HTTP request smuggling and RTSP request injection.

## Operator triage

1. For S3/proxy gateways, test encoded separators, dot segments, duplicated slashes, alternate bucket/key spellings, and prefix-confusion cases against every allow/deny rule.
2. For TUF/tough users, upgrade and verify delegated metadata role paths, signature thresholds, expiration, and consistent snapshot behavior in CI with malicious metadata fixtures.
3. For JWT consumers, reject tokens with any `crit` header value unless every extension is explicitly implemented and bound to policy.
4. For HTTP libraries and microframeworks, fuzz cookie values, redirect state, and request URI setters with CR/LF, spaces, tabs, absolute-form URLs, RTSP-looking schemes, and encoded control bytes.
5. For Kubernetes secret/network controllers, verify namespace scoping for referenced ConfigMaps/Secrets and confirm sensitive traffic is encrypted where policy claims it is.

## Durable controls

- Authorization must compare canonical resource identities, not raw request paths.
- Supply-chain metadata validation must include delegation role, threshold, path pattern, expiration, and rollback/freeze checks.
- `crit` is a hard-fail JWT field unless every critical extension is understood; ignoring it is not safe compatibility.
- Redirect state should carry opaque nonces mapped server-side, not user-controlled URLs.
- Header/cookie/request-line builders must reject control characters before serialization.
- Cross-namespace references need explicit namespace fields, RBAC checks, and deny-by-default behavior for omitted namespaces.
