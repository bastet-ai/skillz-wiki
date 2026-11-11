---
title: Framework authentication, static-path, and policy-field boundaries from July 24 GHSA updates
---

# Framework authentication, static-path, and policy-field boundaries from July 24 GHSA updates

This July 24 wave yields four durable source-assisted checks: high-level OpenAPI middleware silently installing no-op authentication, Apache Camel validating only token presence under its documented default Keycloak policy, static-file authorization running on a different path representation than file resolution, and CEL exposing Go fields that JSON tags appear to hide.

Sources:

- [GHSA-r277-6w6q-xmqw: kin-openapi `ValidationHandler.Load()` fail-open authentication](https://github.com/advisories/GHSA-r277-6w6q-xmqw)
- [GHSA-qvc3-6q9x-95pj: Apache Camel `KeycloakSecurityPolicy` default verification gap](https://github.com/advisories/GHSA-qvc3-6q9x-95pj)
- [GHSA-83w8-p2f5-377r: `@fastify/static` route-guard bypass](https://github.com/advisories/GHSA-83w8-p2f5-377r)
- [GHSA-8pvw-jcv7-9cmj: `@fastify/static` `allowedPath` canonicalization bypass](https://github.com/advisories/GHSA-8pvw-jcv7-9cmj)
- [GHSA-gcjh-h69q-9w9g: cel-go JSON private-field exposure](https://github.com/advisories/GHSA-gcjh-h69q-9w9g)
- [GHSA-fpm2-m4qq-wghr: Apache Camel platform-http JWT iss/aud skipped when unset / CVE-2026-66908](https://github.com/advisories/GHSA-fpm2-m4qq-wghr)

!!! warning "Authorized validation only"
    Use local fixtures, synthetic routes, marker files, fake bearer values, and structs containing canary fields. Never retrieve production static files, submit forged tokens to third-party services, or evaluate expressions against real credentials or customer objects.

## kin-openapi: declared security versus installed authenticator

`github.com/getkin/kin-openapi` through 0.143.0 behaves differently across two APIs. Direct `ValidateRequest` fails closed when `AuthenticationFunc` is nil, but `openapi3filter.ValidationHandler.Load()` replaces nil with `NoopAuthenticationFunc`. The no-op returns success for every OpenAPI security scheme, so applications that rely on the high-level handler as their enforcement layer can pass an unauthenticated request to a protected route. Version 0.144.0 removes the implicit substitution.

### Minimal decision-table proof

1. Confirm the application uses `ValidationHandler`, calls `Load()`, omits `AuthenticationFunc`, and relies on OpenAPI `security` declarations for enforcement. Package presence or schema validation alone is insufficient.
2. Build a local OpenAPI fixture with one public route and one route protected by a synthetic `X-Canary-Key` API-key scheme. Both handlers should return only marker text.
3. Send the protected request with no header, a wrong marker, and the expected marker. Record the handler counter and status.
4. Run the same request through direct `ValidateRequest` with nil authentication to establish the library's fail-closed contrast.
5. Repeat with an explicit test authenticator and with 0.144.0. Missing authentication must not reach the protected marker handler.

Report **declared OpenAPI security -> high-level middleware injects no-op authenticator -> protected handler executes without credentials**. Do not report applications that install a separate, effective authentication layer ahead of this middleware.

## Apache Camel: token presence is not token verification

In `org.apache.camel:camel-keycloak` 4.15.0 through 4.18.2 and 4.19.0 through 4.20.x, `KeycloakSecurityPolicy` verifies token signature, issuer, expiry, or introspection state only inside role or permission checks. Both `requiredRoles` and `requiredPermissions` default to empty in the documented basic setup. With those defaults and header token input enabled, any non-null bearer value passes the presence gate without cryptographic verification. Fixed releases are 4.18.3 and 4.21.0.

### Fake-token route matrix

Use a disposable Camel route whose only side effect is incrementing an in-memory counter.

| Policy/input | Expected secure result |
| --- | --- |
| no bearer value | reject |
| arbitrary non-JWT marker | reject |
| unsigned synthetic JWT with wrong issuer | reject |
| expired JWT signed by a lab key | reject |
| valid lab token | reach marker route |
| non-empty role requirement, wrong role | reject |

Capture whether the verifier or owned introspection stub was called, not only the final status. A positive finding proves **bearer presence -> empty role/permission branches skip all verification -> route executes**. Do not describe downstream RCE unless that exact protected route independently reaches a code-execution producer and explicit authorization permits proving it.

### Platform-HTTP JWT follow-up: iss/aud skipped when unset (GHSA-fpm2-m4qq-wghr / CVE-2026-66908)

In `org.apache.camel:camel-platform-http-main` 4.8.0 through 4.21.x, `JWTAuthenticationConfigurer.buildJwtOptions` returns `null` when **neither `jwtIssuer` nor `jwtAudience` is configured**, and the caller then skips `JWTAuthOptions.setJWTOptions` entirely. The Vert.x `JWTAuth` instance is built from the keystore alone, so inbound tokens are checked for **signature and expiry only**, `iss` and `aud` claims are never validated. The server starts normally with no warning; the component documentation presents signature/expiry checking as the default and issuer/audience as an optional extra. Both the application server and management server paths are affected. Fixed in 4.22.0.

Operator deltas from the matrix above:

- **Mint a lab-issued token with a *wrong* `iss` and `aud`** (signed by the trusted keystore key, unexpired). Positive: the route accepts it even though the documented claim checks are not enforced.
- **Mint a token for a *different service audience*** than the target route's intended scope. Positive: cross-audience token accepted.
- **Negative control on 4.22.0+**: the same two tokens must be rejected.
- Evidence: the `buildJwtOptions` return value / `setJWTOptions` call path, the accepted/declared claim set, and the route marker hit. Do not harvest real tokens; use synthetic lab-signed values only.

## `@fastify/static`: authorize and resolve the same canonical path

Two advisories cover distinct representation mismatches:

- through 10.1.0, non-leading `..` or `%2E%2E` can cause `find-my-way` to select the static catch-all rather than a guarded route; later file resolution collapses the segments ([GHSA-83w8-p2f5-377r](https://github.com/advisories/GHSA-83w8-p2f5-377r));
- through 10.1.1, `allowedPath` sees a pre-normalized pathname while file resolution collapses dot segments and duplicate slashes ([GHSA-8pvw-jcv7-9cmj](https://github.com/advisories/GHSA-8pvw-jcv7-9cmj)).

Use 10.1.2 or later as the fixed control for both.

### Synthetic static-root replay

1. Create a disposable static root with `public/allowed.txt` and `private/denied.txt`, both containing unique non-sensitive markers.
2. Protect `/private/*` with the application's actual route hook and independently deny `private/` in `allowedPath`.
3. Record the raw URL, router-selected handler, value passed to `allowedPath`, normalized send path, resolved file, hook decision, and response.
4. Test a small matrix: canonical paths, duplicate slashes, `/./`, `public/../private/`, and both literal and encoded non-leading dot-dot segments.
5. A valid bypass returns only the synthetic denied marker after the policy evaluated a different representation. Stop there; do not enumerate a real static root.
6. Repeat on 10.1.2. The policy and resolver must bind to the same canonical path.

Keep the two causes separate in reports: catch-all route selection bypasses route-family middleware, while pre-normalized `allowedPath` input bypasses a plugin callback.

## cel-go: JSON skip tags are not CEL policy

In `github.com/google/cel-go` 0.22.0 through 0.28.1, `ext.NativeTypes(ext.ParseStructTag("json"))` registers a Go field tagged `json:"-"` under the literal CEL name `"-"`. Because native objects support index access, an untrusted expression can read it using a dynamic lookup. Native type registration also recursively discovers nested struct types. Version 0.29.0 supplies the fixed control.

### Canary-field harness

1. Confirm untrusted users can submit CEL expressions and that the host registers native Go structs with `NativeTypes(ParseStructTag("json"))`.
2. Define a test struct with a public marker and a private canary tagged `json:"-"`; include one nested synthetic type.
3. Verify standard JSON serialization omits the canary.
4. Enumerate CEL-visible field names and evaluate ordinary field access plus dynamic index access to the literal skip-tag name. Log only marker values.
5. Repeat conversion to a JSON-like CEL value, because the same name mapping can expose the field during conversion.
6. Repeat on 0.29.0 and with an explicit allowlisted CEL object schema.

The finding is **developer-intended JSON omission -> native-type adapter registers the skipped field -> untrusted CEL expression reads the canary**. Do not infer access to every application secret: identify the exact struct, expression channel, and restricted field reachable in the deployed integration.

## Reporting checklist

Include the package and version, exact wrapper/API in use, attacker-controlled input source, raw and canonical representations, route or field actually reached, marker-only evidence, and patched negative control. Distinguish a library behavior from application impact: each result needs a reachable protected handler, static marker, or private canary field.