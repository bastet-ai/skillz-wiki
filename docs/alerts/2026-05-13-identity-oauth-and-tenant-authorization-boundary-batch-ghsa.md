# Identity, OAuth, and tenant-authorization boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because each issue breaks an identity or tenancy assumption at a security boundary: JWTs accepted without signature verification, OAuth/OIDC error handling redirecting before redirect-URI validation, and cloud-control-plane APIs authorizing tokens without checking role, scope, or target-resource ownership.

## Advisories covered

- **OpenLearnX JWT signature verification disabled** — [GHSA-223g-f5mq-gw33](https://github.com/advisories/GHSA-223g-f5mq-gw33), CVE-2026-44720: `openlearnx < 2.0.4` could allow account takeover when JWT signature verification was disabled or bypassed. Fixed in `2.0.4`.
- **Authlib OIDC Implicit/Hybrid open redirect** — [GHSA-r95x-qfjj-fjj2](https://github.com/advisories/GHSA-r95x-qfjj-fjj2), CVE-2026-44681: OIDC Implicit and Hybrid grants raised a scope error before validating `redirect_uri`, allowing unauthenticated redirects from the authorization server to attacker-controlled URLs. Fixed in `authlib 1.6.12` and `1.7.1`.
- **OpenStack Cyborg default allow policy** — [GHSA-mm7j-mhhj-hj36](https://github.com/advisories/GHSA-mm7j-mhhj-hj36), CVE-2026-40213: `openstack-cyborg < 16.0.1` used `rule:allow` (`@`) as the default policy for multiple API endpoints, letting any valid Keystone token reach actions that should require roles, project membership, or scope.
- **OpenStack Cyborg ARQ project ownership bypass** — [GHSA-mmpc-xjxr-5hf8](https://github.com/advisories/GHSA-mmpc-xjxr-5hf8), CVE-2026-40214: Accelerator Request APIs did not populate/filter project ownership and could let authenticated non-admin users affect ARQs tied to other projects. Fixed in `16.0.1`.

## Operator triage

1. Upgrade OpenLearnX to `2.0.4`; invalidate active sessions and rotate JWT signing material if unsigned or attacker-forged tokens may have been accepted.
2. For Authlib-based OIDC providers, upgrade to `1.6.12` or `1.7.1`. If Implicit/Hybrid flows are unnecessary, unregister those grants; RFC 9700 already pushes deployments away from Implicit flow.
3. Search authorization-server logs for `/authorize` requests using Implicit/Hybrid `response_type` values, missing `openid` scope, and unregistered or suspicious `redirect_uri` domains.
4. Upgrade OpenStack Cyborg to `16.0.1`, then audit policy overrides for any leftover `rule:allow`/`@` defaults on mutating or node-affecting endpoints.
5. In OpenStack environments, review recent Cyborg ARQ actions for cross-project deletes, binds, unbinds, or accelerator operations that do not match the requesting project.

## Durable controls

- JWT verification failures must be fail-closed and observable. Unit tests should reject `alg:none`, missing keys, wrong issuer/audience, expired tokens, and invalid signatures.
- OAuth/OIDC error paths must never redirect to a URI until the client and redirect URI are validated against registration state.
- Error handling should preserve `state` only after redirect validation; otherwise return a local `400` page without a `Location` header.
- Cloud control planes should treat “has any token” as authentication only, never authorization. Every mutating API needs explicit role, scope, and target-resource ownership checks.
- Tenant-owned resources need durable tenant IDs at creation time and query-level tenant filtering; do not infer ownership by comparing request values to themselves.
