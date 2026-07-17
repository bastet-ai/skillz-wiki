# JWT algorithm-confusion testing

Source seed: 2026-07-16 GitHub Security Advisory update for [`GHSA-9gxv-x7rp-r2hc`](https://github.com/advisories/GHSA-9gxv-x7rp-r2hc), covering `gree/jose` treating `none` as a valid token algorithm before `2.2.1`, with the broader JWT library class described by Auth0's 2015 research on algorithm confusion.

This workflow is durable for operators because many applications still delegate token trust to library defaults, framework adapters, or hand-rolled middleware. The useful test is not "try `alg: none` everywhere"; it is to prove whether the application binds the expected algorithm, key type, issuer, audience, and token family before accepting attacker-controlled JOSE headers.

!!! warning "Authorized validation only"
    Test only applications, tenants, and accounts in scope. Use disposable users and synthetic claims. Never forge real customer/admin identities, reuse production signing material, or publish working tokens for live systems.

## When to use this

Use this workflow when you find any of the following during an authorized assessment:

- JWTs used for login sessions, passwordless links, API bearer auth, SSO callbacks, service-to-service auth, or invitation/reset flows.
- Public keys, JWKS URLs, `kid`-selected keys, or algorithm choices that appear to be influenced by token headers.
- Legacy PHP, Node, Python, Ruby, Java, or Go JWT wrappers with sparse verification code such as `decode(token, key)` and no explicit algorithm allowlist.
- Multiple token families accepted by the same endpoint, such as ID tokens, access tokens, refresh tokens, email verification tokens, and API tokens.
- Middleware that verifies signatures separately from route-level authorization, especially when downstream services trust already-decoded claims.

## Preconditions to record

Capture these facts before attempting mutations:

| Field | Evidence to collect |
| --- | --- |
| Token family | Session cookie, bearer token, reset link, API key exchange, SSO callback, etc. |
| Expected issuer/audience | `iss`, `aud`, client ID, realm, tenant, route family. |
| Expected algorithm | For example `RS256`, `ES256`, `HS256`; record whether the server explicitly pins it. |
| Verification key source | Static secret, public key, JWKS endpoint, per-tenant key, `kid` lookup, framework config. |
| Accepted claim boundary | Which claim changes matter: subject, role, tenant, email verification, scopes, org ID. |
| Negative controls | Expired token, wrong audience, wrong issuer, bad signature, unknown `kid`. |

## Safe mutation ladder

Work from harmless parser checks toward authorization-impact proof. Stop as soon as a scoped canary demonstrates the failed trust invariant.

1. **Baseline a disposable token.** Log in as a low-privilege test user and save a token whose claims contain only synthetic identifiers.
2. **Confirm normal failure controls.** Change one byte in the signature, set `exp` in the past, or alter `aud` to a canary value. A correctly configured verifier should reject each mutation.
3. **Check `alg: none` only with canary claims.** Re-encode the header as `{"alg":"none","typ":"JWT"}`, remove the signature, and change a harmless claim such as `name`, `nonce`, or a test-only `canary_role`. Do not claim privilege escalation unless a privileged route consumes the altered claim.
4. **Check asymmetric-to-HMAC confusion in a lab-safe way.** If the application expects `RS*` or `ES*`, create an `HS*` token using the known public key material as the HMAC secret. This should fail when algorithms and key types are pinned.
5. **Check `kid` and JWKS lookup separately.** Use unknown, traversal-looking, URL-looking, duplicate, and case-variant `kid` values only to prove key-selection behavior. Keep callback hosts owned and avoid probing internal metadata or filesystem paths.
6. **Check token-family mixups.** Present an ID token to an API endpoint, an access token to a session endpoint, or a reset-link token to a login endpoint using disposable accounts. The endpoint should bind issuer, audience, purpose, and subject type.
7. **Prove authorization impact with the smallest canary.** Prefer a route that returns `200` plus a synthetic marker for a disposable tenant or feature flag. Avoid destructive admin routes, account changes, or data export.

## Command patterns

Use `jwt_tool.py`, `python-jose`, `node-jose`, or a short local script to build malformed canaries. Keep tokens redacted in reports.

### `alg: none` canary shape

```json
// header
{"alg":"none","typ":"JWT"}
```

```json
// payload
{
  "iss": "https://auth.lab.example",
  "aud": "skillz-wiki-lab",
  "sub": "user-canary-lowpriv",
  "role": "canary-mutated",
  "iat": 1760000000,
  "exp": 1760003600
}
```

A vulnerable acceptance proof is a route decision that changes because of the unsigned canary claim, not merely a parser accepting the syntax.

### Algorithm allowlist decision table

| Mutation | Expected result | Evidence |
| --- | --- | --- |
| Valid low-privilege token | Accepted only as low privilege | Baseline response marker |
| Signature byte flipped | Rejected | HTTP status/error code |
| `alg: none`, no signature | Rejected | HTTP status/error code |
| `RS256` expected, `HS256` supplied | Rejected | HTTP status/error code |
| Wrong `aud` or token family | Rejected | HTTP status/error code |
| Unknown `kid` | Rejected without outbound/internal fetch side effects | App log or owned-callback absence |

## Reporting heuristic

Frame findings as a failed binding, not as generic JWT weakness:

- **Header-selected algorithm -> verifier accepts unsigned token -> canary claim changes route authorization.**
- **Asymmetric public key reused as HMAC secret -> attacker signs token with public material -> API trusts altered subject/role.**
- **Untrusted `kid`/JWKS selector -> verifier fetches attacker-controlled key -> token accepted for wrong tenant.**
- **Token-purpose drift -> reset/ID/access token accepted by another route family -> disposable account canary crosses boundary.**

Include library name/version when known, verification code or configuration snippets when provided by the program, the mutated header/payload with tokens redacted, negative controls, and the exact low-impact route decision observed.

## Safety boundaries

- Do not brute-force HMAC secrets, attack real signing keys, or publish reusable live tokens.
- Do not use customer IDs, production admin subjects, or real email/phone claims as canaries.
- Do not combine JWT bypass proof with data extraction; a route/marker decision table is enough.
- Do not probe arbitrary JWKS URLs or metadata services through a target verifier. Use owned callback domains only.
