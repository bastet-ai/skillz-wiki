# JWT algorithm-confusion testing

Source seeds: the 2026-07-16 GitHub Security Advisory update for [`GHSA-9gxv-x7rp-r2hc`](https://github.com/advisories/GHSA-9gxv-x7rp-r2hc), covering `gree/jose` treating `none` as a valid token algorithm before `2.2.1`; and [`GHSA-fr32-wcm4-p6hf` / CVE-2026-13089](https://github.com/advisories/GHSA-fr32-wcm4-p6hf), where Perl OIDC::Lite's unpinned verification path derives its accepted-algorithm list from the ID Token header. The broader JWT library class was described by Auth0's 2015 research on algorithm confusion.

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

## October 1 addition: the PyJWT 2.13.0 guard-encoding sweep — every guard is a recognizer, and recognizers have encodings

Seven advisories published 2026-09-29 against **PyJWT 2.13.0** (with [GHSA-gvp8-978c-rx2q](https://github.com/advisories/GHSA-gvp8-978c-rx2q), [GHSA-ffc3-869f-jxw9](https://github.com/advisories/GHSA-ffc3-869f-jxw9), [GHSA-9j54-fg26-wv3r](https://github.com/advisories/GHSA-9j54-fg26-wv3r), [GHSA-w2cx-738m-mc7w](https://github.com/advisories/GHSA-w2cx-738m-mc7w), [GHSA-p4g4-x82p-q773](https://github.com/advisories/GHSA-p4g4-x82p-q773), [GHSA-r6x4-923q-g947](https://github.com/advisories/GHSA-r6x4-923q-g947), [GHSA-9v7f-9g4p-ffgj](https://github.com/advisories/GHSA-9v7f-9g4p-ffgj)) turn this workflow's core heuristic into a systematic sweep: **when a library fixes an algorithm/key-confusion bug with a *recognizer* (regex/marker/prefix detection of "is this an asymmetric key?"), the fix inherits every encoding the recognizer fails to see.** The 2022 CVE-2022-29217 guard (`is_pem_format()` / `is_ssh_key()` text markers) was re-bypassed four independent ways in the same release:

- **DER encoding** (p4g4): a public RSA/EC key in binary DER contains neither `-----BEGIN` nor `ssh-` — passes the marker check, used as HMAC secret, HS\* forgery with public material.
- **Container wrapping** (w2cx): public JWK wrapped in JWKS `{"keys":[...]}`, nested arrays, or any container without a top-level `kty` — JWK detection misses it, key accepted as HMAC secret.
- **Whitespace/line-ending mutation** (ffc3, critical): marker-adjacent indentation, CR-only line endings, or single-line PEM folds (all natural outcomes of YAML/JSON block scalars, single-line env vars, config CR/LF round-trips) defeat the `is_pem_format` regex while `cryptography`'s loader still accepts the key.
- **BOM prefix** (r6x4): `bytes.lstrip()` strips ASCII whitespace only — a UTF-8 BOM (`\xef\xbb\xbf`) before `{` defeats the JWK-shape check.
- **Path asymmetry** (9j54): the empty-key rejection lives in `HMACAlgorithm.prepare_key` on the raw str/bytes path; the `PyJWK`/`PyJWKSet` path (`{"kty":"oct","k":""}` → `b""`) skips it → attacker computes `HMAC-SHA256(b"", ...)` offline and forges arbitrary claims.

Two more axes beyond key parsing: **shared-mutable-state verification bypass** (gvp8, a regression of a 2022 fix): `decode()` mutates a caller-supplied `options` dict in place; reuse the dict across calls and a later `verify_signature=True` call silently inherits `verify_exp=False` leftovers — expired/wrong-aud/wrong-iss tokens accepted. The audit question generalizes to every wrapper library: *does the verifier mutate config you share?* And **JWKS redirect trust** (9v7f): `PyJWKClient` followed redirects unvalidated — a compromised/attacker-influenced JWKS endpoint redirects to attacker key material, with caller headers leaked to the redirect target.

Operator translation: on any token verifier, enumerate the **guard's input grammar** and test one representative of every encoding the parser accepts but the recognizer might not: PEM vs DER vs OpenSSH vs JWK vs JWKS-container vs nested; leading BOM/indent/CR/CRLF/single-line; empty vs whitespace key; and run each shape through *every* key-supply path the library exposes (raw key, PyJWK, JWKS client, framework adapter) — path asymmetry is where the marker guards hide. Check verifier-side config objects for cross-call mutation by making a lenient call before the strict call in your harness. Proofs stay with disposable keys and canary claims.

## Reporting heuristic

Frame findings as a failed binding, not as generic JWT weakness:

- **Header-selected algorithm -> verifier accepts unsigned token -> canary claim changes route authorization.**
- **Asymmetric public key reused as HMAC secret -> attacker signs token with public material -> API trusts altered subject/role.**
- **Untrusted `kid`/JWKS selector -> verifier fetches attacker-controlled key -> token accepted for wrong tenant.**
- **Token-purpose drift -> reset/ID/access token accepted by another route family -> disposable account canary crosses boundary.**

Include library name/version when known, verification code or configuration snippets when provided by the program, the mutated header/payload with tokens redacted, negative controls, and the exact low-impact route decision observed.

For wrappers such as the affected OIDC::Lite path, instrument the algorithm list handed to the lower-level decoder. Evidence that an attacker-controlled `alg` becomes the verifier's own allowlist is stronger and more precise than a parser-only result. Compare the unpinned call, key-only call, explicitly pinned call, and patched implementation with one disposable keypair and canary subject.

## Safety boundaries

- Do not brute-force HMAC secrets, attack real signing keys, or publish reusable live tokens.
- Do not use customer IDs, production admin subjects, or real email/phone claims as canaries.
- Do not combine JWT bypass proof with data extraction; a route/marker decision table is enough.
- Do not probe arbitrary JWKS URLs or metadata services through a target verifier. Use owned callback domains only.
