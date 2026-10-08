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

## October 1 follow-up: pre-verification parse surfaces (PyJWT RecursionError, GHSA-42vr-xj54-vc7v)

[GHSA-42vr-xj54-vc7v](https://github.com/advisories/GHSA-42vr-xj54-vc7v) (PyJWT ≤2.14.0, fixed 2.15.0): `PyJWKClient.get_signing_key_from_jwt()` — step one of the documented JWKS flow — must parse the payload before signature verification, via a `verify_signature: False` decode whose `except` catches only `ValueError`. A **valid-JSON payload nested ~20,000 levels deep** makes `json.loads` raise `RecursionError`, an undocumented exception type that every documented error-handling pattern (`DecodeError`/`InvalidTokenError`/`PyJWTError`) misses. Unsigned, no-network, ~50 KB request repeatably 500s the auth handler or kills the worker. Generalizable axes for any token verifier: (1) **the pre-verification parse is an unauthenticated attack surface with its own failure modes** — deep-nesting, oversized, and weirdly-encoded payloads hit parsers *before* any crypto gate; (2) **exception-type escape is a DoS amplifier** — verifiers that catch their own library's error class but not the transport/parser's give callers no way to fail gracefully, so the finding is the raw exception reaching framework 500 paths; sweep which exception types exit the verification function, not just which claims are checked. Test battery (owned lab verifier only): deep-nested JSON payload token, `verify_signature: False` documented entry points, malformed-segment spellings; evidence = exception class + status/worker outcome decision table. Same wave: [GHSA-gvp8-978c-rx2q](https://github.com/advisories/GHSA-gvp8-978c-rx2q) confirms the `options`-dict in-place mutation from the Sept-30 encoding sweep **regressed in 2.13.x patching** — re-run the full guard-encoding battery on every point release of a security-fix train, a fixed range is not a fixed property.

## October 8 follow-up: the fast-jwt six-leg pack — the JS mirror of the recognizer rule plus three new verifier-invariant classes

Six advisories published 2026-10-08T22:01–22:10Z against **fast-jwt** (Node.js) turn the PyJWT guard-encoding sweep from the October 1 section into a cross-language invariant. Fixed bands: 6.3.0 for most legs, 6.3.1 for the falsy-key leg.

1. **Incomplete patch, same recognizer, new leading byte** ([GHSA-ww5h-9m49-7xx4](https://github.com/advisories/GHSA-ww5h-9m49-7xx4) / CVE-2026-107722, critical 9.8, 6.2.0–6.2.4): the fix for CVE-2026-34950 added `key.trim()` before the `^-----BEGIN` PEM detector — but `trim()` strips ECMAScript whitespace only. **Any non-whitespace leading byte** (`#` comment, control char, zero-width codepoint, HTTP-style header, PGP wrapper) keeps the PEM header off position 0, the anchored regex misses, and the key falls through to the HMAC path with the RSA public key as shared secret — the exact RSA→HS256 confusion the CVE fixed, re-enabled. This is the PyJWT BOM/indent leg (r6x4/ffc3) restated in JavaScript: a whitespace-only normalizer in front of a `^`-anchored marker regex is the most common incomplete-patch shape in JWT libraries. On any fix-differential check, replay the *class* battery (whitespace, BOM, comment prefix, control chars, container wrapping, DER) against the patched recognizer, not just today's spelling.
2. **Falsy key + explicit allowlist = signature verification skipped entirely** ([GHSA-8wpc-h4q6-8fxv](https://github.com/advisories/GHSA-8wpc-h4q6-8fxv) / CVE-2026-107720, 7.4, ≤6.3.0): `createVerifier({key: '' | null, algorithms: ['HS256']})` — the outer `typeof` check passes, the `if (key && ...)` guard skips `prepareKeyOrSecret` (where the empty-secret rejection lives), and the caller-supplied allowlist stays active. Result: **any attacker-presented JWT passes with no signing key at all**, regardless of algorithm. Config-misuse-as-auth-bypass: the empty-string default in a config/env plumbing layer plus "we pinned algorithms so we're safe" is the realistic deployment shape. Audit rule: for every verifier wrapper in your stack, check what happens when the key material resolves to `''`/`null` (missing env var, unset tenant key) — the guard that rejects empty secrets must run on *every* path, not one branch behind a truthiness check.
3. **Raw JWK/JWKS JSON treated as HMAC secret** ([GHSA-g3jj-5cmm-3hxx](https://github.com/advisories/GHSA-g3jj-5cmm-3hxx) / CVE-2026-107724, 7.4, =6.2.4): key classification is PEM-regex-or-HMAC — serialized public JWK/JWKS JSON isn't PEM, so it's used as the HMAC secret; an attacker who knows the public JSON forges arbitrary HS256 tokens. This is the PyJWT container-wrapping leg (w2cx) exactly: **the "is this asymmetric material?" recognizer must speak every serialization the loader speaks** (PEM, DER, OpenSSH, JWK, JWKS-container, nested). Fingerprint: grep the verifier's key-detection code for regex/string matching on key material; if the fallback branch is "assume secret", every non-matching encoding is a forgery path.
4. **Array payload silently skips every claim validator** ([GHSA-5hjw-83fp-phq9](https://github.com/advisories/GHSA-5hjw-83fp-phq9) / CVE-2026-107723, 8.1, ≤6.2.4): the decoder guards the *header* against arrays but the payload check is `typeof payload !== 'object'` — and `typeof [] === 'object'`. A validly-signed token with `["exp"...]`-style array payload passes with **only the signature enforced**: every `in`-test in the validator loop is false for arrays, so `exp`/`nbf`/`iss`/`aud`/`sub`/`jti` all skip while the verifier reports success. RFC 7519 §7.2 step-10 violation shipped as auth bypass. New class for the battery: **payload-shape mutation** — sign (or observe, in `none`-adjacent setups) an array/scalar payload and confirm the claim validators actually fire; the asymmetry between header validation and payload validation in the same decoder is the code smell to grep.
5. **`clockTolerance: Infinity` disables exp and nbf and poisons the verifier cache** ([GHSA-687g-22h4-j4w4](https://github.com/advisories/GHSA-687g-22h4-j4w4) / CVE-2026-107721, 5.9, ≤6.2.4): option validation rejects only negatives; the same primitive persists cached entries with infinite validity that outlive a later developer-removed Infinity config until LRU eviction. Config-sanity sweep: numeric security options that accept `Infinity`/`0`/negative silently disable the check they parameterize — check what validation the option parser does, and remember cache-state persistence means fixing the config does not fix live tokens.
6. **Verification cache accepts expired tokens when `iat` is absent** ([GHSA-x937-hj6v-793p](https://github.com/advisories/GHSA-x937-hj6v-793p) / CVE-2026-107719, medium, fixed 6.3.x): the cache deadline is derived from `iat` when present, else `now + tolerance + cacheTTL`, and the cache path returns the stored payload *before* `verifyToken` runs — so an expired token with no `iat` stays accepted until cache eviction. The invariant to test on every cached verifier: **a cached token must stop being accepted at exactly the time the uncached path rejects it.** Probe: forge/keep a valid token, let it expire, replay within cache TTL with and without `iat` — a behavior difference between cached and cold paths is the finding.

Operator rollup for verifier libraries (any language): the six legs map to three sweep families beyond algorithm confusion — (a) **key-classification grammar sweep** (legs 1,3: every encoding × every key-supply path), (b) **degenerate-config battery** (legs 2,5: empty key, null key, `Infinity`/zero tolerance, missing env-var defaults), and (c) **path-parity probes** (legs 4,6: cached vs cold, header vs payload shape checks — every duplicated validation path must agree). fast-jwt ships a working PoC for leg 1; reproduce in your own lab with disposable keys only.
