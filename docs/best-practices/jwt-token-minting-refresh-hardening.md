# JWT token minting / refresh endpoints: hardening

## Why this matters
If an attacker can **mint** (create) or **refresh** JSON Web Tokens (JWTs) without proving they already hold valid credentials, they effectively gain a universal “log in as anyone” capability.

This shows up in real systems when a “heartbeat”, “refresh”, or “session keepalive” endpoint:

- accepts a user/role in a request body and returns a signed JWT
- uses a weak/guessable signing key (or lets the client choose the algorithm)
- fails open when verification fails
- allows privilege escalation by trusting unvalidated claims (e.g., `role=admin`)

## Failure modes to look for
### 1) Refresh endpoint issues tokens based on **untrusted input**
Red flags:

- `POST /auth/refresh` returns a new JWT when given only a username / email / user id
- a “heartbeat” endpoint returns an admin token if `isAdmin: true` is in the payload

**Rule:** Token issuance must be tied to a server-side session state (or a refresh token) that is itself protected.

### 2) Refresh endpoint accepts *any* valid JWT and upgrades privileges
Common bug: the server verifies signature but then **re-mints** a token using request parameters (or DB fields) without re-checking authorization.

**Rule:** Refresh should preserve (or reduce) privilege — never increase it.

### 3) JWT verification weaknesses
Checklist:

- disallow `alg=none`
- ensure algorithm is fixed server-side (don’t accept algorithm from token header)
- verify signature before reading claims
- validate `iss`, `aud`, `exp`, `nbf` (and `iat` where relevant)
- reject tokens with missing required claims

### 4) Long-lived admin JWTs + “automation” APIs
If your product has administrative scripting/automation features:

- issuing a high-privilege JWT is equivalent to remote code execution (RCE) in many deployments
- a token refresh bug becomes a full-system compromise

**Rule:** Automation endpoints should require explicit, high-assurance auth and be segmented from normal user auth.

## Safer patterns
### Use refresh tokens (or server sessions), not “mint-by-API”
- Refresh token should be **random**, **unpredictable**, and stored/validated server-side.
- Bind refresh tokens to:
  - user id
  - device/session id
  - optional client properties (risk-based)
- Rotate refresh tokens on use and revoke on suspicion.

### Minimize JWT content and trust
- Treat JWT claims as *assertions* to be verified, not as a source of truth.
- Consider looking up user privileges server-side for sensitive operations.

### Separate admin auth from user auth
- Distinct keys for different token classes (admin vs user vs service)
- Distinct audiences and issuers
- Least privilege scopes

### Logging and monitoring
- alert on refresh/mint endpoints called without a known session
- detect sudden minting of many tokens, or minting for privileged roles
- rate limit token issuance endpoints

## Quick tests for auditors
- Can you obtain a JWT without first completing a login flow?
- Can you set `role=admin` (or similar claim) in any request and get an admin token back?
- Can you replay a stale/expired token at refresh to get a new valid token?
- Does `alg=none` or algorithm confusion work?

## References
- GitHub Advisory example: unauthenticated admin JWT minting via “heartbeat refresh” endpoint (class of issue)
