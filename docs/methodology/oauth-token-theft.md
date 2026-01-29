# OAuth Token Theft (Practical Attack Chains)

OAuth failures rarely look like “OAuth is broken.” They look like **small web bugs** (XSS, open redirects, weak CORS, mis-scoped cookies) that become **account takeover** once tokens are in play.

This page is a field guide for *how token theft actually happens* and how to test for it.

## Threat model: what counts as “token theft”

Attackers want any of the following:

- **Authorization Code** (pre-token; can be exchanged if redirect URI/PKCE are weak)
- **Access Token** (API access)
- **Refresh Token** (long-lived access)
- **ID Token** (identity claims; sometimes accepted as auth)

If you can steal a token, the game becomes:
- Can I **replay** it?
- Is it **bound** to the client/device?
- Is it **scoped** correctly?
- Can I **exchange** it for something better?

## Common real-world chains

### 1) XSS → token exfiltration
**Where the token lives** determines how serious XSS is:

- URL fragment (`#access_token=...`) — classic implicit flow leakage
- URL query (`?code=...`) — authorization code leakage
- browser storage (`localStorage`, `sessionStorage`) — common SPA pattern
- in-memory — still exfiltratable via XSS (e.g., intercepting fetch/XHR)

**Tests:**
- If you can run JS, try:
  - monkeypatch `fetch` / `XMLHttpRequest` to capture Authorization headers
  - read `localStorage`/`sessionStorage` keys that look like tokens/JWTs
  - scrape DOM for embedded tokens

### 2) Open redirect → code/token capture
If the OAuth redirect URI validation is weak, an attacker can:
- start an OAuth flow
- send user to auth
- bounce redirect to attacker-controlled domain

**Tests:**
- Try redirect URI manipulation:
  - subdomain confusion
  - path traversal / wildcard patterns
  - scheme confusion (`http` vs `https`)
  - query parameter injection

### 3) Edge controls / WAF behavior as part of the chain
Sometimes the “protection” becomes an oracle:
- WAF blocks one payload shape but not another
- CDN rewrites headers in inconsistent ways
- redirect chains change cookie domain/path behavior

**Tests:**
- Compare behavior across:
  - different endpoints
  - different headers / encodings
  - different user agents
  - redirected vs non-redirected requests

## Investigator checklist

### Token storage & transport
- [ ] Are tokens ever present in URLs (fragment/query)?
- [ ] Do redirects leak referrers that contain sensitive params?
- [ ] Are tokens stored in localStorage/sessionStorage?
- [ ] Are tokens placed in cookies? If yes:
  - [ ] `HttpOnly` set?
  - [ ] `Secure` set?
  - [ ] `SameSite` appropriate?
  - [ ] cookie `Domain` / `Path` minimized?

### OAuth flow hardening
- [ ] Authorization code flow (with PKCE for public clients)
- [ ] PKCE is **mandatory** and enforced server-side
- [ ] `state` is validated (anti-CSRF)
- [ ] Redirect URIs are exact matches (no wildcards unless unavoidable)
- [ ] Code is single-use + short TTL
- [ ] Tokens are audience-bound (`aud`) and validated

### Backend acceptance
- [ ] API never accepts an ID token in place of an access token
- [ ] Token signature + issuer + audience validated
- [ ] Revocation / rotation behavior defined

## Defensive guidance (what to recommend)

- Prefer **Authorization Code + PKCE** for SPAs and mobile.
- Avoid tokens in URLs.
- Avoid long-lived refresh tokens in browsers.
- Use **HttpOnly cookies** for sessions when feasible.
- Bind tokens (DPoP / mTLS) where risk profile justifies.

## Source / inspiration

- Curated from common bug bounty write-ups and incident patterns.
- See also the Disclosed issue discussing an XSS → OAuth token theft chain.
