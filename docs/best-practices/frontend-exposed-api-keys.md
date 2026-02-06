# Frontend-exposed API keys are not secrets

Some apps accidentally expose **long-lived API keys** in the browser (rendered into HTML, embedded into JavaScript bundles, or returned by an API used by the UI).

This is not “just an info leak”. It often becomes:

- **account takeover** (the key is effectively a password)
- **privilege escalation** (if the key is an admin/service key)
- **automation/abuse** (bulk operations via API)
- **persistent compromise** (because keys don’t naturally expire)

A recent example class: an administrative dashboard that renders each user’s **permanent API key** in page source on login, making it accessible to any script running in the browser context.

## Threat model (what can actually steal it)

If an API key is available in the browser, assume it can be accessed by:

- browser extensions (malicious or over-permissioned)
- XSS (stored or reflected)
- compromised third-party scripts / analytics tags
- “just-in-time” supply chain issues (CDN/script swap)
- any user with local access to the machine (shared workstation)
- session recording / RUM tooling (if it captures DOM/JS state)

**Rule:** if it can be read by JavaScript in the browser, treat it as **public**.

## Durable guidance

### 1) Don’t use long-lived API keys as a primary auth mechanism for humans
Prefer:

- normal interactive auth (password + MFA, SSO)
- short-lived access tokens (e.g., OAuth2 access tokens)
- session cookies with strong CSRF defenses

If you must use API keys, scope them to **service-to-service** or controlled automation use cases.

### 2) Never render secrets into HTML or JS bundles
Anti-patterns:

- server-side templating that injects a key into the page
- “config” endpoints that return `apiKey` to the frontend
- embedding a key at build time (bundled into a static SPA)

If the frontend needs to call your API, use **user-bound tokens** issued after auth, not a shared static key.

### 3) Use *short-lived* tokens and rotate aggressively
If a token must exist in the browser:

- make it **short-lived** (minutes, not weeks)
- issue via a secure session
- rotate automatically
- bind to context when possible (audience, client, device)

### 4) Scope and constrain credentials
For any key/token:

- least privilege scopes
- per-user or per-client issuance (no global “god key”)
- rate limits and anomaly detection
- explicit revocation support

### 5) Design admin pages so compromise isn’t catastrophic
Admin UIs are common XSS targets. Reduce blast radius:

- avoid displaying raw credentials
- if you need a “reveal” feature, treat it like a password reset:
  - re-auth prompt
  - step-up MFA
  - one-time display
  - audit logs

## Quick audit checks

- Search your HTML/JS for `apiKey`, `token`, `Authorization`, `Bearer`.
- Open DevTools → Network → look for responses containing long-lived keys.
- Inspect admin pages for secrets in initial HTML payload.
- Verify tokens stored in `localStorage` aren’t long-lived (assume XSS reads them).

## If you found this in your app (response)

1) **Assume the key is compromised.**
2) Rotate/revoke affected keys and invalidate sessions.
3) Remove the exposure path.
4) Add monitoring for key use from unusual IPs/agents.
5) Postmortem: why was a long-lived secret ever present client-side?
