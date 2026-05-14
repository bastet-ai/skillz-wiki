# Authlib cache-backed OAuth state CSRF boundary

**Signal:** GitHub Security Advisories updated **2026-05-14** for [GHSA-jj8c-mmj3-mmgv](https://github.com/advisories/GHSA-jj8c-mmj3-mmgv) / CVE-2026-41425. `authlib < 1.6.11` can lose OAuth state-to-browser binding when integrations store authorization state in a shared cache instead of the user's session.

## Why it matters

OAuth `state` is an anti-CSRF boundary, not just a lookup key. In affected Authlib integrations, callback handlers read the `state` value from the callback URL and fetched matching data from cache without proving that the same browser/session initiated the flow. An attacker could start an OAuth flow, stop before following the callback, and send that callback URL to a victim. If the victim completed it, the application could link the attacker's upstream account or attacker-controlled authorization context to the victim's local account.

The issue was reported against the Starlette client, but the advisory notes that other Authlib integrations using the cache-backed state feature share the pattern.

## Operator triage

1. Upgrade `authlib` to **1.6.11** or later anywhere OAuth clients use `cache=` for authorization state.
2. Inventory Starlette/FastAPI/Flask/Django OAuth integrations and flag flows that use a server-side cache for `state`, nonce, PKCE verifier, or redirect data.
3. Review account-linking, billing, invoice, payment, and SSO logs for OAuth callbacks where the initiating IP/user-agent/session differs from the completing browser.
4. If account linking can change payment or identity ownership, require re-authentication and explicit confirmation before trusting existing linked accounts created during the exposure window.
5. Rotate or expire pending OAuth state entries after upgrade; keep state TTLs short and one-time-use.

## Durable controls

- Bind OAuth state to the browser session that initiated the flow: signed session cookie, server session ID, or another per-user secret that is not attacker-controlled.
- Treat cache entries as storage, not authentication. A cache hit for `state` must still be paired with a session-bound nonce/CSRF value.
- Use PKCE and nonce checks where available, but do not treat either as a replacement for user-session CSRF binding.
- Make OAuth callbacks one-time-use and fail closed on replay, missing session context, or mismatched redirect target.
- Add regression tests where attacker A initiates an OAuth flow and victim B attempts to complete A's callback URL; the callback must be rejected.

## Detection ideas

- Search for successful OAuth callbacks with no matching initiation event in the same app session.
- Look for many authorization starts by one account/IP followed by callback completions from unrelated users.
- Alert on account-link changes followed by sensitive actions such as invoice creation, payment-method changes, admin grants, or SSO provider swaps.

## References

- [GitHub Advisory GHSA-jj8c-mmj3-mmgv](https://github.com/advisories/GHSA-jj8c-mmj3-mmgv)
- [OAuth 2.0 RFC 6749 section 10.12: Cross-Site Request Forgery](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12)
