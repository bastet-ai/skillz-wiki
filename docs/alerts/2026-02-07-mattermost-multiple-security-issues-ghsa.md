# 2026-02-07 — Mattermost Server: multiple security issues (GHSAs)

GitHub advisories:

- <https://github.com/advisories/GHSA-42x9-rr3c-gr59> (XSS through channel headers)
- <https://github.com/advisories/GHSA-m462-mqw4-2c8m> (X.509 improper certificate validation)
- <https://github.com/advisories/GHSA-hxxj-8phw-74vw> (server restarts may provide attackers with API access)
- <https://github.com/advisories/GHSA-x33g-375j-jhf7> (improper authorization for integration requests)
- <https://github.com/advisories/GHSA-jxc4-w54c-qv5r> (weak hashing for OAuth/email verification/invites)
- <https://github.com/advisories/GHSA-5ghq-28r7-qwfj> (SAML certificate path not restricted for system admins)

## Summary

Mattermost Server has a cluster of newly-published advisories covering:

- **Web layer issues** (XSS)
- **Authorization / access control** problems (integration requests; restart-related behavior)
- **Cryptography / identity verification** problems (certificate validation; weak token hashing)
- **SAML configuration** hardening gaps (certificate path restriction)

Taken together, the durable guidance is:

- keep **chat/collaboration platforms** on a tight patch cadence
- treat them as **high-value infrastructure** (SSO + tokens + web UI + integrations)
- plan for **token/session rotation** when token-generation or hashing is implicated

## Who is at risk

You should treat yourself as potentially impacted if:

- you run **Mattermost Server** and allow internet / broad-network access, or
- you rely on Mattermost **SSO (SAML/OAuth)**, or
- you use **integrations / webhooks / bots**, or
- you have many users and depend on the web UI (XSS blast radius).

## Recommended actions

1. **Upgrade Mattermost Server**
   - Apply the vendor’s fixed versions as indicated in each GHSA.

2. **Rotate sensitive tokens (if applicable in your environment)**
   - If your deployment could have been impacted by weak hashing for verification/invite/OAuth tokens, plan to:
     - invalidate old invite / verification links,
     - rotate relevant secrets/keys, and
     - force re-auth where reasonable.

3. **SSO hardening**
   - Review SAML settings; restrict certificate paths / admin-only operations per the advisory guidance.
   - Ensure your certificate validation behavior matches your threat model (no silent fallbacks).

4. **Web security mitigations**
   - If you must delay patching:
     - reduce exposure (VPN / allowlist / WAF where feasible),
     - review CSP / security headers,
     - monitor for suspicious admin actions and integration creations.

## Detection / hunt ideas

- Look for new/changed **integrations**, webhooks, or bot tokens.
- Review admin audit logs around **server restarts** and any subsequent anomalous API usage.
- Hunt for signs of **stored XSS**: unusual channel header content, sudden admin actions following page views.
