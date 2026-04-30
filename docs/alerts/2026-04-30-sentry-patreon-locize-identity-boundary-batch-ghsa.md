# Sentry SAML, Patreon auth, and locize message-origin identity boundary batch (GHSA-rcmw-7mc7-3rj7 / GHSA-f6qq-3m3h-4g42 / GHSA-w937-fg2h-xhq2)

**Signal:** GitHub Security Advisories updated **2026-04-30**. Three identity-boundary bugs landed together: Sentry SAML account takeover, go-pkgz/auth Patreon account collapse, and locize InContext Editor cross-origin DOM XSS / handler hijack.

## What it is
- `GHSA-rcmw-7mc7-3rj7`: self-hosted Sentry `21.12.0` through `26.4.0` can allow account takeover through SAML SSO identity linking when the instance has multiple organizations and an attacker can configure SSO for another organization. Fixed in `26.4.1`.
- `GHSA-f6qq-3m3h-4g42`: `github.com/go-pkgz/auth` Patreon provider maps every Patreon login to the same local user ID, causing cross-user impersonation or subscription/identity leakage. Fixed in `1.25.2` and `v2.1.2`.
- `GHSA-w937-fg2h-xhq2`: npm `locize` before `4.0.21` trusts `postMessage` sender fields instead of browser-enforced `event.origin`, enabling cross-origin DOM XSS and editor handler hijack in locize-enabled pages.

References:

- <https://github.com/advisories/GHSA-rcmw-7mc7-3rj7>
- <https://github.com/advisories/GHSA-f6qq-3m3h-4g42>
- <https://github.com/advisories/GHSA-w937-fg2h-xhq2>

## Triage
1. Inventory self-hosted Sentry instances and check `SENTRY_SINGLE_ORGANIZATION`, SAML SSO use, and organization-admin rights.
2. Search Go services for `github.com/go-pkgz/auth` Patreon provider and confirm whether `token.User.ID` is used as the stable account key.
3. Search browser apps for `locize` InContext Editor usage, especially pages that can be embedded, previewed, or opened by untrusted users.
4. Prioritize identity surfaces where an attacker can choose an IdP, OAuth provider account, iframe parent, or translation-editor frame.

## Mitigation
- Upgrade Sentry to `26.4.1+`, go-pkgz/auth to `1.25.2+` / `v2.1.2+`, and locize to `4.0.21+`.
- Lock down who can configure SAML/OIDC providers and require domain/email-claim ownership checks before identity linking.
- Derive local user IDs from provider-stable, provider-scoped identifiers; never use empty/default user objects as identity keys.
- For `postMessage`, require an exact origin allowlist and validate message schema before dispatching privileged handlers.
- Disable embedding of sensitive app pages unless explicitly required (`frame-ancestors` / CSP).

## Detection ideas
- Sentry: hunt new SAML providers, identity-linking events, or logins where a user joins an organization they did not belong to before.
- Patreon auth: look for multiple distinct Patreon accounts mapped to one local user ID or sudden subscription/role changes.
- locize: review browser error logs, CSP reports, and translation-editor actions initiated from unexpected origins or iframes.

## Durable lesson
Identity code has three separate trust anchors: issuer, subject, and transport origin. Treat any default ID, unsigned browser message field, or tenant-controlled IdP setting as attacker input until it is bound to an explicit allowlist and verified claim.
