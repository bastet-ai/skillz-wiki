# AVideo platform SSRF, auth, and secret-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because AVideo shows the same platform failure from several angles: optional plugin endpoints, webhook handlers, mobile redirects, notification features, and socket relays all need the same authorization, SSRF, secret, and render boundaries as core routes.

## Advisories covered

- **Sensitive information exposure and missing authorization** — [GHSA-xr49-f4rh-qcjf](https://github.com/advisories/GHSA-xr49-f4rh-qcjf): `wwbn/avideo <= 29.0` exposed privileged data without the expected access check.
- **Core SSRF guard bypass** — [GHSA-2hch-c97c-g99x](https://github.com/advisories/GHSA-2hch-c97c-g99x): `isSSRFSafeURL()` could be bypassed with redirects and DNS rebinding.
- **YPTWallet blind SSRF** — [GHSA-wp38-whx3-xffh](https://github.com/advisories/GHSA-wp38-whx3-xffh): donation webhook handling missed the SSRF guard and followed redirects.
- **PayPalYPT IDOR** — [GHSA-958h-qp3x-q4gj](https://github.com/advisories/GHSA-958h-qp3x-q4gj): authenticated users could cancel arbitrary PayPal subscription agreements.
- **Unauthenticated user enumeration** — [GHSA-6rvw-7p8v-mjfq](https://github.com/advisories/GHSA-6rvw-7p8v-mjfq): `objects/users.json.php` exposed user listing paths via `isCompany`.
- **Unauthenticated platform email sending** — [GHSA-5hgj-7gm9-cff5](https://github.com/advisories/GHSA-5hgj-7gm9-cff5): `sendEmail.json.php` could send phishing mail from the legitimate site identity.
- **Meet reflected XSS** — [GHSA-mm5f-8q57-4fc4](https://github.com/advisories/GHSA-mm5f-8q57-4fc4): unescaped `user` and `pass` parameters reached a JavaScript string literal.
- **Profile-photo CSRF** — [GHSA-jw8g-5j46-44rp](https://github.com/advisories/GHSA-jw8g-5j46-44rp): cross-origin requests could overwrite authenticated users' profile photos.
- **Subscriber HTML-injection phishing** — [GHSA-g9cm-rxp7-6gv5](https://github.com/advisories/GHSA-g9cm-rxp7-6gv5): `notifySubscribers.json.php` allowed platform-branded HTML injection.
- **MobileManager OAuth password-hash leak** — [GHSA-5w8w-26ch-v5cw](https://github.com/advisories/GHSA-5w8w-26ch-v5cw): password hashes leaked through redirect URLs.
- **CloneSite key disclosure** — [GHSA-qm9p-p5pw-jrx2](https://github.com/advisories/GHSA-qm9p-p5pw-jrx2): unauthenticated error echo exposed `myKey`, enabling cross-site DB dump of the configured clone server.
- **YPTSocket incomplete-fix relay bypass** — [GHSA-ghcv-22jf-vfxm](https://github.com/advisories/GHSA-ghcv-22jf-vfxm): `$msg['json']` relay bypassed `autoEvalCodeOnHTML` stripping for unauthenticated cross-user JavaScript execution.

## Operator triage

1. Treat all public AVideo instances at or below `29.0` as exposed until vendor fixes or compensating controls are confirmed.
2. Disable or restrict PayPalYPT, YPTWallet donation webhooks, CloneSite, MobileManager OAuth, Meet iframe, socket relay, and subscriber notification endpoints if they are not business-critical.
3. Review outbound HTTP logs for redirect chains, loopback/private IP destinations, and repeated webhook probes from unauthenticated clients.
4. Rotate clone keys, OAuth/client secrets, payment-webhook secrets, and any credentials present in logs or redirect URLs.
5. Search mail logs for unexpected platform-branded subscriber or arbitrary recipient messages.

## Durable controls

- Plugin routes inherit the same route middleware, CSRF policy, and object ownership checks as core account routes.
- SSRF validation must resolve, connect, and re-resolve through a single guarded client that blocks redirects to private, loopback, link-local, metadata, and DNS-rebound targets.
- Never place password hashes, clone keys, OAuth secrets, or webhook secrets in URLs; use short-lived opaque handles stored server-side.
- Render email, iframe, socket, and notification payloads through context-specific encoders; do not rely on post-hoc HTML stripping.
- Add regression tests that exercise optional plugins, not only default install paths.
