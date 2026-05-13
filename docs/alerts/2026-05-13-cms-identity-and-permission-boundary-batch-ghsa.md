# CMS, identity, and permission-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because the advisories repeat the same failure mode across CMS, SaaS-auth, and admin surfaces: UI-visible roles, object IDs, forwarded headers, and “already authenticated” checks were treated as sufficient authorization. The result is privilege escalation, content overwrite, API data disclosure, account takeover, and destructive importer access.

## Advisories covered

- **Grav CMS / plugins** — [GHSA-pxm6-mhxr-q4mj](https://github.com/advisories/GHSA-pxm6-mhxr-q4mj), [GHSA-w48r-jppp-rcfw](https://github.com/advisories/GHSA-w48r-jppp-rcfw), [GHSA-r945-h4vm-h736](https://github.com/advisories/GHSA-r945-h4vm-h736), [GHSA-hmcx-ch82-3fv2](https://github.com/advisories/GHSA-hmcx-ch82-3fv2), [GHSA-w4rc-p66m-x6qq](https://github.com/advisories/GHSA-w4rc-p66m-x6qq), [GHSA-rr73-568v-28f8](https://github.com/advisories/GHSA-rr73-568v-28f8), [GHSA-3f29-pqwf-v4j4](https://github.com/advisories/GHSA-3f29-pqwf-v4j4), [GHSA-w8cg-7jcj-4vv2](https://github.com/advisories/GHSA-w8cg-7jcj-4vv2), [GHSA-9695-8fr9-hw5q](https://github.com/advisories/GHSA-9695-8fr9-hw5q), [GHSA-r7fx-8g49-7hhr](https://github.com/advisories/GHSA-r7fx-8g49-7hhr), [GHSA-c2q3-p4jr-c55f](https://github.com/advisories/GHSA-c2q3-p4jr-c55f): privilege escalation, plugin-upload RCE, API super-admin escalation, FormFlash traversal/write, anonymous content overwrite, admin-account disruption, account-service disclosure, and stored XSS. Upgrade Grav core to at least `2.0.0-beta.2`, Form plugin to `9.1.0`, and API plugin to `1.0.0-beta.15` where applicable.
- **Wagtail permission restrictions** — [GHSA-p5gm-92h4-6pv6](https://github.com/advisories/GHSA-p5gm-92h4-6pv6), [GHSA-pwm3-7fv4-g6xx](https://github.com/advisories/GHSA-pwm3-7fv4-g6xx), [GHSA-c4mr-889m-vgf6](https://github.com/advisories/GHSA-c4mr-889m-vgf6), [GHSA-c6wj-9vcj-75pj](https://github.com/advisories/GHSA-c6wj-9vcj-75pj): restricted documents/images API exposure plus form-submission deletion, page-history, and revision-compare permission gaps. Fixed in `7.0.7` and `7.3.2`.
- **Clerk authorization predicate bypass** — [GHSA-w24r-5266-9c3c](https://github.com/advisories/GHSA-w24r-5266-9c3c): combining organization, billing, or reverification checks could bypass authorization across many Clerk SDK packages. Upgrade all Clerk packages in lockstep to the fixed versions listed in the advisory.
- **phpVMS importer authorization bypass** — [GHSA-fv26-4939-62fh](https://github.com/advisories/GHSA-fv26-4939-62fh): unauthenticated `/importer` access could wipe the database. Fixed in `nabeel/phpvms 7.0.6`.
- **AzuraCast reset-host and media-upload boundaries** — [GHSA-gv7r-3mr9-h5x8](https://github.com/advisories/GHSA-gv7r-3mr9-h5x8), [GHSA-vp2f-cqqp-478j](https://github.com/advisories/GHSA-vp2f-cqqp-478j): untrusted `X-Forwarded-Host` enabled password-reset poisoning and `currentDirectory` traversal enabled media-upload RCE. Fixed in `0.23.6`.
- **Sentry SAML identity linking** — [GHSA-rcmw-7mc7-3rj7](https://github.com/advisories/GHSA-rcmw-7mc7-3rj7): improper SAML SSO authentication could link identities incorrectly. Fixed in `26.4.1`.
- **openvpn-auth-oauth2 fail-open client deny** — [GHSA-246w-jgmq-88fg](https://github.com/advisories/GHSA-246w-jgmq-88fg): returning `FUNC_SUCCESS` on `client-deny` allowed unauthenticated VPN access. Fixed in `1.27.3`.
- **Grafana public-dashboard datasource disclosure** — [GHSA-3q27-7qjq-p9c5](https://github.com/advisories/GHSA-3q27-7qjq-p9c5): public dashboards disclosed direct-mode datasources.

## Operator triage

1. Prioritize exposed admin panels, hosted CMS, VPN/OIDC gateways, and public dashboards before internal-only instances.
2. Upgrade affected packages, then invalidate sessions/tokens where auth, role, reset-link, or SAML/OIDC identity state may have been bypassed.
3. Search access logs for Grav plugin ZIP/direct-install actions, FormFlash writes, `/importer`, AzuraCast reset requests with unusual Host/X-Forwarded-Host values, Wagtail API enumeration, and Clerk endpoints that combine org/billing/reverification guards.
4. For destructive bugs, verify backups before upgrade and preserve evidence before cleanup.

## Durable controls

- Enforce authorization server-side on every mutating and sensitive-read endpoint; UI role state is only a hint.
- Treat `Host` and proxy headers as untrusted unless set by a trusted reverse proxy and validated against a configured external URL.
- File upload and plugin install paths need allowlisted extensions, archive root checks, symlink rejection, and execution disabled unless explicitly intended.
- Identity providers should fail closed: a deny result, missing group, failed reverification, or unrecognized SAML assertion must stop the request, not continue with partial success.
