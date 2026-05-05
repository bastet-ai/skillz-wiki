# Grav and AVideo web-platform boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because CMS and media-platform control planes keep mixing low-trust browser input with admin, filesystem, email, calendar, payment, SSRF, and code-execution paths. Treat plugin installs, account services, scheduler exports, webhook callbacks, and admin rendering as separate trust boundaries, not as one generic 'authenticated web app' surface.

## Advisories covered

- **Grav multi-vector RCE** — [GHSA-vj3m-2g9h-vm4p](https://github.com/advisories/GHSA-vj3m-2g9h-vm4p): unsafe unserialize paths, command injection in git clone, and an SSTI blocklist bypass create multiple remote-code-execution routes.
- **Grav privilege escalation** — [GHSA-pxm6-mhxr-q4mj](https://github.com/advisories/GHSA-pxm6-mhxr-q4mj): missing server-side validation of groups/access can grant higher privileges.
- **Grav FormFlash** — [GHSA-hmcx-ch82-3fv2](https://github.com/advisories/GHSA-hmcx-ch82-3fv2): unauthenticated path traversal and arbitrary file write.
- **Grav file cache** — [GHSA-gwfr-jfjf-92vv](https://github.com/advisories/GHSA-gwfr-jfjf-92vv): insecure deserialization in file-cache handling.
- **Grav account overwrite logic** — [GHSA-rr73-568v-28f8](https://github.com/advisories/GHSA-rr73-568v-28f8): administrative account disruption and privilege de-escalation through user overwrite logic.
- **Grav accounts service** — [GHSA-3f29-pqwf-v4j4](https://github.com/advisories/GHSA-3f29-pqwf-v4j4): sensitive information disclosure through accounts-service bypass.
- **Grav SVG upload** — [GHSA-3446-6mgw-f79p](https://github.com/advisories/GHSA-3446-6mgw-f79p): XXE through uploaded SVG content.
- **Grav stored XSS tag injection** — [GHSA-w8cg-7jcj-4vv2](https://github.com/advisories/GHSA-w8cg-7jcj-4vv2): stored XSS via tag injection.
- **Grav publisher stored XSS** — [GHSA-9695-8fr9-hw5q](https://github.com/advisories/GHSA-9695-8fr9-hw5q): publisher-level stored XSS via unquoted event attributes.
- **Grav taxonomy XSS** — [GHSA-c2q3-p4jr-c55f](https://github.com/advisories/GHSA-c2q3-p4jr-c55f): admin-panel XSS through taxonomy field values.
- **Grav Markdown media XSS** — [GHSA-r7fx-8g49-7hhr](https://github.com/advisories/GHSA-r7fx-8g49-7hhr): stored XSS through Markdown media `attribute()` handling.
- **AVideo sensitive data / missing authorization** — [GHSA-xr49-f4rh-qcjf](https://github.com/advisories/GHSA-xr49-f4rh-qcjf): unauthorized users can reach sensitive information due to missing authorization.
- **AVideo SSRF protection bypass** — [GHSA-2hch-c97c-g99x](https://github.com/advisories/GHSA-2hch-c97c-g99x): HTTP redirects and DNS rebinding bypass `isSSRFSafeURL()`.
- **AVideo wallet webhook blind SSRF** — [GHSA-wp38-whx3-xffh](https://github.com/advisories/GHSA-wp38-whx3-xffh): YPTWallet donation webhook misses `isSSRFSafeURL()` and follows redirects.
- **AVideo PayPalYPT IDOR** — [GHSA-958h-qp3x-q4gj](https://github.com/advisories/GHSA-958h-qp3x-q4gj): authenticated users can cancel arbitrary PayPal subscription agreements.
- **AVideo scheduler CRLF/ICS injection** — [GHSA-mwgh-92m2-wvhv](https://github.com/advisories/GHSA-mwgh-92m2-wvhv): unauthenticated calendar export injection enables event spoofing.
- **AVideo user enumeration** — [GHSA-6rvw-7p8v-mjfq](https://github.com/advisories/GHSA-6rvw-7p8v-mjfq): `isCompany` bypass exposes admin-only user listing behavior.
- **AVideo arbitrary email sending** — [GHSA-5hgj-7gm9-cff5](https://github.com/advisories/GHSA-5hgj-7gm9-cff5): unauthenticated endpoint can send phishing mail from the legitimate site identity.
- **Rails per-form CSRF token forgery** — [GHSA-jp5v-5gx4-jmj9](https://github.com/advisories/GHSA-jp5v-5gx4-jmj9): older Rails advisory update for forged per-form CSRF tokens.

## Operator triage

1. Patch or disable Grav admin/plugin/file-cache/FormFlash/account-service paths and AVideo scheduler, wallet, PayPal, email, and URL-fetch endpoints until fixed.
2. Hunt for new Grav plugins/themes, modified user/account files, unexpected cache objects, SVG uploads, `git clone` activity, SSTI payloads, and files written outside expected media paths.
3. Retest AVideo SSRF defenses with redirects, DNS rebinding, IPv6/IPv4-mapped loopback, link-local, cloud metadata, and private ranges; verify the final destination on every hop.
4. Review payment and subscription audit logs for cross-account cancellation attempts and scheduler/email endpoints for phishing or calendar spoofing payloads.
5. Treat successful Grav RCE, arbitrary write, or unsafe deserialization as host compromise and rotate admin/API/database/mail/payment secrets from a clean workstation.

## Durable controls

- CMS admin features need per-action server-side authorization, not client-side or role-name assumptions.
- Plugin/theme/archive installs must run in a non-privileged worker with canonical extraction roots, no symlinks, strict extension checks, and post-write verification.
- URL fetch helpers should use positive egress allowlists and re-resolve/classify every redirect hop immediately before connect.
- Calendar, email, and header-generating endpoints must reject CR/LF and encode fields by target format, not by generic HTML escaping.
- Stored admin-render surfaces need context-specific output encoding, including tags, taxonomy fields, Markdown media attributes, event attributes, and account-service data.
