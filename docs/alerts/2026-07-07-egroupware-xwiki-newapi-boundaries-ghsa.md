# EGroupware template/mail, XWiki skin, and New API notification-boundary checks

Source: hourly offensive-security scan, 2026-07-07. Primary entries: GitHub Advisory Database [GHSA-h9qx-v5xp-ph8p](https://github.com/advisories/GHSA-h9qx-v5xp-ph8p) / CVE-2026-27823, [GHSA-8737-2x9g-xjj7](https://github.com/advisories/GHSA-8737-2x9g-xjj7) / CVE-2026-40187, [GHSA-c8m7-r2jv-rw63](https://github.com/advisories/GHSA-c8m7-r2jv-rw63) / CVE-2026-45016, [GHSA-qj4x-9g63-25g6](https://github.com/advisories/GHSA-qj4x-9g63-25g6) / CVE-2026-34151, [GHSA-6qcr-qxgr-m7fv](https://github.com/advisories/GHSA-6qcr-qxgr-m7fv) / CVE-2026-33655, and [GHSA-26v7-h57m-gh9m](https://github.com/advisories/GHSA-26v7-h57m-gh9m) / CVE-2026-44342.

These advisories are durable for operators because they expose repeatable boundary classes: application-controlled course/media metadata crossing into file writes, admin template uploads crossing into PHP evaluation, rich mail bodies crossing into server-side URI reads, Jetty/XWiki path decoding crossing out of the webapp resource root, notification URL hostnames crossing into server-originated fetches without resolved-IP filtering, and GET account-binding routes crossing browser navigation into account state changes. Keep proofs to disposable labs, marker-only files, synthetic notification callbacks, two-account binding tests, and route/version decision tables.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-h9qx-v5xp-ph8p](https://github.com/advisories/GHSA-h9qx-v5xp-ph8p) / CVE-2026-27823 | EGroupware `SmallPartMediaRecorder::ajax_upload()`, versions before `23.1.20260224` and `26.2.20260224` | user-controlled course participant role data can satisfy a teacher-style authorization check, then media path fields can steer writes; the published chain also relies on a file-read primitive | Test education/collaboration modules where request-supplied nested role/course objects are trusted before upload paths or import/export file selectors are reached. |
| [GHSA-8737-2x9g-xjj7](https://github.com/advisories/GHSA-8737-2x9g-xjj7) / CVE-2026-40187 | EGroupware eTemplate `.xet` upload to `/etemplates`, versions before `23.1.20260601` and `26.4.20260413` | admin-uploaded template widget attributes reach `Widget::expand_name()` and PHP `eval()` with incomplete escaping; non-hardened PHP builds may execute backtick command substitution | Test template marketplaces, VFS-backed overrides, and admin customization paths for template attributes that cross into PHP, Twig, shell, or expression evaluators. |
| [GHSA-c8m7-r2jv-rw63](https://github.com/advisories/GHSA-c8m7-r2jv-rw63) / CVE-2026-45016 | EGroupware mail compose inline-image processing, versions before `23.1.20260601` and `26.5.20260507` | HTML mail image URLs that do not start with `http` can be read with `file_get_contents()` and embedded as MIME parts | Test rich-text mail/editor importers for URI scheme confusion where `file://`, stream wrappers, or relative paths are treated as local attachments instead of rejected remote images. |
| [GHSA-qj4x-9g63-25g6](https://github.com/advisories/GHSA-qj4x-9g63-25g6) / CVE-2026-34151 | XWiki oldcore `/skin/` action on Jetty 12+, versions before `17.10.5` and `18.2.0` | double-encoded traversal can escape the expected skin/resource root and reach webapp or server-readable files | Test static-resource actions behind modern servlet containers for decode-order drift between application path checks and container resource resolution. |
| [GHSA-6qcr-qxgr-m7fv](https://github.com/advisories/GHSA-6qcr-qxgr-m7fv) / CVE-2026-33655 | QuantumNous New API notification URLs, versions before `0.12.0-alpha.1` | default SSRF protection applied domain checks without resolving hostnames and applying IP filters; authenticated users could configure Webhook/Bark/Gotify URLs that resolve to internal addresses | Test user-configurable notification/webhook destinations for hostname-to-IP validation gaps and DNS-rebinding-adjacent behavior. |
| [GHSA-26v7-h57m-gh9m](https://github.com/advisories/GHSA-26v7-h57m-gh9m) / CVE-2026-44342 | QuantumNous New API email and WeChat binding routes, versions before `0.12.0-alpha.1` | state-changing account-binding operations used GET routes and query parameters | Test identity-linking, recovery, and OAuth binding routes for browser-navigation CSRF and follow-on account recovery impact. |

## Operator triage

Prioritize targets where one of these conditions is true:

1. EGroupware exposes SmallParT/media uploads, import/export downloads, mail compose, or admin eTemplate customization to scoped test users.
2. Admin customization can override built-in templates, skins, workflows, reports, or mail layouts from a database/VFS path rather than immutable source files.
3. Rich text, HTML mail, CMS content, or notification templates support embedded images, imports, attachments, or remote URL fetching.
4. XWiki runs on Jetty 12+ and exposes `/xwiki/bin/skin/` or equivalent static resource actions through the same origin as authenticated pages.
5. New API or similar AI/API gateways let regular users save notification, webhook, Bark, Gotify, callback, or provider URLs.
6. Account-binding or identity-linking routes change state through GET requests, query parameters, or browser redirects.

Lower priority: single-admin labs with no lower-privilege boundary, patched versions, read-only deployments with PHP shell execution disabled and no template override path, URL validators that resolve and pin IPs per request, and identity flows protected by POST-only anti-CSRF state plus strict SameSite cookies.

## Replayable validation boundaries

### Nested role object to upload/file selector check

Use this only in a disposable EGroupware lab or customer-approved staging instance.

- Preconditions: affected version, a low-privilege test account, a synthetic course/media object, and a disposable upload directory or marker file path.
- Capture the normal upload request and identify which server-side course membership or teacher role should authorize the operation.
- Attempt a request where only nested request-side role/course fields are changed to a teacher-like marker while the real test account remains low privilege.
- Use a harmless media file and a lab-only path marker; stop once the server accepts or rejects the authorization boundary.
- Positive evidence: the server derives authorization from caller-supplied nested course/participant fields and accepts a write or file selector that the real account should not control.
- Negative controls: patched build, server-side ACL lookup by immutable course ID, low-privilege denial, and path canonicalization to a fixed media root.
- Do not target production config files, PHP include files, shell payloads, user media, credentials, or destructive overwrite paths.

Report this as **request-supplied role metadata to upload/file boundary**. Strong evidence includes role, route, changed fields, server-side authorization expectation, marker-only write/select evidence, and patched or denial controls.

### Template override to evaluator check

Use this only in a lab where template uploads and template rendering are explicitly authorized.

- Preconditions: affected EGroupware version, admin-equivalent test account if the route is admin-only, a non-production PHP configuration, and a disposable template name that cannot override production workflows.
- Upload a benign `.xet` or equivalent template override containing a fixed inert marker expression or render-time marker string, not a command payload.
- Render only the disposable template path and record whether widget attributes are expanded through an evaluator.
- If command execution is in scope for a private lab, use an inert local marker such as writing a fixed string under a temporary lab directory; otherwise stop at proof that evaluator metacharacters are interpreted.
- Positive evidence: uploaded template attributes are interpreted by the runtime evaluator and can influence render-time behavior beyond static markup.
- Negative controls: patched build, disabled PHP backtick execution, template attribute escaping, and templates stored outside the override-precedence path.
- Do not publish web shells, reverse shells, command strings, environment reads, production template names, or secrets.

Report this as **template override to server-side evaluator**. Include the upload role, VFS/path precedence, template name, render trigger, inert marker evidence, PHP hardening state, and patched behavior.

### Rich mail/editor URI scheme to server file read check

Use this only with synthetic files you create in a disposable lab.

- Preconditions: affected EGroupware version, authenticated mail/editor access, and a lab-created canary file readable by the web process but containing no secrets.
- Create an HTML body with an embedded image reference that points only to the synthetic canary through the suspected non-HTTP scheme or local wrapper.
- Send or preview the message to a controlled test mailbox and inspect whether the inline MIME part contains the canary marker.
- Positive evidence: the server reads the local canary and embeds it as an attachment or inline image when the URI should have been rejected.
- Negative controls: patched build, scheme allowlist for `http`/`https`, rejected stream wrappers, and relative-path confinement to an upload/media directory.
- Do not read `/etc/passwd`, application config, TLS keys, database credentials, mailboxes, or user documents.

Report this as **rich-content URI scheme to server-side local file read**. Strong evidence includes route, editor context, scheme, canary path class, MIME attachment metadata, and patched rejection behavior.

### XWiki `/skin/` double-decode traversal check

Use this only on owned XWiki labs or explicitly authorized staging targets.

- Preconditions: affected XWiki version, Jetty 12+ deployment, known webapp path depth, and a synthetic marker resource placed in a lab-readable but normally unreachable location.
- First request an allowed skin resource and record normal response behavior.
- Request a double-encoded traversal path that attempts to reach only the synthetic marker file or an in-webapp non-secret marker, not system files.
- Positive evidence: `/skin/` returns the marker outside the intended skin/resource root.
- Negative controls: patched XWiki, a non-affected servlet container, canonical path rejection, and a traversal path that stays within the intended resource root.
- Do not request production configuration, database files, private attachments, tokens, or system files.

Report this as **servlet/resource decode-order traversal**. Include XWiki and container versions, webapp path depth, encoded path form, marker location class, response status, and negative controls.

### Notification URL hostname to SSRF check

Use this for New API or similar products with user-configurable notification URLs.

- Preconditions: affected version, regular authenticated test account, owned callback domains, and a synthetic internal canary service if the customer explicitly provides one.
- Configure a notification URL to an owned domain that resolves to a public callback first and record the normal outbound request shape.
- Repoint the same hostname to a lab-controlled private-range canary or mock metadata endpoint approved for testing; do not use real cloud metadata endpoints.
- Trigger a notification and compare whether the application validates the resolved IP before connecting.
- Positive evidence: the server follows the hostname to the private/mock destination even though IP filtering should block it.
- Negative controls: patched build with `ApplyIPFilterForDomain` enabled, per-request DNS/IP enforcement, fixed domain allowlist, and blocked private/mock destination.
- Do not query production internal services, metadata APIs, service meshes, admin panels, or credentials-bearing endpoints.

Report this as **user notification hostname to server-originated internal fetch**. Include role, notification type, URL field, DNS resolution timeline, callback logs with tokens redacted, and blocked/patched behavior.

### GET account-binding CSRF check

Use this only with two disposable accounts and owned identity providers or email addresses.

- Preconditions: affected New API version, a victim test account, an attacker-controlled test email/OAuth identity, and a browser profile where cookie behavior is documented.
- Confirm the expected account-binding route and whether it changes state with GET and query parameters.
- From a separate origin you control, navigate the victim test browser to the binding URL with an attacker-owned canary identity.
- Positive evidence: the victim account binds the attacker-controlled canary identity without an explicit POST, anti-CSRF token, or in-session confirmation.
- Negative controls: SameSite Strict cookie behavior, patched POST-only JSON route, anti-CSRF state mismatch, and user confirmation prompts.
- Do not target real user accounts, real recovery addresses, production identities, or live OAuth tenants.

Report this as **browser navigation to account-binding state change**. Include route, method, cookie/SameSite context, before/after binding state for disposable accounts, and patched controls.

## Reporting notes

- Lead with the crossed boundary, not just the CVE label: **role metadata to upload**, **template override to evaluator**, **rich-content URI to local file read**, **resource action decode-order traversal**, **notification hostname to SSRF**, or **GET identity binding CSRF**.
- Include product version, role, route, affected feature flag/deployment condition, and negative controls.
- Keep artifacts synthetic: marker media, disposable templates, lab canary files, owned callback domains, mock private services, and disposable identities.
- Redact callback tokens, session cookies, mail content, template paths, absolute production paths, and account identifiers.
