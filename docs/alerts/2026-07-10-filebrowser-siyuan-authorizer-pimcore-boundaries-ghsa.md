# File Browser proxy-auth, SiYuan local-app, Authorizer OAuth, and Pimcore CMS boundary checks

Source: hourly offensive-security scan, 2026-07-10 late GitHub advisory wave with 19:32 UTC follow-ups. Primary entries: [GHSA-xqp3-jq6g-x3qm](https://github.com/advisories/GHSA-xqp3-jq6g-x3qm) / CVE-2026-54089, [GHSA-m93h-4hw7-5qcm](https://github.com/advisories/GHSA-m93h-4hw7-5qcm) / CVE-2026-54088, [GHSA-hvr9-72v2-fff3](https://github.com/advisories/GHSA-hvr9-72v2-fff3) / CVE-2026-54069, [GHSA-gcm7-57gf-953c](https://github.com/advisories/GHSA-gcm7-57gf-953c) / CVE-2026-54068, [GHSA-p4m3-mgmm-c664](https://github.com/advisories/GHSA-p4m3-mgmm-c664) / CVE-2026-54066, [GHSA-w7cg-whh7-xp28](https://github.com/advisories/GHSA-w7cg-whh7-xp28) / CVE-2026-54070, [GHSA-mvjr-vv3c-w4qv](https://github.com/advisories/GHSA-mvjr-vv3c-w4qv) / CVE-2026-54067, [GHSA-5xfx-xj4h-5p7r](https://github.com/advisories/GHSA-5xfx-xj4h-5p7r) / CVE-2026-54158, [GHSA-h29v-hj44-q8cv](https://github.com/advisories/GHSA-h29v-hj44-q8cv) / CVE-2026-54072, and the Pimcore updates [GHSA-wc7j-g8wx-m2qx](https://github.com/advisories/GHSA-wc7j-g8wx-m2qx), [GHSA-r2f4-ff2p-xc64](https://github.com/advisories/GHSA-r2f4-ff2p-xc64), [GHSA-jwcc-gv4m-93x6](https://github.com/advisories/GHSA-jwcc-gv4m-93x6), [GHSA-36fc-7wjg-mfvj](https://github.com/advisories/GHSA-36fc-7wjg-mfvj), [GHSA-332x-r494-54fq](https://github.com/advisories/GHSA-332x-r494-54fq), [GHSA-h4ph-crvj-9h92](https://github.com/advisories/GHSA-h4ph-crvj-9h92), and [GHSA-3234-gxc3-pq6f](https://github.com/advisories/GHSA-3234-gxc3-pq6f).

This batch is durable because each item maps to a repeatable operator boundary: a reverse-proxy identity header reaching an app that is also directly exposed, desktop/browser origins crossing into loopback note-app administrator APIs, unauthenticated template helpers crossing into local SQLite reads, publish-mode path normalization missing a second decode, marketplace or synced content crossing into trusted desktop rendering, OAuth implicit-flow redirect URIs missing client allowlist checks, and CMS backend feature permissions drifting away from object-level permissions, SQL construction, or deserialization sinks.

!!! warning "Authorized validation only"
    Keep proofs to disposable File Browser, SiYuan, Authorizer, and Pimcore labs. Use fake proxy usernames, synthetic note blocks, marker-only workspace files, harmless DOM markers, owned redirectors, disposable OAuth clients/users, seeded CMS assets/reports/documents, and local database canaries. Do not impersonate real users, query personal notes, read workspace secrets, capture live OAuth tokens, move/delete production assets, dump real CMS data, or run PHP gadget chains.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-xqp3-jq6g-x3qm](https://github.com/advisories/GHSA-xqp3-jq6g-x3qm) | File Browser proxy auth | Direct requests can supply the trusted proxy identity header when `auth.method=proxy` is enabled and the backend is network-reachable | Add direct-backend exposure and header-forgery checks to File Browser/reverse-proxy assessments. |
| [GHSA-m93h-4hw7-5qcm](https://github.com/advisories/GHSA-m93h-4hw7-5qcm) | File Browser hook auth | Login-screen username/password values are expanded into an external shell hook command before authentication | Add hook-auth command-construction tests with inert credential canaries to File Browser reviews. |
| [GHSA-hvr9-72v2-fff3](https://github.com/advisories/GHSA-hvr9-72v2-fff3) | SiYuan kernel auth | Any `chrome-extension://` origin is treated as administrator for loopback APIs | Test local desktop app APIs for blanket browser-extension origin trust and missing extension-ID binding. |
| [GHSA-gcm7-57gf-953c](https://github.com/advisories/GHSA-gcm7-57gf-953c) | SiYuan dynamic icon API | Unauthenticated icon rendering executes template helpers that can read SQLite note data when a valid block ID is supplied | Add unauthenticated render/template helper reachability checks with synthetic block IDs and marker tables. |
| [GHSA-p4m3-mgmm-c664](https://github.com/advisories/GHSA-p4m3-mgmm-c664) | SiYuan publish `/assets/*path` | First-pass URL cleanup is followed by a fallback decode and publish access fall-through outside `DataDir` | Test double-encoding and route-specific patch gaps using only workspace canary files. |
| [GHSA-w7cg-whh7-xp28](https://github.com/advisories/GHSA-w7cg-whh7-xp28) | SiYuan Bazaar README renderer | Markdown sanitizer blocks a legacy event-handler list but allows newer handler attributes before `innerHTML` insertion | Treat marketplace README/rendered-package metadata as trusted-origin DOM input; prove with harmless event markers. |
| [GHSA-mvjr-vv3c-w4qv](https://github.com/advisories/GHSA-mvjr-vv3c-w4qv) | SiYuan snippets | CSS snippet content can break out of a generated `<style>` tag and reach the Electron renderer | Test synced workspace configuration as a desktop-renderer trust boundary, without host command payloads. |
| [GHSA-5xfx-xj4h-5p7r](https://github.com/advisories/GHSA-5xfx-xj4h-5p7r) | SiYuan attribute-view cells | Synced database cell values in `text`, `url`, `phone`, and `mAsset` branches are interpolated into renderer HTML without escaping | Add attribute/database cell renderers to synced-workspace DOM-sink checks; stop at harmless renderer canaries unless a lab explicitly permits inert Electron sink validation. |
| [GHSA-h29v-hj44-q8cv](https://github.com/advisories/GHSA-h29v-hj44-q8cv) | Authorizer `/authorize` | `redirect_uri` is not validated against allowed origins before implicit-flow tokens are appended and redirected | Reuse OAuth redirect allowlist tests with owned callback URLs and fake lab tokens. |
| Pimcore advisory wave | Pimcore CMS/backend | WebDAV moves, report detail/export routes, class-definition import, translation filters, custom report SQL, and deserialization sources miss the expected auth/object/schema boundary | Add CMS route-family drift, object-permission, SQL-construction, and chained-deserialization precondition checks to Pimcore tests. |

## Replayable validation boundaries

### File Browser proxy-auth header forgery

1. Confirm the deployment explicitly uses File Browser `auth.method=proxy`; default JSON/password auth is a negative control.
2. Determine whether the File Browser backend is reachable directly, bypassing the trusted reverse proxy. Check only approved network paths and record listener address, security group/load-balancer path, and container port publishing.
3. In a lab, send a request directly to the backend with the configured proxy username header, using a fake account such as `fb-canary-user` or a disposable admin account.
4. Record whether File Browser accepts the header as identity or auto-creates the user. Evidence should be a role/session decision table, not access to real files.
5. Add a negative control through the intended proxy path where the proxy strips client-supplied identity headers before setting its own value.

Report this as **direct backend reachability -> caller-supplied proxy identity header -> File Browser session/user creation**. Do not target production user names, shares, files, or admin actions.

### File Browser hook-auth command construction

1. Confirm hook authentication is enabled and identify the exact external command template. Default JSON/password auth is a negative control.
2. In a disposable lab, submit login attempts where username and password contain inert shell metacharacter canaries that should be treated as data, not command syntax.
3. Instrument the hook wrapper to log argv, environment, and marker-file side effects. Positive evidence is command substitution, extra shell tokens, or a marker generated before any successful authentication.
4. Compare with a patched or safer configuration that passes credentials as fixed argv/environment values and rejects shell evaluation.

Report this as **pre-auth login credential -> hook command expansion -> shell command boundary**. Do not run reverse shells, destructive commands, or production hook binaries; keep evidence to inert marker strings and wrapper logs.

### SiYuan browser-extension and loopback administrator boundary

1. Use a disposable SiYuan desktop or Docker lab with synthetic notebooks and no personal workspace data.
2. From a test Chromium extension you control, make one harmless API request to the loopback kernel and record the `Origin: chrome-extension://<id>` value, response status, and reported role.
3. Test whether authorization binds to a specific extension ID, configured token, `AccessAuthCode`, or browser profile. A blanket scheme allow is the vulnerable pattern.
4. Keep proof to route metadata or a synthetic configuration canary. Do not query note content, assets, sync keys, tokens, or browser history.

Report as **browser extension origin -> blanket local API trust -> administrator role on loopback app**. This is a local-service browser-pivot pattern; pair it with scoped extension and localhost reachability evidence.

### SiYuan unauthenticated render helpers and publish path traversal

1. Seed a lab workspace with one synthetic block ID and a marker row or note whose content is safe to disclose, for example `SIYUAN-CANARY-ONLY`.
2. Exercise `/api/icon/getDynamicIcon` with a template that queries only the seeded canary. Positive evidence is the canary in the SVG/response body without authentication.
3. For publish mode, place a harmless marker file under a lab workspace path that is outside `DataDir` but not sensitive.
4. Compare single-encoded, double-encoded, and patched route behavior on `/assets/*path` and any sibling routes that recently received traversal fixes.
5. Stop at marker files. Never request `conf`, database, log, sync, token, or personal note files.

Report the boundaries separately: **unauthenticated render endpoint -> template SQL helper -> note database canary**, and **double-encoded route parameter -> second decode fallback -> publish-mode outside-DataDir file read**.

### SiYuan marketplace README and snippet renderer DOM sinks

1. For Bazaar README rendering, create a lab package or mocked marketplace response with harmless modern event-handler attributes such as pointer/focus/animation canaries.
2. Open the package listing as a disposable administrator after the explicit marketplace trust step, and capture whether the rendered README is assigned into the main document without sandboxing.
3. For snippet rendering, create a synced workspace snippet whose CSS body contains a harmless `</style>` breakout marker that changes a local DOM marker only.
4. For attribute-view/database cells, seed a synced lab workspace with harmless values in `text`, `url`, `phone`, and `mAsset` branches that attempt only DOM marker insertion or a benign `console.log` canary when the block-attribute panel opens.
5. On desktop/Electron builds, do not use host-command payloads. The proof should stop at renderer script execution and pre/post DOM marker values unless the program explicitly approves an inert Electron sink such as writing to a temp canary file.
6. Include controls where sanitization allowlists attributes, escapes `</style>`, HTML-escapes cell values, uses a sandboxed iframe, or renders text inertly.

Report as **untrusted marketplace/synced content -> trusted SiYuan origin DOM insertion -> renderer script canary**. Keep host RCE discussion conditional unless an approved lab explicitly validates the Electron sink with inert commands.

### Authorizer OAuth redirect URI token relay

1. Create a disposable Authorizer lab with a fake client, fake user, and owned callback domain.
2. Pull only public client metadata that the target intentionally exposes, then build `/authorize` requests for `response_type=token` or `id_token` with an unregistered `redirect_uri` under your owned domain.
3. Authenticate as the disposable user and record only whether the 302 `Location` points to the unregistered callback and contains fake token parameters. Redact token bodies or use throwaway tokens.
4. Test the expected negative controls: registered redirect succeeds, unregistered redirect is rejected, and other login/email flows that were previously fixed still call the allowlist validator.

Report this as **public client ID -> unvalidated `redirect_uri` in `/authorize` -> implicit-flow tokens relayed to attacker-controlled origin**. Do not target real users, harvest tokens, or send phishing links.

### Pimcore CMS route, SQL, and deserialization drift

1. Build a Pimcore lab with two backend users, seeded assets/documents/reports, and marker-only database rows.
2. For WebDAV, test whether unauthenticated or low-privileged `MOVE` can move/delete/overwrite only disposable assets when normal asset permissions would deny it.
3. For CustomReports and WordExport, compare list visibility to direct detail/export routes using synthetic report/document IDs. Positive evidence is a hidden canary returned from a route whose listing correctly hid it.
4. For class-definition import/save, translation grid filters, and custom report column configuration, keep SQL proofs to harmless syntax, error, or selected marker values. Do not dump user tables or credentials.
5. Treat unsafe deserialization as a chain precondition. Show only that a seeded serialized canary reaches an `unserialize()` source; do not run gadget chains or publish executable payloads.

Report the exact boundary: **WebDAV route -> unauthenticated asset move**, **feature permission -> object export without view permission**, **report listing filter -> direct report detail bypass**, **class/report/filter metadata -> SQL expression construction**, or **writable CMS state -> unrestricted PHP deserialization sink**.

## Reporting notes

- Lead with deployment preconditions: proxy-auth mode and direct backend reachability for File Browser; desktop/loopback, publish mode, valid block IDs, marketplace trust, or synced workspace write access for SiYuan; implicit-flow route exposure for Authorizer; authenticated backend role and feature permissions for Pimcore.
- Prefer decision tables over exploit prose: raw route, normalized route, role, expected denial, observed response, canary returned, and patched/negative control.
- Redact proxy usernames, OAuth tokens, workspace paths, block IDs tied to real notes, CMS object IDs, report names, database errors that reveal schema beyond the canary, and any host/container paths that identify tenants.
- Skip adjacent resource-only advisories from the same wave unless they unlock a non-availability operator workflow in scope.
