# Snipe-IT, Mattermost, Camel K, Algernon, and Jackson boundary checks

Source: hourly offensive-security scan, 2026-06-23. Primary entries: GitHub Advisory Database [GHSA-52fw-7fw2-fmv5](https://github.com/advisories/GHSA-52fw-7fw2-fmv5), [GHSA-f3c5-6cw8-fg57](https://github.com/advisories/GHSA-f3c5-6cw8-fg57), [GHSA-pwpj-p52h-q484](https://github.com/advisories/GHSA-pwpj-p52h-q484), [GHSA-hf68-g98v-wp9g](https://github.com/advisories/GHSA-hf68-g98v-wp9g), [GHSA-33g4-646g-qwmm](https://github.com/advisories/GHSA-33g4-646g-qwmm), [GHSA-p68w-rgmg-3c2v](https://github.com/advisories/GHSA-p68w-rgmg-3c2v), [GHSA-x667-r589-43m7](https://github.com/advisories/GHSA-x667-r589-43m7), [GHSA-6mmj-jhqj-6c6q](https://github.com/advisories/GHSA-6mmj-jhqj-6c6q), [GHSA-c4r7-j7pp-r8mp](https://github.com/advisories/GHSA-c4r7-j7pp-r8mp), [GHSA-6cfr-wp44-6qmv](https://github.com/advisories/GHSA-6cfr-wp44-6qmv), [GHSA-q8ch-jx67-q52x](https://github.com/advisories/GHSA-q8ch-jx67-q52x), [GHSA-jc3j-x6pg-4hmv](https://github.com/advisories/GHSA-jc3j-x6pg-4hmv), [GHSA-j3rv-43j4-c7qm](https://github.com/advisories/GHSA-j3rv-43j4-c7qm), [GHSA-rmj7-2vxq-3g9f](https://github.com/advisories/GHSA-rmj7-2vxq-3g9f), and [GHSA-hgj6-7826-r7m5](https://github.com/advisories/GHSA-hgj6-7826-r7m5).

These items are durable for operators because they share a reusable pattern: client-controlled identity, route, namespace, host, or type metadata crosses into a more privileged control plane. Validate with owned labs, disposable users, synthetic namespaces, inert files, and canary DNS names only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-52fw-7fw2-fmv5](https://github.com/advisories/GHSA-52fw-7fw2-fmv5) / CVE-2026-48493 | Snipe-IT API | a user with `users.edit` plus API access can update their own permission set beyond the intended role envelope | Test self-service user update routes for permission-field mass assignment and prove with harmless view-only capability toggles. |
| [GHSA-f3c5-6cw8-fg57](https://github.com/advisories/GHSA-f3c5-6cw8-fg57) / CVE-2026-48492 | Snipe-IT selectlist API | low-privileged authenticated users can enumerate user IDs and identity metadata from generic selectlist endpoints | Add inventory/asset apps to recon checklists for roleless API enumeration and user-ID harvesting that enables follow-on authorization tests. |
| [GHSA-pwpj-p52h-q484](https://github.com/advisories/GHSA-pwpj-p52h-q484) / CVE-2026-54329 | Snipe-IT Accessories API | FMCS tenant context can be overwritten by request-supplied `company_id` during accessory creation | Test multi-company APIs for mass-assigned tenant IDs using synthetic company records and harmless accessory markers. |
| [GHSA-hf68-g98v-wp9g](https://github.com/advisories/GHSA-hf68-g98v-wp9g) / CVE-2026-55483 | Snipe-IT user creation | `users.create` paths stripped `superuser` but not `admin` permission during web/API user creation | Check delegated HR/helpdesk roles that can create users for admin-flag field acceptance; prove with disposable accounts only. |
| [GHSA-33g4-646g-qwmm](https://github.com/advisories/GHSA-33g4-646g-qwmm) / CVE-2026-55482 | Snipe-IT bulk asset update | bulk asset updates accept `company_id` directly instead of deriving it from the current user | Add bulk update/import endpoints to tenant-boundary checks; evidence is a synthetic asset moving between lab companies. |
| [GHSA-6f75-x745-xcpr](https://github.com/advisories/GHSA-6f75-x745-xcpr) / CVE-2026-48507 | Snipe-IT bulk user edit | granular `users.edit` users could submit `activated` and `ldap_import` state changes that affect other users' login and reset paths | Test bulk-edit allowlists for account-state and identity-source flags with disposable accounts; do not lock real admins or production users. |
| [GHSA-p68w-rgmg-3c2v](https://github.com/advisories/GHSA-p68w-rgmg-3c2v) / CVE-2026-49976 | Snipe-IT CSV user import | import update mode rebuilds auth fields from raw CSV rows after attempted field stripping | Test importer update paths for email/username mutation of non-owned users with lab-only accounts and owned reset addresses. |
| [GHSA-x667-r589-43m7](https://github.com/advisories/GHSA-x667-r589-43m7) / CVE-2026-55519 | Snipe-IT asset file deletion | class-level asset edit authorization is used where instance/company-level ownership is required | Verify file-delete IDORs with disposable attachments; never delete real asset evidence or user uploads. |
| [GHSA-6mmj-jhqj-6c6q](https://github.com/advisories/GHSA-6mmj-jhqj-6c6q) / CVE-2026-55542 | Snipe-IT S3 signature image retrieval | S3-backed signature retrieval can return a temporary signed URL before the authorization check used by local files | Test only synthetic signature filenames and prove unauthorized signed-URL issuance without downloading sensitive files. |
| [GHSA-c4r7-j7pp-r8mp](https://github.com/advisories/GHSA-c4r7-j7pp-r8mp) / CVE-2026-4858 | Mattermost integration action URLs | an authenticated user-controlled integration URL path can traverse into arbitrary Mattermost API calls executed with a system-admin auth token | Validate webhook/action URL canonicalization with harmless status or synthetic team resources; do not perform destructive admin API calls. |
| [GHSA-6cfr-wp44-6qmv](https://github.com/advisories/GHSA-6cfr-wp44-6qmv) / CVE-2026-4055 | Mattermost playbook runs | create-run authorization is checked against one team while the request supplies a different target team ID | Reuse as an IDOR pattern: compare permission checks to every request-supplied tenant/team/resource identifier. |
| [GHSA-q8ch-jx67-q52x](https://github.com/advisories/GHSA-q8ch-jx67-q52x) / CVE-2026-45760 | Apache Camel K operator | namespace-authorized users can create `Build` resources that steer pod generation into another namespace, including the operator namespace | In Kubernetes reviews, test custom resources whose spec chooses namespace, service account, image, or pod template placement. |
| [GHSA-jc3j-x6pg-4hmv](https://github.com/advisories/GHSA-jc3j-x6pg-4hmv) / CVE-2026-48126 | Algernon `--domain` / `--letsencrypt` mode | raw `Host` header is joined into the served directory, so `..` can escape one level above the document root and render executable server-side files | Add host-header filesystem joins to web-server boundary testing; prove only with a parent-directory marker file or inert Lua marker in a lab. |
| [GHSA-j3rv-43j4-c7qm](https://github.com/advisories/GHSA-j3rv-43j4-c7qm) / CVE-2026-54512 | Jackson databind polymorphic typing | `PolymorphicTypeValidator` validates a generic container raw type but misses nested type parameters | For Java deserialization reviews, treat generic type IDs as a validator-bypass surface and prove with inert canary classes, not real gadgets. |
| [GHSA-rmj7-2vxq-3g9f](https://github.com/advisories/GHSA-rmj7-2vxq-3g9f) / CVE-2026-54513 | Jackson databind `allowIfSubTypeIsArray()` | array allowlisting validates only the array shape, not the component type | Add array-wrapped type IDs to Jackson PTV harnesses when testing allowlists. |
| [GHSA-hgj6-7826-r7m5](https://github.com/advisories/GHSA-hgj6-7826-r7m5) / CVE-2026-54514 | Jackson `InetSocketAddress` binding | deserialization performs eager DNS resolution before application validation or explicit connection logic | Use owned canary DNS names to detect outbound resolver interaction from JSON binding alone. |

Adjacent [GHSA-58fg-62fg-3fcj](https://github.com/advisories/GHSA-58fg-62fg-3fcj), [GHSA-r6fj-869h-4f6q](https://github.com/advisories/GHSA-r6fj-869h-4f6q), [GHSA-3fc8-8hp6-6jr4](https://github.com/advisories/GHSA-3fc8-8hp6-6jr4), [GHSA-5w46-g9pq-wh6f](https://github.com/advisories/GHSA-5w46-g9pq-wh6f), [GHSA-53h4-8rc4-f539](https://github.com/advisories/GHSA-53h4-8rc4-f539), [GHSA-mr8g-2mj4-pcq2](https://github.com/advisories/GHSA-mr8g-2mj4-pcq2), [GHSA-6x4j-8954-5hxm](https://github.com/advisories/GHSA-6x4j-8954-5hxm), [GHSA-5hh8-q8hv-fr38](https://github.com/advisories/GHSA-5hh8-q8hv-fr38), [GHSA-9fxm-vc8v-hj55](https://github.com/advisories/GHSA-9fxm-vc8v-hj55), [GHSA-5jmj-h7xm-6q6v](https://github.com/advisories/GHSA-5jmj-h7xm-6q6v), [GHSA-3wrr-2qpf-2prh](https://github.com/advisories/GHSA-3wrr-2qpf-2prh), and [GHSA-rcqc-6cw3-h962](https://github.com/advisories/GHSA-rcqc-6cw3-h962) were processed without standalone pages: they are either generic XSS/enumeration/crypto/resource notes, Snipe-IT second-factor control issues that do not add a new endpoint-boundary pattern beyond the table above, or narrower Jackson authorization edge cases that should be revisited if paired with a stronger exploit-chain workflow.

## August 28 follow-up: Snipe-IT cross-company, destructive-sink, and CSV/formula boundaries

A same-day Snipe-IT wave reinforces the same reusable bug-hunting heuristics. Durable patterns, not per-endpoint details:

- **FMCS cross-company re-parenting/deletion.** `PATCH /api/v1/maintenances/{id}` accepts a new `asset_id` and authorizes only the *existing* record's asset, not the new one, so a Company A user moves a maintenance record onto a Company B asset ([GHSA-575r-357h-fhch / CVE-2026-55516](https://github.com/advisories/GHSA-575r-357h-fhch), high). The same class shows up in a `reports.view`-scoped delete endpoint that looks up `CheckoutAcceptance::pending()->find($id)` by global ID without re-checking the related asset's company scope ([GHSA-35cr-9hqq-p2mg / CVE-2026-55515](https://github.com/advisories/GHSA-35cr-9hqq-p2mg)). Heuristic: on every multi-company update/delete, the authorization must bind to the **target** object's company, not the source's — enumerate `company_id`-accepting fields and delete-by-global-ID endpoints.
- **Destructive sinks authorized with a weaker permission than the UI route.** `POST /users/bulksave` soft-deletes a user when the caller has only `users.edit` while the confirmation route requires `users.delete` ([GHSA-vgx7-c78r-69w9 / CVE-2026-55460](https://github.com/advisories/GHSA-vgx7-c78r-69w9), high); `POST /account/request/.../cancel_by_admin?/` cancels any user's pending request when the truthy path segment is present with no authorization check ([GHSA-53jc-27pc-x8r8 / CVE-2026-55476](https://github.com/advisories/GHSA-53jc-27pc-x8r8)). Heuristic: for each destructive action, compare the permission the *UI/route* gate checks against the permission the *sink* actually checks — a gap is the finding. Prove with a disposable user and a marker pending request; do not lock or delete real accounts.
- **Request-supplied filename into a filesystem join.** `displaySig` concatenates the route-supplied signature filename into a private-upload path with no sanitization, enabling arbitrary file read under the web server ([GHSA-c6f4-wj38-m3g3 / CVE-2026-55474](https://github.com/advisories/GHSA-c6f4-wj38-m3g3), high); a parallel path traversal reaches the CSV-import `image` field ([GHSA-xr9m-gphc-9p63 / CVE-2026-55469](https://github.com/advisories/GHSA-xr9m-gphc-9p63)). Heuristic: any Snipe-IT action that echoes a filename into `storage_path`/`downloadFile`/`readfile` is a traversal probe. Prove only with a synthetic out-of-root canary file; do not read credentials or user data.
- **Stored value → CSV/spreadsheet formula.** `Actionlog::logaction()` stores the request `User-Agent`; the Activity Report CSV export writes it via `fputcsv()` without quoting, so a low-privileged user who logs an action with a formula-like UA plants a payload that executes when an admin opens the export in a spreadsheet ([GHSA-whrx-mmgr-gpcf / CVE-2026-55452](https://github.com/advisories/GHSA-whrx-mmgr-gpcf)). Heuristic: audit every user-controlled field that lands in an exported CSV/XLSX and test for formula injection with an inert `=HYPERLINK("https://canary.example/")` canary — no exfiltration, no real endpoint.
- **Object-level authorization gaps on binding/creation routes.** `POST /api/v1/kits/{kit}/licenses` checks kit-edit but not the referenced license's ownership ([GHSA-crv3-j83j-f3r6 / CVE-2026-55478](https://github.com/advisories/GHSA-crv3-j83j-f3r6)); location creation bypasses the FMCS parent/child company validation ([GHSA-8w8c-8mx9-52cw / CVE-2026-55472](https://github.com/advisories/GHSA-8w8c-8mx9-52cw)). Heuristic: for each "bind/attach/create-with-reference" endpoint, supply a foreign object ID and confirm whether the reference is re-authorized.

Lower-priority items in the same wave (stored XSS via inline attachment / Markdown custom field, open redirect after user edit, CSS injection via `header_color`, `import.created_by` overwrite, legacy license-checkin permission, print-inventory authorization bypass) were reviewed and are standard XSS/redirect/mass-assignment notes that do not add a new boundary class; track them, revisit if they chain with the cross-company or destructive-sink findings above.

## August 31 follow-up: Snipe-IT sparse-permission mass-assignment wipe

**Advisory:** [GHSA-j5g3-42wp-gqm3 / CVE-2026-55843](https://github.com/advisories/GHSA-j5g3-42wp-gqm3) — high (CVSS 6.5).

`UsersController::update()` passes the request `permission` field **unconditionally** to `NormalizePermissionsPayloadAction`, which returns an **empty array** when the field is absent. That empty result flows to `PreserveUnauthorizedPrivilegedPermissionsAction`, which restores *only* the `superuser` key (when the editor is not a superuser) and the `admin` key (when the editor is neither admin nor superuser). Every other permission — including `admin` when the editing user *is* an admin — is discarded, and `$user->permissions` is overwritten with the sparse result.

The durable pattern: **an absent request field is treated as "set this to empty," not "leave it unchanged."** Because the `canEditAuthFields` gate lets admins update any non-superuser account (including other admins), a `PUT /users/{id}` that omits `permission` silently and permanently destroys the target's admin flag and all granular permissions with no error. A secondary, lower-impact path exists for non-admin users holding `users.edit` who can wipe granular permissions off regular accounts the same way.

This is the destructive twin of the self-service permission mass-assignment items already in the table: there the field is *present* and out-of-envelope; here the field is *absent* and the missing-field normalization erases everything. Heuristic for any mass-assignment surface: **audit the missing-field path.** For each permission/role/tenant/capability field, verify that "not in the payload" means "preserve current value" and not "set to null/empty." Build the test as a before/after permission matrix on a disposable account, sending the minimal update payload that omits the protected field, and confirm whether the field survives.

Patched in `grokability/snipe-it` commit [`1cff2d67`](https://github.com/grokability/snipe-it/commit/1cff2d67aabd00ee51d864c1d7fb717494c1d6ad).

## August 31 follow-up: finfo-MIME-gated inline-serve sanitizer bypass → stored XSS

**Advisory:** [GHSA-jhph-5q74-pmfx](https://github.com/advisories/GHSA-jhph-5q74-pmfx) — stored XSS via inline-served attachment.

The durable pattern: an upload/attachment is **content-type gated by a MIME sniff (finfo)** and then **inline-served with that sniffed MIME as the response `Content-Type`** without an `X-Content-Type-Options: nosniff` header or an explicit block on `text/html`/`image/svg+xml`/`application/xml`. When a low-privileged user uploads a file whose finfo-sniffed MIME is a browser-executable type but whose name or content the upload-side sanitizer did not strip, the inline-serve route returns the file with the sniffed MIME and the browser executes it in the app's origin. The trust boundary is **finfo-sniffed MIME → response `Content-Type` → browser script execution**, not the upload-time extension filter.

Heuristic for any attachment/document inline-serve route: (1) enumerate the MIME types finfo can sniff from a user-controlled upload; (2) confirm whether the inline-serve response sets `X-Content-Type-Options: nosniff`; (3) confirm whether the browser will execute the sniffed MIME in the app's origin (`text/html`, `image/svg+xml`, `application/xml` with an embedded `<script>`, `image/gif` with `<svg>`); (4) confirm the upload-side sanitizer does not strip the executable payload for that MIME. Prove only with a marker payload that logs a benign beacon to an owned callback — do not exfiltrate data or target other users' sessions.

### Bounded PoC workflow

1. Provision an owned Snipe-IT lab with an affected version and a low-privileged account that can upload attachments.
2. Upload a synthetic file whose finfo MIME is `image/svg+xml` (or `text/html`) and whose body contains only a benign `<script>` that fires a beacon to an owned `canary.invalid` listener. Do not place a real exfiltration or session-hijack payload.
3. Request the inline-serve route for that attachment and capture the response `Content-Type`, `X-Content-Type-Options`, and whether the browser executed the script (owner callback hit).
4. Add controls: a `nosniff` response (must not execute), a non-executable MIME (`application/pdf`), and the patched version (must reject or serve with a safe MIME / download disposition).
5. Keep the proof to the beacon hit and the response headers; do not read other users' sessions, do not upload real sensitive data, and do not target production.

Strong evidence is **low-priv upload -> finfo-sniffed executable MIME -> inline-serve response with that MIME and no `nosniff` -> browser executes the marker script in the app's origin** on the affected version, with the patched version serving a safe disposition.

## Operator triage

1. **Start with privilege boundaries, not CVSS.** Prioritize routes where a low-privileged user supplies permission fields, tenant/team IDs, target namespaces, action URLs, hostnames, or type IDs.
2. **Build positive and negative role matrices.** For Snipe-IT and Mattermost, compare a no-permission user, a scoped editor, a team member, and an admin against the same endpoint.
3. **Keep Kubernetes checks synthetic.** For Camel K, use a disposable namespace, fake images, and inert pod templates; evidence is the generated resource placement decision, not workload execution.
4. **Constrain filesystem proofs.** For Algernon, create a disposable parent-directory canary and stop after proving one-level docroot escape or inert renderer invocation in a lab.
5. **Instrument Java harnesses.** For Jackson, use local classes that only set marker fields or perform canary DNS lookup; do not load gadget chains, JNDI endpoints, or production classpaths.

## Replayable validation boundaries

### Snipe-IT API mass assignment and selectlist enumeration

- Preconditions: owned Snipe-IT lab, disposable user accounts, known role assignments, and non-sensitive test users/assets.
- Baseline the user's current permissions and expected API denials.
- Attempt self-update, user-create, CSV-import, bulk-user-edit, bulk-asset-update, accessory-create, file-delete, and S3-signature retrieval requests that include fields or object IDs beyond the user's assigned role/company. Use harmless read/list permissions, synthetic companies, disposable assets, disposable user accounts, and marker files as the canary.
- Query selectlist endpoints with a logged-in low-privileged session and verify whether user IDs or identity metadata appear outside the role's expected scope.
- Positive evidence: before/after permission and tenant matrices, endpoint response codes, synthetic cross-company object placement, and redacted user-ID enumeration counts from lab accounts.

### Mattermost integration and team-ID authorization drift

- Preconditions: Mattermost lab in the affected version range, disposable teams/channels, a low-privileged authenticated user, and synthetic integration/playbook objects.
- For integration action URLs, compare path normalization between the configured integration URL and the API route ultimately invoked. Use harmless read/status or synthetic object routes only.
- For playbook runs, submit paired create-run requests where the permission-bearing team and target team differ.
- Positive evidence: route-decision table showing the privileged token or target-team mismatch with only disposable resources affected.

### Camel K build resource namespace steering

- Preconditions: disposable cluster or namespace, Camel K affected version, low-privileged namespace user, and no production operator namespace.
- Create only inert `Build` resources and inspect generated pod metadata, namespace placement, service account, and image references.
- Positive evidence: Kubernetes events or object YAML showing cross-namespace placement attempted or accepted.
- Stop before running arbitrary build steps, mounting secrets, or using real operator service accounts as proof.

### Algernon Host-to-filesystem join

- Preconditions: owned Algernon lab started with `--domain` or `--letsencrypt`, a document root, and one synthetic canary file in the parent directory.
- Send paired baseline and altered-Host requests and compare which filesystem root is selected.
- Positive evidence: retrieval or directory listing of only the synthetic parent canary, plus patched or hardened rejection if available.
- Do not read certificates, keys, logs, configs, user content, or sibling sites.

### Jackson type and DNS canaries

- Preconditions: local harness using the application's `ObjectMapper` configuration, disposable canary classes, and an owned DNS interaction domain.
- Test generic type IDs where the allowed raw container wraps a denied inert canary class.
- Test array-wrapped type IDs where the array shape is allowed but the component class should not be.
- Test `InetSocketAddress` JSON binding with an owned canary DNS name and verify whether resolution occurs during `readValue`.
- Positive evidence: exception/no-exception matrix, marker-field population for inert classes, and DNS query timestamps. Avoid real gadget classes or external callbacks beyond owned DNS canaries.

## October 25 follow-up: Snipe-IT identity-lifecycle trio — SSO callback skips account-state flags, non-atomic SAML nonce, ignored StartTLS return

Source: GitHub advisories published 2026-10-25T15:32Z (Snipe-IT < 8.6.3 / < 8.5.0). Three legs, all on the identity-lifecycle axis this page's Snipe-IT coverage hadn't reached:

- **Google SSO callback logs in deactivated users** ([GHSA-9cjx-rmhj-qc37](https://github.com/advisories/GHSA-9cjx-rmhj-qc37) / CVE-2026-116199, critical): `GoogleAuthController::handleGoogleCallback` matches the Google account email to a local username and issues a session **without enforcing the `activated` flag** — a deactivated user with a still-live Google identity re-enters at their original permission level, including admin. Durable rule: **SSO/OAuth/SAML callback paths enforce a different check-set than the local password path.** Offboarding state (`activated`, archived, suspended, ldap_import source flags — the same fields this page's Aug 28 bulk-edit leg plants) is enforced in the local auth controller, not in the external-identity join. Lifecycle probe battery on any SSO-integrated app: disable a disposable lab account, then attempt login on **both** the password path and every enabled external-identity path; a deactivation that only sticks on one path is the finding. Secondary: email-match-as-identity means an email address reassignment or takeover inherits the old account's sessions.
- **SAML assertion replay via non-atomic nonce check** ([GHSA-xj2c-rw8f-hjqh](https://github.com/advisories/GHSA-xj2c-rw8f-hjqh) / CVE-2026-116201, high, < 8.5.0): the `/saml/acs` nonce check is check-then-set, so **concurrent POSTs of one captured assertion** each pass and mint multiple authenticated SP sessions that then survive IdP-driven revocation. Durable rules: (1) replay defenses are TOCTOU primitives — fire the N-parallel-copy battery at any single-use token/nonce/assertion gate in a lab, don't test replay serially; (2) the resulting sessions are SP-local state, so IdP logout/revocation never reaches them — report impact as revocation-evasion lifetime, not one-shot access.
- **`ldap_start_tls()` return value ignored → forced-cleartext downgrade** ([GHSA-5j22-x9vm-7fm5](https://github.com/advisories/GHSA-5j22-x9vm-7fm5) / CVE-2026-116200, high): `Ldap::connectToLdap()` continues on StartTLS failure, so an on-path attacker who answers the StartTLS request with a protocol error downgrades the session and captures service-account binds and end-user passwords. Durable rule: **crypto negotiation that fails open on a return value nobody reads is a silent downgrade** — same fail-open family as this scan's ImageMagick `LoadPolicyCache` zero-policy leg; any `start_tls`/`upgrade`/`set_ssl` call whose return is discarded is a grep hit. On-path proof stays in a lab MITM position against your own instance; never capture real credentials.

## Reporting notes

- Lead with the precise trust boundary: **self permission fields**, **selectlist enumeration**, **integration URL to admin-token API**, **team ID mismatch**, **CRD namespace steering**, **Host header to filesystem path**, or **Jackson type/DNS binding** — and since Oct 25: **SSO-vs-local lifecycle-flag parity**, **parallel-replay nonce gates**, **ignored TLS-negotiation returns**.
- Include version, role, endpoint or object kind, sanitized request shape, expected authorization decision, actual decision, and a patched negative control when possible.
- Keep all proof artifacts disposable: synthetic accounts, teams, namespaces, marker files, inert Java classes, and owned canary domains.
- Do not include real user lists, production admin API results, Kubernetes secrets, filesystem secrets, or executable gadget payloads in wiki/report evidence.
