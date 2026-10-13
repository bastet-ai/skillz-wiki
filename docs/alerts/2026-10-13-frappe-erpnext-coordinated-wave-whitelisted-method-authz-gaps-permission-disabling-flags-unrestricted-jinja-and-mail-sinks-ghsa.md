# Frappe/ERPNext coordinated wave: whitelisted-method authz gaps, permission-disabling flags, unrestricted Jinja, and mail sinks

Source: GitHub Security Advisories published 2026-10-13 00:31Z — a coordinated CNA-import wave of **~70 GHSAs** against Frappe Framework `15.x/16.x` and ERPNext `15.x/16.x` (fix bands spread across 15.98–15.121.3 and 16.6–16.35.0 — the advisory set itself is a per-patch history map), plus Frappe Suite mail (`get_mailboxes`/`get_quota`) and a Frappe pdfkit dependency leg.

**Why this is worth an operator page.** Frappe/ERPNext is the most-deployed open-source ERP you've never scoped: self-hosted manufacturing/retail ERPs, NGO back-offices, and a public bug-bounty program — almost always with at least one trial/demo instance exposed. Frappe's architecture makes the whole wave replayable as one audit kit: every Python method decorated `@frappe.whitelist()` becomes a callable HTTP endpoint under `/api/method/<dotted.path>`, permission enforcement is a *per-method opt-in* (`frappe.has_permission` / `validate` hooks) rather than a route-level default, and templates are Jinja rendered server-side across notifications, print formats, and communication fields. Roughly 30 of these advisories are the same sentence — "certain endpoints fail to enforce proper authorization checks" — which is the vendor publicly inventorying its own ungated whitelisted methods. Read the wave as an attack map, not 70 CVEs.

## Boundary map (legs with substantive descriptions)

| GHSA / CVE | CVSS | Surface | Boundary crossed |
| --- | --- | --- | --- |
| [GHSA-f3v4-m95v-25ch](https://github.com/advisories/GHSA-f3v4-m95v-25ch) / CVE-2026-109667 | 8.8 | Record-creation endpoint | **Record type taken from the request, inserted with permission checks disabled** — any authenticated user (even zero roles) supplies a privileged record type to create privileged accounts → full site takeover |
| [GHSA-cw68-6fr5-c994](https://github.com/advisories/GHSA-cw68-6fr5-c994) / CVE-2026-109652 | 8.8 | User-controlled message fields → template rendering | **SSTI in an unrestricted (non-sandboxed) context**: template expressions read/write arbitrary database data, delete documents, make outbound requests, and send mail from the site |
| [GHSA-59gg-p7mc-h3g6](https://github.com/advisories/GHSA-59gg-p7mc-h3g6) / CVE-2026-109608 | 8.8 | Several endpoints, no input validation | SQLi reachable by **any authenticated user including one with no assigned roles**; read other users' data, escalate to a privileged account |
| [GHSA-w3h8-9m75-6p69](https://github.com/advisories/GHSA-w3h8-9m75-6p69) / CVE-2026-109640 | 8.1 | Record-modify endpoints without authz checks | Any authenticated user modifies records beyond role (fixed 16.22.0) |
| [GHSA-rcfr-6r59-hm5x](https://github.com/advisories/GHSA-rcfr-6r59-hm5x) / CVE-2026-109633 | 8.1 | Public-facing booking page | **Unauthenticated stored XSS**: crafted content stored raw, rendered as raw HTML in a privileged user's session → act as that user, account takeover |
| [GHSA-g24j-j8m9-65fg](https://github.com/advisories/GHSA-g24j-j8m9-65fg) / CVE-2026-109621 | 6.5 | Party-record read endpoint | **Honours a caller-supplied flag that disables the endpoint's own permission enforcement** — set the flag, read party records beyond role |
| [GHSA-r69h-vwpx-6874](https://github.com/advisories/GHSA-r69h-vwpx-6874) / CVE-2026-109651 | 4.3 | Configuration field writable by common operational roles | SSRF: field accepts an arbitrary outbound destination with no validation — server requests hosts only reachable inside the deployment network |
| [GHSA-3cf9-2fpp-3v7v](https://github.com/advisories/GHSA-3cf9-2fpp-3v7v) / CVE-2026-109601 | 6.5 | Outgoing email HTML attributes | **Arbitrary file read**: an attribute value referencing a local file path in outgoing email HTML exposes server files to whoever receives the mail |
| [GHSA-8q8g-5ghh-6f67](https://github.com/advisories/GHSA-8q8g-5ghh-6f67) / CVE-2026-109675 | 4.3 | Frappe Suite `get_mailboxes` / `get_quota` (JMAP) | IDOR: **supply another user's JMAP account ID** to read their mailbox names, message counts, automation rules (incl. sender addresses), and quota |
| [GHSA-h2g2-w3jw-9f6h](https://github.com/advisories/GHSA-h2g2-w3jw-9f6h) / CVE-2026-109602 | 5.4 | Dashboard chart filters | Stored XSS — jQuery renders entered filter values as rich text in other viewers' browsers |
| [GHSA-8q9q-vqwh-rpm8](https://github.com/advisories/GHSA-8q9q-vqwh-rpm8) / CVE-2026-109603 | 3.3 | PDF generation via vulnerable pdfkit (CVE-2025-26240) | SSRF + local file inclusion through crafted content into PDF rendering — internal resources fetched, local server files embedded in the generated PDF (readable by the requester) |

Plus ~30 further "missing authorization" legs in the same band (document create/read/modify/status verbs beyond role: [GHSA-mpfp-cmm2-68pc](https://github.com/advisories/GHSA-mpfp-cmm2-68pc) document status, [GHSA-9964-cw4f-c96r](https://github.com/advisories/GHSA-9964-cw4f-c96r) document creation, [GHSA-8pxf-9hmp-wv7f](https://github.com/advisories/GHSA-8pxf-9hmp-wv7f) data read, [GHSA-vc8c-vcg7-x76v](https://github.com/advisories/GHSA-vc8c-vcg7-x76v) master data, [GHSA-242p-xjhp-68jh](https://github.com/advisories/GHSA-242p-xjhp-68jh) financial records read, [GHSA-frwq-f3qm-frf9](https://github.com/advisories/GHSA-frwq-f3qm-frf9)/[GHSA-gqg9-2w62-58r8](https://github.com/advisories/GHSA-gqg9-2w62-58r8)/[GHSA-pv62-434m-g9vq](https://github.com/advisories/GHSA-pv62-434m-g9vq)/[GHSA-59gg-p7mc-h3g6](https://github.com/advisories/GHSA-59gg-p7mc-h3g6) SQLi singles, stored-XSS singles [GHSA-82qc-4rqg-p3g8](https://github.com/advisories/GHSA-82qc-4rqg-p3g8)/[GHSA-24f3-935v-8wmm](https://github.com/advisories/GHSA-24f3-935v-8wmm)/[GHSA-g9jx-m3gp-q3jv](https://github.com/advisories/GHSA-g9jx-m3gp-q3jv)/[GHSA-q3p4-7c35-89wj](https://github.com/advisories/GHSA-q3p4-7c35-89wj)/[GHSA-frw3-f8vj-wxg9](https://github.com/advisories/GHSA-frw3-f8vj-wxg9)) — recorded here as inventory; the audit kit below covers all of them.

## The whitelisted-method surface is the whole game

Frappe exposes any `@frappe.whitelist()`-decorated method as `POST /api/method/<app>.<module>.<file>.<method>` (and short-alias forms). Authorization is expected to live *inside* the method — there is no route-level default-deny. This wave is ~30 advisories saying "this method didn't."

Operator audit kit (works on any Frappe/ERPNext instance you're authorized to test, and generalizes to every framework that auto-exposes annotated functions as RPC):

1. **Enumerate the callable surface.** On an accessible instance, list routes via the API (`/api/method/frappe.desk.client` family, `/api/v2` docs) and, when you have source (open-source = public source, always diff it), grep `@frappe.whitelist` including `allow_guest=True` variants. Every hit is a test case; the guest ones are pre-auth.
2. **Lowest-token sweep.** Auth as the weakest role you're allowed to have (a contacts-only or no-role user) and replay every enumerated method's canonical read/modify verb. The wave proves ~30 of these answered 200 with data or writes for low-priv users. This is a scripted decision table, not manual poking.
3. **Verb parity.** Several legs are the same document with create gated but modify/status not (or read gated but list not). For every gated verb you find, immediately test its siblings: create/read/update/delete/submit/cancel/amend/set-status. Frappe document verbs are separately implemented — gate drift between them is this product's native failure mode.

## Permission-disabling flags as parameters

Two legs share a rule the whole ecosystem breeds:

- The record-creation endpoint **takes the record type from the request and inserts with permission checks disabled** (f3v4/109667) — the doctype name is user input, and the insert path runs `ignore_permissions`-style semantics because it was written for internal callers.
- A read endpoint **honours a caller-supplied flag that disables its own permission enforcement** (g24j/109621).

Replayable battery on any Frappe-shaped app (and any framework with permission-bypass booleans in internal APIs):

- On every create/update/call endpoint, fuzz the internal bypass spellings as extra parameters: `ignore_permissions`, `ignore_permissions=1/true`, `ignore_mandatory`, `no_permission_check`, plus the framework's own names once you've grepped the function signatures. Same shape as the Sept 21 "supplied-scope vs owned-scope" rule: the check is performed against what *you sent*, not what the server *owns*.
- On record-creation endpoints, swap the type/name parameter to privileged records (`User`, `Role`, `DocType`, `Print Format`, `Notification`) and observe whether insertion succeeds — the 8.8 leg is exactly "supply privileged record type → create privileged account → site takeover."
- Doctypes with `istable`/hidden flags are still reachable through the generic `/api/resource/` and `/api/method/frappe.client` families even when no UI exists for them — enumerate the DocType list (`frappe.get_all('DocType')` equivalent via generic read) and probe the generic CRUD surface per doctype, not per UI page.

## Unrestricted Jinja = the compute sink

The SSTI leg (cw68/109652, 8.8) is the highest-value single in the wave: user-controlled message fields are rendered as templates **without validation, in an unrestricted context**, and the advisory's own impact list — read/write arbitrary DB data, delete documents, server-side outbound requests, send mail from the site — is the full impact cone of a non-sandboxed Jinja environment reaching Frappe's `db`/`sendmail`/`requests` surface.

Operator rules:

1. **Inventory every field that stores text and is later rendered.** Frappe renders Jinja in notifications, print formats, email communication fields, and document hooks; the advisory shows the message field is enough. Any "message"/"content"/"subject" field that later crosses into the site's templating path is a candidate — submit one canary expression per field you're authorized to touch and watch whether it evaluates.
2. **Sandbox posture is invisible from the outside** — `{{ ''.__class__ }}`-style probing distinguishes unrestricted from sandboxed environments; the wave proves ship-default here was unrestricted on the affected path. Pair with the Aug 6 agent-authority page's codegen legs: framework-rendered user text is compute-on-behalf-of-the-server.
3. The outbound-request + send-mail legs make the SSTI an SSRF and mail-relay pivot *by itself* — one expression, three impact classes. Report per-sink, not as generic "SSTI".

## Mail as both leak channel and IDOR target

Three legs treat outgoing mail as an attack surface rather than a delivery mechanism:

- **File read via outgoing HTML attributes** (3cf9/109601): an attribute value referencing a local file path in outgoing email HTML embeds server file content into mail that goes to a recipient you control. The mail pipeline becomes the readback channel for an SSRF-adjacent file-read — same "read needs a channel, email is one" pattern as the Fleet canary pagination leg and the Pulp credential-slot leg.
- **JMAP account-ID IDOR** (8q8g/109675): `get_mailboxes`/`get_quota` accept *another user's account ID* — mailbox names, message counts, and **automation rules with sender addresses** come back. Automation rules are a config-disclosure oracle (filters, actions, forwarding addresses) worth more than the mailbox names. Probe every JMAP/mail API verb with a sibling account's ID — the class is the same as the Nginx UI node-token and PictShare leak family: API takes the principal as a parameter, not from the session.
- The May 6 page's Frappe Cloud multi-recipient signup OTP leg (CVE-2026-4894) is the third independent break in this product's mail boundary in five months — **same-product re-sweep rule validated again**: any Frappe item on an engagement gets the full mail-boundary battery (recipient-parsing shapes, attribute/file references, principal-as-parameter sweeps), because this vendor's mail surface has now produced bugs in three separate subsystems.

## Fix-band spread is a fingerprint and a timeline

The fix bands (15.98.0 → 15.121.3, 16.6.0 → 16.35.0) mean each leg was patched at a different point over months. A live instance's exact version (readable from `/api/method/frappe.client.get_versions`-shaped endpoints, login-page asset paths, or response headers) tells you **which subset of this wave is still open on that host** — diff version against the per-advisory bands before choosing test cases. A site current on 16.35+ is patched; a site on 16.20 still has everything fixed in 16.21–16.35, including the 8.1 public-page XSS and the permission-flag leg. This is the same "advisory set as per-host attack map" pattern as the Brocade and HPE ClearPass waves.

## Validation boundaries

- Authorized instances only; Frappe's public bounty program defines scope — read it per engagement.
- Prove authz gaps with **two disposable accounts** (low-role vs target) and canary documents you own; never read real ERP data (customer records, payroll, bank master data are all in-scope-of-the-database here).
- Prove the SSTI with an inert marker expression (string output, or a canary read of a doctype you created); do not exercise the delete/mail legs beyond presence — one sent test mail to an owned mailbox max.
- SSRF to owned callbacks only; file-read proofs to synthetic canary files, never `/etc/passwd`-style reads in report evidence.
- Public booking-page XSS: inert DOM marker in your own privileged test account's browser.

Tracked from the same wave without individual publication: IBM i 7.3–7.6 authenticated pack (detail-free boilerplate, IBM June-style), IBM TRIRIGA pair, IBM DataStage authenticated path-traversal/DoS/disclosure singles, IBM Aspera local LPE/info-disclosure singles, Mistral.rs and CityGaussian sparse singles, and the remaining Frappe missing-authz/XSS singles inventoried above.

Related pages: the [May 6 render/identity page](2026-05-06-render-identity-and-url-canonicalization-boundary-batch-ghsa.md) (Frappe Cloud multi-recipient signup OTP, CVE-2026-4894), the [Sept 18 ignored-scope page](2026-09-18-ignored-scope-parameters-kcp-identity-header-smuggling-convoy-perses-obot-ghsa.md) (supplied-scope lineage for the record-type-from-request leg), the [Sept 21 auth-precedence page](2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md) (verb-gate drift family), the [Oct 12 Grav page](2026-10-12-grav-coordinated-wave-derived-federated-credentials-2fa-lifecycle-gaps-and-nested-git-disclosure-ghsa.md) (same-week coordinated-wave audit-kit shape), and the [Oct 8 Malcolm page](2026-10-08-malcolm-nsm-stack-reverse-proxy-composition-wave-rbac-byte-vs-route-forged-identity-headers-and-fetch-anywhere-uploader-ghsa.md) (per-surface authz coverage audits).
