# Concrete CMS package, file, and block boundary checks

Source: hourly offensive-security scan, 2026-06-23, updated 2026-06-24 with adjacent Concrete CMS authorization, file, and package-control advisories. Primary entries: GitHub Advisory Database [GHSA-r42c-3rr2-jrfp](https://github.com/advisories/GHSA-r42c-3rr2-jrfp), [GHSA-pv2v-6w2v-97x6](https://github.com/advisories/GHSA-pv2v-6w2v-97x6), [GHSA-4g7q-44qp-cc5c](https://github.com/advisories/GHSA-4g7q-44qp-cc5c), [GHSA-645j-cm4x-3xvw](https://github.com/advisories/GHSA-645j-cm4x-3xvw), [GHSA-p8p9-5953-h9jw](https://github.com/advisories/GHSA-p8p9-5953-h9jw), [GHSA-chfm-cm6h-q5x7](https://github.com/advisories/GHSA-chfm-cm6h-q5x7), [GHSA-fqg3-8w8r-8g94](https://github.com/advisories/GHSA-fqg3-8w8r-8g94), [GHSA-66rg-92q4-6m8q](https://github.com/advisories/GHSA-66rg-92q4-6m8q), [GHSA-4c8m-6fwx-m7xq](https://github.com/advisories/GHSA-4c8m-6fwx-m7xq), [GHSA-jr5g-qv3g-rxxx](https://github.com/advisories/GHSA-jr5g-qv3g-rxxx), [GHSA-5rj5-gfmr-hrc3](https://github.com/advisories/GHSA-5rj5-gfmr-hrc3), [GHSA-prxr-vjgc-2cq9](https://github.com/advisories/GHSA-prxr-vjgc-2cq9), [GHSA-g7xp-jf3x-wcx4](https://github.com/advisories/GHSA-g7xp-jf3x-wcx4), and [GHSA-46xh-7854-f568](https://github.com/advisories/GHSA-46xh-7854-f568).

These Concrete CMS advisories are durable for operators because they expose four reusable CMS trust boundaries: CSRF-able package downloads, REST/JSON type coercion into serialized block state, unauthenticated file-reference disclosure, and template path traversal from page-type composer controls. Validate only against owned labs or explicitly scoped CMS instances.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-r42c-3rr2-jrfp](https://github.com/advisories/GHSA-r42c-3rr2-jrfp) / CVE-2026-8140 | Concrete CMS marketplace package install | `/dashboard/extend/install/download/<remoteId>` is a state-changing GET that checks package-install permission but not a CSRF token | Test privileged CMS routes where a GET pulls remote package code or writes under the package directory. |
| [GHSA-pv2v-6w2v-97x6](https://github.com/advisories/GHSA-pv2v-6w2v-97x6) / CVE-2026-8135 | ExpressEntryList block controller | REST API `json_decode()` can turn string-like controls into strict booleans and bypass `_fromCIF` protections before serialized data reaches `filterFields` | Add API-vs-form parser differential checks for CMS blocks that store serialized configuration. |
| [GHSA-4g7q-44qp-cc5c](https://github.com/advisories/GHSA-4g7q-44qp-cc5c) / CVE-2026-6826 | file usage dialog | unauthenticated `/ccm/system/dialogs/file/usage/{fID}` can disclose page IDs, handles, and full URLs referencing a file | Use file-reference enumeration as a scoped recon primitive for hidden page discovery, but keep evidence to synthetic files/pages. |
| [GHSA-645j-cm4x-3xvw](https://github.com/advisories/GHSA-645j-cm4x-3xvw) / CVE-2026-8134 | page type composer custom template | `ptComposerFormLayoutSetControlCustomTemplate` can include traversal sequences when saving composer form layouts | Test backend CMS template selectors for path traversal into readable files or uploaded canary templates, not production secrets. |

## Operator triage

1. **Confirm Concrete CMS ownership first.** Collect version, role model, marketplace connection status, installed packages, and whether REST API and dashboard routes are reachable in scope.
2. **Prioritize package and block editors.** Users who can install packages, edit page types, add blocks, or call REST block APIs sit near code/file boundaries even when they are not full server admins.
3. **Treat file IDs as recon pivots.** If file usage dialogs lack auth, enumerate only lab-created file IDs or target-approved synthetic files; the value is discovering route/permission drift, not scraping private page maps.
4. **Look for parser differentials.** Compare dashboard form submissions with REST JSON bodies for the same CMS object, especially where booleans, serialized arrays, template names, or block options are stored.
5. **Keep CSRF proofs inert.** A package-download CSRF proof should use a harmless marketplace/package ID in a disposable lab and stop at demonstrating the missing token/state change.

## June 24 Concrete CMS authorization and package-control update

Late GitHub Advisory Database updates added a second Concrete CMS 9.5.0-and-below cluster. Promote it with the same operator frame: public or low-privilege CMS routes crossing into private file/form/calendar objects, group membership changes, or package/core update execution. Keep proofs to lab users, canary files, synthetic form entries, harmless package controllers, and route/token decision tables.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-p8p9-5953-h9jw](https://github.com/advisories/GHSA-p8p9-5953-h9jw) / CVE-2026-7886 | Conversation `AddMessage` / `UpdateMessage` attachments | user-supplied `attachments[]` file IDs are loaded directly without `canViewFile()` checks | Test conversation/comment upload features for file-ID attachment pivots into restricted file-manager objects. |
| [GHSA-chfm-cm6h-q5x7](https://github.com/advisories/GHSA-chfm-cm6h-q5x7) / CVE-2026-7881 | Express Entry Detail block | `exEntryID` can select form submissions outside the viewer's authorization boundary | Add sequential-ID and block-route checks for CMS form submissions and lead-capture records. |
| [GHSA-fqg3-8w8r-8g94](https://github.com/advisories/GHSA-fqg3-8w8r-8g94) / CVE-2026-7879 | `download_file.php` `submit_password()` | password and no-password download paths bypass `view_file` permission decisions | Compare direct download routes with file-manager permissions using only synthetic private files. |
| [GHSA-66rg-92q4-6m8q](https://github.com/advisories/GHSA-66rg-92q4-6m8q) / CVE-2026-7882 | Conversation `DeleteFile` controller | an inverted CSRF-token check allows deletion when the token is invalid or missing | Treat token-validation polarity as a test case; prove with disposable conversation attachments only. |
| [GHSA-4c8m-6fwx-m7xq](https://github.com/advisories/GHSA-4c8m-6fwx-m7xq) / CVE-2026-8421 | Dashboard package install | `install_package()` lacks CSRF protection when a package already exists under `DIR_PACKAGES/<handle>/` | Package-control routes are execution-adjacent; validate only with an inert local package marker in a clone. |
| [GHSA-jr5g-qv3g-rxxx](https://github.com/advisories/GHSA-jr5g-qv3g-rxxx) / CVE-2026-8417 | Dashboard package update | state-changing `GET /dashboard/extend/update/do_update/<pkgHandle>` checks package permission but not a token | Add package-update GET routes to CSRF/navigation harnesses; evidence is method/token mismatch plus a harmless upgrade marker. |
| [GHSA-5rj5-gfmr-hrc3](https://github.com/advisories/GHSA-5rj5-gfmr-hrc3) / CVE-2026-8426 | Remote package upgrade prep | `prepare_remote_upgrade/<remoteMPID>` can overwrite package PHP and invoke `upgrade()` when marketplace preconditions hold | Validate marketplace/package-source binding with owned packages only; never publish or trigger a web shell. |
| [GHSA-prxr-vjgc-2cq9](https://github.com/advisories/GHSA-prxr-vjgc-2cq9) / CVE-2026-8428 | Core update controller | token is rendered for `do_update` but not validated server-side | Record rendered-token vs server-validation drift and stop at a fake or lab-local update version marker. |
| [GHSA-g7xp-jf3x-wcx4](https://github.com/advisories/GHSA-g7xp-jf3x-wcx4) / CVE-2026-8350 | `bulk_user_assignment.php` | any authenticated user with page access can add emails to arbitrary groups or remove admins | Use two disposable accounts and a non-production group to prove route-level authorization drift; do not alter real admin groups. |
| [GHSA-46xh-7854-f568](https://github.com/advisories/GHSA-46xh-7854-f568) / CVE-2026-8205 | Calendar Block `action_get_events` | restricted event details are returned without checking `canView` on the calendar | Pair this with the frontend-dialog calendar check: public block route to private calendar/event marker disclosure. |

### Added validation boundaries

- **File-ID and form-entry IDOR:** Seed one public and one restricted canary file or Express entry. From a low-privilege account, reference only the known restricted ID through conversation attachments, download routes, and Express detail routes. Evidence is the controlled marker crossing the expected permission boundary, plus a patched or access-denied negative control.
- **Token polarity and missing validation:** For file deletion, package install/update, remote upgrade prep, and core update routes, capture three requests: valid token, invalid token, and no token. A vulnerable route either ignores token state or accepts the invalid/missing token. Use only disposable attachments and inert package/update markers.
- **Package execution-adjacent routes:** If package install/update behavior must be proven, use a local lab package whose install/upgrade controller writes a benign marker file under a temp lab path. Do not use production package handles, marketplace accounts, shells, or destructive updates.
- **Group assignment drift:** Test only a lab group and disposable accounts. Capture the route, authenticated role, before/after membership table, and denied negative control; never remove real administrators or grant persistent production privileges.
- **Calendar event route checks:** Use synthetic public/private calendars and event titles that are safe to screenshot. Stop at marker disclosure; do not enumerate real event IDs or attendee data.

## Replayable validation boundaries

### Package-download CSRF

- Preconditions: Concrete CMS lab, marketplace-connected site, administrator or package installer test account, and a harmless package or remote ID approved for the lab.
- Capture a normal dashboard package-download request and verify whether it is a GET state change.
- Replay from a same-browser cross-origin HTML page or image/link trigger and confirm whether no CSRF token is required.
- Positive evidence: request/response pair, package directory marker, and a negative control on a patched build or token-enforced route.
- Do not force production admins to install packages or write files under live package directories.

### ExpressEntryList REST-to-serialized-block control

- Preconditions: lab site, rogue-admin/block-editor account, disposable ExpressEntryList block, and an inert serialized canary object or marker string.
- Submit equivalent dashboard-form and REST JSON updates and compare how `_fromCIF`, boolean fields, and `filterFields` are parsed and stored.
- Positive evidence: database/config diff showing the canary serialized state accepted through REST where the form path rejects it.
- Stop before loading real gadget chains or executing production PHP code; if execution validation is explicitly approved, use only a benign marker in a clone.

### File usage disclosure

- Preconditions: lab file manager with public and restricted synthetic pages referencing known canary files.
- Request `/ccm/system/dialogs/file/usage/{fID}` unauthenticated for only those canary file IDs.
- Positive evidence: response showing page IDs, handles, or URLs for the synthetic restricted page while the page itself remains permission-protected.
- Do not enumerate real customer file IDs, restricted URLs, or page maps outside scope.

### Composer template traversal

- Preconditions: lab account with page-type composer form editing rights, an uploaded benign canary file, and a safe readable marker path.
- Save `ptComposerFormLayoutSetControlCustomTemplate` values with baseline template names, then controlled traversal to a canary template or marker file.
- Positive evidence: server attempts to include or render only the canary target, plus patched rejection if available.
- Do not read system files, database credentials, keys, or uploaded user content as proof.

## Reporting notes

- Lead with the exact boundary: **GET package install without CSRF**, **REST JSON type coercion into serialized block config**, **unauthenticated file-usage route**, **composer template path traversal**, **file/form/calendar IDOR**, **token polarity failure**, **package/core update without server-side token validation**, or **bulk group assignment without authorization**.
- Include Concrete CMS version, role, route, request method, object ID, expected permission/token decision, actual decision, and disposable canary evidence.
- Keep all proof artifacts synthetic: lab package IDs, marker blocks, canary files, and controlled page paths. Avoid real marketplace installs, production secrets, private pages, and executable payloads.
