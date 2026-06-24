# Concrete CMS package, file, and block boundary checks

Source: hourly offensive-security scan, 2026-06-23, updated 2026-06-24 with adjacent Concrete CMS authorization, file, package-control, survey, OAuth, conversation, summary-template, log, RSS-fetch, file-manager, and Express association advisories. Primary entries: GitHub Advisory Database [GHSA-r42c-3rr2-jrfp](https://github.com/advisories/GHSA-r42c-3rr2-jrfp), [GHSA-pv2v-6w2v-97x6](https://github.com/advisories/GHSA-pv2v-6w2v-97x6), [GHSA-4g7q-44qp-cc5c](https://github.com/advisories/GHSA-4g7q-44qp-cc5c), [GHSA-645j-cm4x-3xvw](https://github.com/advisories/GHSA-645j-cm4x-3xvw), [GHSA-p8p9-5953-h9jw](https://github.com/advisories/GHSA-p8p9-5953-h9jw), [GHSA-chfm-cm6h-q5x7](https://github.com/advisories/GHSA-chfm-cm6h-q5x7), [GHSA-fqg3-8w8r-8g94](https://github.com/advisories/GHSA-fqg3-8w8r-8g94), [GHSA-66rg-92q4-6m8q](https://github.com/advisories/GHSA-66rg-92q4-6m8q), [GHSA-4c8m-6fwx-m7xq](https://github.com/advisories/GHSA-4c8m-6fwx-m7xq), [GHSA-jr5g-qv3g-rxxx](https://github.com/advisories/GHSA-jr5g-qv3g-rxxx), [GHSA-5rj5-gfmr-hrc3](https://github.com/advisories/GHSA-5rj5-gfmr-hrc3), [GHSA-prxr-vjgc-2cq9](https://github.com/advisories/GHSA-prxr-vjgc-2cq9), [GHSA-g7xp-jf3x-wcx4](https://github.com/advisories/GHSA-g7xp-jf3x-wcx4), [GHSA-46xh-7854-f568](https://github.com/advisories/GHSA-46xh-7854-f568), [GHSA-v7c7-658v-hh7v](https://github.com/advisories/GHSA-v7c7-658v-hh7v), [GHSA-56c9-xq5g-xrf9](https://github.com/advisories/GHSA-56c9-xq5g-xrf9), [GHSA-8c7c-h7px-267g](https://github.com/advisories/GHSA-8c7c-h7px-267g), [GHSA-f54h-78c9-c24h](https://github.com/advisories/GHSA-f54h-78c9-c24h), [GHSA-f73j-pm2c-rxvr](https://github.com/advisories/GHSA-f73j-pm2c-rxvr), [GHSA-wmw3-3fv3-h54w](https://github.com/advisories/GHSA-wmw3-3fv3-h54w), [GHSA-vpgr-cwfx-pwfw](https://github.com/advisories/GHSA-vpgr-cwfx-pwfw), [GHSA-2xp7-rpvc-pjwc](https://github.com/advisories/GHSA-2xp7-rpvc-pjwc), [GHSA-qv3x-mffx-9gw8](https://github.com/advisories/GHSA-qv3x-mffx-9gw8), [GHSA-xpgc-7vc2-8725](https://github.com/advisories/GHSA-xpgc-7vc2-8725), [GHSA-58c8-vvqw-cm7m](https://github.com/advisories/GHSA-58c8-vvqw-cm7m), [GHSA-pcrh-gj77-j4mw](https://github.com/advisories/GHSA-pcrh-gj77-j4mw), and [GHSA-gjwq-9v8p-47w7](https://github.com/advisories/GHSA-gjwq-9v8p-47w7).

These Concrete CMS advisories are durable for operators because they expose reusable CMS trust boundaries: CSRF-able package, log, file-manager, and Express association actions, REST/JSON type coercion into serialized block state, unauthenticated file/page/conversation metadata disclosure, template path traversal from page-type composer controls, public-widget ID pivots into restricted surveys/calendars, OAuth account-status drift, profile mass assignment, trusted-render HTML sinks, and editor-supplied RSS URLs crossing into server-side fetches. Validate only against owned labs or explicitly scoped CMS instances.

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

## Late June 24 survey, conversation, OAuth, log, and RSS update

A later GitHub updated-feed wave added more Concrete CMS 9.5.0-and-below issues. They stay on this page because they are the same CMS boundary family: public widgets and unauthenticated helpers accepting object IDs, low-privilege profile or OAuth paths crossing account-state controls, trusted dashboard/report render sinks, state-changing log deletion without token enforcement, and editor-controlled feed URLs causing server-side fetches.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-v7c7-658v-hh7v](https://github.com/advisories/GHSA-v7c7-658v-hh7v) | Bulk log delete dialog | `concrete/controllers/dialog/logs/bulk/delete` is CSRF-able in affected versions | Add admin log/delete dialogs to token-polarity checks; prove only with disposable lab log rows. |
| [GHSA-56c9-xq5g-xrf9](https://github.com/advisories/GHSA-56c9-xq5g-xrf9) | Single log delete dialog | `concrete/controllers/dialog/logs/delete` is CSRF-able in affected versions | Treat maintenance dialogs as state-changing routes even when they are not navigation links. |
| [GHSA-8c7c-h7px-267g](https://github.com/advisories/GHSA-8c7c-h7px-267g) | Survey block | public survey submission can carry a restricted `optionID` and vote in a private survey when both exist | Test widget endpoints for cross-widget object-ID pivots with synthetic public/private survey options. |
| [GHSA-f54h-78c9-c24h](https://github.com/advisories/GHSA-f54h-78c9-c24h) | OAuth 2.0 authorization-code handler | inactive users can still complete OAuth and receive API tokens | Add account-status negative controls to OAuth grant testing; use suspended disposable accounts and inert scopes. |
| [GHSA-f73j-pm2c-rxvr](https://github.com/advisories/GHSA-f73j-pm2c-rxvr) | Legacy pagination on dashboard form reports | `$URL` is interpolated into pagination link attributes for report viewers/admins | Include legacy report URLs and pagination helpers in trusted-dashboard render-sink reviews. |
| [GHSA-wmw3-3fv3-h54w](https://github.com/advisories/GHSA-wmw3-3fv3-h54w) | User profile update controller | raw POST fields can change password without current-password reauth and alter session validator settings | Test profile mass-assignment for auth-hardening flags with disposable users, not real session bypass attempts. |
| [GHSA-vpgr-cwfx-pwfw](https://github.com/advisories/GHSA-vpgr-cwfx-pwfw) | Summary templates | unauthenticated summary-render routes leak private, draft, or restricted page metadata | Extend hidden-page recon to summary-template endpoints using synthetic restricted pages. |
| [GHSA-2xp7-rpvc-pjwc](https://github.com/advisories/GHSA-2xp7-rpvc-pjwc) | Conversation `get_rating` | message IDs confirm existence and return rating scores across expected boundaries | Treat ratings as low-noise conversation-ID existence oracles. |
| [GHSA-qv3x-mffx-9gw8](https://github.com/advisories/GHSA-qv3x-mffx-9gw8) | Conversation `message_page` | unauthenticated requests can return full restricted or moderation-queue messages and attachment URLs | Use two-message canaries to test page-scoped conversation disclosure; do not enumerate production messages. |
| [GHSA-xpgc-7vc2-8725](https://github.com/advisories/GHSA-xpgc-7vc2-8725) | Conversation `message_detail` | message detail endpoint exposes full content by message ID | Pair with `message_page` as alternate route-family coverage for the same object boundary. |
| [GHSA-58c8-vvqw-cm7m](https://github.com/advisories/GHSA-58c8-vvqw-cm7m) | File usage dialog | unauthenticated `file/usage/{fID}` returns internal page/version/path data | Confirms the file-usage route as a reusable hidden-structure oracle; keep proofs to lab files. |
| [GHSA-pcrh-gj77-j4mw](https://github.com/advisories/GHSA-pcrh-gj77-j4mw) | External-link page `cvName` | external alias update can preserve stored markup in page names | Add external-link aliases to CMS trusted-render checks with harmless DOM markers only. |
| [GHSA-gjwq-9v8p-47w7](https://github.com/advisories/GHSA-gjwq-9v8p-47w7) | RSS Displayer block | page editors can supply arbitrary feed URLs, including redirect-to-internal patterns | Treat content blocks that fetch feeds/previews as SSRF candidates; prove with owned callbacks and synthetic internal canaries only. |

### Added validation boundaries for the late wave

- **Survey and conversation object-ID pivots:** Seed public and restricted survey options plus public, restricted, and moderation-queue conversation messages. Exercise only known canary IDs through `optionID`, `get_rating`, `message_page`, and `message_detail`; evidence is expected-deny versus actual marker disclosure or state change.
- **OAuth and profile account-state drift:** Use an inactive disposable user and a normal active user. Compare authorization-code token issuance, password-change requirements, and whether profile POSTs accept auth-hardening flags that are absent from the visible form.
- **Summary and file-usage recon:** Create restricted pages with distinctive titles/descriptions and synthetic file references. Request only their known summary/template and usage routes while unauthenticated; stop at metadata fields, not content scraping.
- **Log CSRF and trusted render sinks:** For log deletes, capture valid-token, invalid-token, and no-token requests against lab log rows. For legacy pagination or external-link names, use inert DOM markers and record the exact trusted origin where they render.
- **RSS fetch SSRF:** Configure the RSS Displayer with an owned callback URL, then with an owned redirector pointing to a synthetic lab-only internal canary. Evidence is callback timing and request metadata; never target cloud metadata, production admin panels, or unrelated internal services.

## Later June 24 file-manager and Express association CSRF update

The GitHub updated feed added another adjacent Concrete CMS 9.x cluster after the first June 24 update. These are lower-severity by themselves, but useful for operators because they widen the same token-enforcement harness from package/log routes into file-manager metadata actions and Express association ordering.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-44q4-354f-c826](https://github.com/advisories/GHSA-44q4-354f-c826) / CVE-2026-8435 | File manager `approveVersion()` | backend file-version approval is CSRF-able in Concrete CMS 9 through 9.5.0 | Add file-version approval to state-changing file routes tested with valid, invalid, and absent CSRF tokens. |
| [GHSA-6qjh-p324-694f](https://github.com/advisories/GHSA-6qjh-p324-694f) / CVE-2026-8434 | File manager `rescanMultiple()` | multi-file rescan can be triggered without expected CSRF enforcement in affected Concrete CMS 9 builds | Use disposable lab files to prove whether background metadata/indexing actions can be cross-origin triggered. |
| [GHSA-6fxm-r8p3-mx5c](https://github.com/advisories/GHSA-6fxm-r8p3-mx5c) / CVE-2026-8433 | File manager `rescan()` | single-file rescan lacks CSRF protection before 9.5.0 | Treat file maintenance verbs as state changes even when no file content is directly disclosed. |
| [GHSA-97jw-gr4m-c5v8](https://github.com/advisories/GHSA-97jw-gr4m-c5v8) / CVE-2026-8432 | File manager `star()` | favorite/star state can be altered through a CSRF-able backend file route | Include UI-state mutation routes in CSRF coverage when they influence workflow visibility or later operator pivots. |
| [GHSA-67hj-8239-cmf5](https://github.com/advisories/GHSA-67hj-8239-cmf5) / CVE-2026-8427 | File manager `removeFavoriteFolder($id)` | favorite-folder removal is CSRF-able before 9.5.0 | Validate with a temporary folder and a low-impact favorite marker only. |
| [GHSA-qj94-6rx6-27fr](https://github.com/advisories/GHSA-qj94-6rx6-27fr) / CVE-2026-8416 | File manager `addFavoriteFolder($id)` | favorite-folder addition is CSRF-able in Concrete CMS 9 through 9.5.0 | Pair add/remove favorite-folder tests to catch inconsistent token checks across sibling backend actions. |
| [GHSA-xj25-753j-wgp9](https://github.com/advisories/GHSA-xj25-753j-wgp9) / CVE-2026-8415 | Express association reorder dialog | `concrete/controllers/dialog/express/association/reorder` can reorder associations without CSRF protection before 9.5.0 | Add relationship-ordering endpoints to CMS object-graph tests; prove only with synthetic Express objects. |

### Added validation boundaries for file-manager CSRF

- **File-manager token matrix:** For `approveVersion`, `rescan`, `rescanMultiple`, `star`, `addFavoriteFolder`, and `removeFavoriteFolder`, capture baseline same-origin requests, then replay no-token and invalid-token requests from an inert cross-origin harness. Evidence is the route/method, token state, response, and a lab marker such as version approval state, rescan timestamp, star flag, or favorite-folder membership.
- **Express association ordering:** Seed two disposable Express objects and a visible association order. Attempt only known canary IDs through the reorder dialog with valid, invalid, and missing tokens. Evidence is before/after ordering plus a patched negative control where available.
- **No destructive file proofs:** Do not rescan production libraries, approve real user uploads, reorder live business records, or alter persistent editor favorites outside a disposable lab account. These routes prove token-boundary drift; they do not require file disclosure or executable payloads.

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

- Lead with the exact boundary: **GET package install without CSRF**, **REST JSON type coercion into serialized block config**, **unauthenticated file-usage route**, **composer template path traversal**, **file/form/calendar/survey/conversation IDOR**, **token polarity or missing CSRF validation**, **package/core/log/file-manager/Express association state change without server-side token validation**, **bulk group assignment without authorization**, **inactive account to OAuth token**, **profile mass assignment of auth controls**, **summary-template hidden-page metadata disclosure**, **trusted dashboard/page-name render sink**, or **editor-controlled RSS URL to server-side fetch**.
- Include Concrete CMS version, role, route, request method, object ID, expected permission/token decision, actual decision, and disposable canary evidence.
- Keep all proof artifacts synthetic: lab package IDs, marker blocks, canary files, and controlled page paths. Avoid real marketplace installs, production secrets, private pages, and executable payloads.
