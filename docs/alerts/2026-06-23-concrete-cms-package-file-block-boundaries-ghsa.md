# Concrete CMS package, file, and block boundary checks

Source: hourly offensive-security scan, 2026-06-23. Primary entries: GitHub Advisory Database [GHSA-r42c-3rr2-jrfp](https://github.com/advisories/GHSA-r42c-3rr2-jrfp), [GHSA-pv2v-6w2v-97x6](https://github.com/advisories/GHSA-pv2v-6w2v-97x6), [GHSA-4g7q-44qp-cc5c](https://github.com/advisories/GHSA-4g7q-44qp-cc5c), and [GHSA-645j-cm4x-3xvw](https://github.com/advisories/GHSA-645j-cm4x-3xvw).

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

- Lead with the exact boundary: **GET package install without CSRF**, **REST JSON type coercion into serialized block config**, **unauthenticated file-usage route**, or **composer template path traversal**.
- Include Concrete CMS version, role, route, request method, object ID, expected permission/token decision, actual decision, and disposable canary evidence.
- Keep all proof artifacts synthetic: lab package IDs, marker blocks, canary files, and controlled page paths. Avoid real marketplace installs, production secrets, private pages, and executable payloads.
