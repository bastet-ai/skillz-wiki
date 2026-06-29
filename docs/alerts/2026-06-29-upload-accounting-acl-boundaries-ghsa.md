# Upload, accounting, and ACL filesystem boundary checks

Source: hourly offensive-security scan, 2026-06-29. Primary entries: GitHub Advisory Database [GHSA-gxrr-wfg5-xqqf](https://github.com/advisories/GHSA-gxrr-wfg5-xqqf) / CVE-2026-56290, [GHSA-wghr-7f2j-9x3f](https://github.com/advisories/GHSA-wghr-7f2j-9x3f) / CVE-2026-56124, [GHSA-w5j4-x499-pfwp](https://github.com/advisories/GHSA-w5j4-x499-pfwp) / CVE-2026-40524, [GHSA-8ccm-j5hq-9jhr](https://github.com/advisories/GHSA-8ccm-j5hq-9jhr) / CVE-2026-40523, and [GHSA-53ch-pxc8-6g72](https://github.com/advisories/GHSA-53ch-pxc8-6g72) / CVE-2026-54369.

These advisories are useful to operators because they repeat boundaries that are easy to miss during authorized assessments: CMS upload controls that decide whether uploaded bytes can become executable server-side content, upload portals that leak their full metadata tables into client-side state, accounting report filters that cross into SQL construction, and privileged filesystem helpers that follow path components after validation.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-gxrr-wfg5-xqqf](https://github.com/advisories/GHSA-gxrr-wfg5-xqqf) / CVE-2026-56290 | Joomla Page Builder CK extension | unauthenticated file upload could accept executable files and lead to RCE | Add unauthenticated extension media/upload endpoints to CMS route matrices; prove with benign marker files and storage/execution decision evidence, not shells. |
| [GHSA-wghr-7f2j-9x3f](https://github.com/advisories/GHSA-wghr-7f2j-9x3f) / CVE-2026-56124 | phpUploader | index view embedded the complete uploaded-files table as JSON in an inline script | Inspect upload portals for server-side metadata serialized into public pages: uploader IPs, internal filenames, content hashes, and key/hash material. |
| [GHSA-w5j4-x499-pfwp](https://github.com/advisories/GHSA-w5j4-x499-pfwp) / CVE-2026-40524 | FrontAccounting | `filter_type` reached a SQL `IN()` clause without parameterization | Include report filter arrays and comma-list parameters in SQLi tests; focus on boolean response-size differentials with seeded canary rows. |
| [GHSA-8ccm-j5hq-9jhr](https://github.com/advisories/GHSA-8ccm-j5hq-9jhr) / CVE-2026-40523 | FrontAccounting | Audit Trail report POST parameters crossed into SQL query construction | Add finance/reporting endpoints to authenticated SQLi matrices, especially report builders that join broad ledger tables. |
| [GHSA-53ch-pxc8-6g72](https://github.com/advisories/GHSA-53ch-pxc8-6g72) / CVE-2026-54369 | `acl` path-based helper functions | pathname components could be swapped for symlinks before ACL read/write operations | When reviewing privileged file-management tools, test path canonicalization, symlink races, and final target binding with disposable canary paths. |

The same scan included several generic WordPress plugin XSS, broken-access-control, arbitrary-deletion, IDOR, and business-logic advisories. They were marked processed but not promoted as standalone wiki content because the available records did not add a reusable operator workflow beyond existing role-matrix and trusted-render testing patterns.

## Replayable validation boundaries

### CMS upload-to-executable-content harness

- Preconditions: authorized lab CMS, disposable extension/plugin instance, isolated upload directory, and a benign marker file with non-executable contents.
- Enumerate unauthenticated and low-privilege upload routes, including builder/media endpoints, AJAX upload handlers, drag-and-drop widgets, and template asset imports.
- Capture each route's authentication decision, allowed extension/MIME decision, final stored path, web reachability, and fixed-version denial.
- Use safe canaries such as text markers or image/polyglot-looking filenames that do not execute. Do not upload web shells, server-side script payloads, or files into production web roots.

### Upload metadata exposure harness

- Preconditions: disposable upload portal, two lab users or anonymous upload sessions, synthetic files, and known marker filenames/hashes.
- After uploads, inspect public and authenticated pages for inline JSON, hydration state, JavaScript variables, debug endpoints, and API responses that serialize more than the current user's file metadata.
- Evidence should show only synthetic uploader IPs, marker filenames, content hashes, or row counts. Redact or avoid real addresses, user identifiers, key hashes, internal storage names, and non-test files.
- Add a fixed-version negative control showing the table is scoped, minimized, or withheld from the page.

### Accounting/report SQL construction harness

- Preconditions: lab FrontAccounting-style instance, disposable low-privilege account with the relevant reporting permission, and seeded canary journal rows.
- Prioritize report filters that accept comma lists, date ranges, enum arrays, account IDs, sorting controls, and audit-history selectors.
- Compare baseline, boolean-true, boolean-false, and harmless time/size differential probes against seeded canary rows. Capture request, permission, parameter, differential, and fixed-version behavior.
- Do not dump live ledgers, customer invoices, payroll data, credentials, or run destructive SQL. Keep tests to synthetic rows and stop at proof of query influence.

### Privileged ACL/path helper harness

- Preconditions: local lab host, disposable privileged helper or test wrapper, scratch directory tree, canary target files, and no real system files in scope.
- Exercise every pathname component, not just the leaf: parent directories, symlink swaps, bind mounts where permitted, relative paths, trailing slashes, and time-of-check/time-of-use windows.
- Evidence should bind the requested path, canonical path before operation, final target observed by the ACL operation, and whether a symlink swap changed the target.
- Do not modify ACLs on production files, credentials, user home directories, service configs, or shared tenant paths.

## Reporting notes

- Lead with the crossed boundary: **unauthenticated upload route to executable storage**, **upload table to public inline state**, **report filter to SQL clause**, or **validated path to symlink-resolved ACL target**.
- Include version, route/function name, role or unauthenticated state, exact parameter class, storage path or SQL clause context, synthetic canary evidence, and fixed-version negative controls.
- Keep proofs reversible: lab CMS instances, marker files, seeded finance rows, fake upload metadata, scratch ACL trees, and no production secret exposure.
