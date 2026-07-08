# Joomla page-builder upload and ColdFusion traversal KEV boundary checks

Source: CISA Known Exploited Vulnerabilities catalog update released 2026-07-07, plus CVE/NVD records for [CVE-2026-48908](https://nvd.nist.gov/vuln/detail/CVE-2026-48908), [CVE-2026-56290](https://nvd.nist.gov/vuln/detail/CVE-2026-56290), and [CVE-2026-48282](https://nvd.nist.gov/vuln/detail/CVE-2026-48282). Vendor references include [SP Page Builder](https://www.joomshaper.com/page-builder), [JoomlaCK](https://www.joomlack.fr/), and [Adobe APSB26-68](https://helpx.adobe.com/security/products/coldfusion/apsb26-68.html).

This batch is durable because the KEV additions point at two reusable operator workflows: unauthenticated CMS extension upload surfaces where extension-specific media endpoints cross into executable PHP storage, and ColdFusion path handling where traversal reaches code-execution context without user interaction. Keep validation scoped to owned or explicitly authorized instances and use inert marker files only.

## What changed

| CVE | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [CVE-2026-48908](https://nvd.nist.gov/vuln/detail/CVE-2026-48908) | JoomShaper SP Page Builder extension for Joomla, versions 1.0.0 through 6.6.1 | unauthenticated upload path accepts arbitrary files that can become executable PHP | Add extension-specific unauthenticated upload probes to Joomla page-builder assessment checklists; prove with non-executable marker files unless a lab explicitly permits PHP execution. |
| [CVE-2026-56290](https://nvd.nist.gov/vuln/detail/CVE-2026-56290) | JoomlaCK Page Builder CK extension for Joomla, versions 1.0 through 3.6.0 | unauthenticated arbitrary file upload permits executable file placement and RCE | Treat page-builder extensions as independent upload surfaces, not just CMS core media managers. |
| [CVE-2026-48282](https://nvd.nist.gov/vuln/detail/CVE-2026-48282) | Adobe ColdFusion 2025.9, 2023.20, and earlier | pathname restriction failure can traverse to an execution-relevant file boundary | Validate ColdFusion-exposed file routes for decode-order, prefix, and extension-mapping drift with disposable canaries only. |

## Joomla page-builder upload validation

1. **Fingerprint product and extension, not just CMS core.** Capture Joomla core version, extension name, extension version, exposed page-builder routes, and whether upload endpoints are reachable before authentication.
2. **Use benign multipart canaries first.** Submit a text marker and an image-like marker with a harmless extension. Record status code, response JSON, returned file path, and whether the file is reachable over HTTP.
3. **Check filename and MIME controls separately.** Exercise original filename, content type, magic bytes, extension allowlist, path normalization, and storage directory decisions. Do not upload web shells or execute code on production targets.
4. **Prove executable placement only in a lab.** If explicit lab authorization permits PHP execution testing, use a minimal inert marker such as a fixed string response and delete the file afterward. For customer or bounty targets, stop at evidence that a dangerous extension is accepted into an executable directory.
5. **Include negative controls.** Compare patched extension versions, authenticated-only endpoints, blocked extensions, and storage outside PHP-executed paths.

## ColdFusion traversal validation

1. **Inventory reachable ColdFusion routes.** Record version evidence, exposed CFML/admin paths, document roots, upload/import/download handlers, and any reverse-proxy path rewriting that may change decode order.
2. **Use marker files under authorized roots.** Place disposable canaries in lab-controlled directories and attempt traversal only toward those markers. Never read configuration, credentials, templates, logs, or customer files.
3. **Vary path canonicalization forms.** Test single/double URL encoding, mixed separators, dot segments, trailing spaces/dots, case changes, and extension mapping boundaries when they are in scope.
4. **Stop before unsafe writes or execution.** Positive evidence can be a canary read, route dispatch to a marker template in a disposable lab, or a decision table showing traversal escaping the intended directory. Do not publish payloads that overwrite CFML, deploy web shells, or trigger production code execution.
5. **Capture proxy/origin differentials.** Include raw request path, proxy-normalized path, ColdFusion-observed path if logged, response marker, and patched-version behavior.

## Reporting notes

- Name the crossed boundary precisely: **unauthenticated page-builder upload to executable PHP storage**, **extension upload policy to CMS web root**, or **ColdFusion route pathname to outside-root execution context**.
- Evidence should include version, endpoint, auth state, request shape, allowed extension/MIME result, storage path, route reachability, and safe canary proof.
- Keep all artifacts synthetic: disposable Joomla sites, lab ColdFusion instances, marker files, owned callback/log endpoints, and redacted paths. Do not include exploit shells, real filesystem listings, credentials, or production code-execution output.
