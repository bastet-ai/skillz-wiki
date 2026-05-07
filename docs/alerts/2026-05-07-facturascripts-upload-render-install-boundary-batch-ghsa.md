# FacturaScripts upload, render, and install-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced six new FacturaScripts advisories published on 2026-05-07. The cluster spans plugin ZIP extraction, product-image upload, installer debug exposure, product-search rendering, cookie rendering, and Library image metadata handling.

## Advisories covered

- **Plugin ZIP upload Zip Slip to arbitrary file write / RCE** — [GHSA-3pgc-xqg9-cfr6](https://github.com/advisories/GHSA-3pgc-xqg9-cfr6) / [CVE-2026-27891](https://www.cve.org/CVERecord?id=CVE-2026-27891): `facturascripts/facturascripts <= 2025.71` accepts plugin ZIP entries such as `ValidPlugin/../../shell.php`, passing the one-root-folder check while extracting outside the intended plugin directory. No patched version is listed in the advisory at publication time.
- **Product image upload executable-file bypass** — [GHSA-vf3q-frmr-vrr9](https://github.com/advisories/GHSA-vf3q-frmr-vrr9) / [CVE-2026-42879](https://www.cve.org/CVERecord?id=CVE-2026-42879): authenticated product-image uploads trust an `image/*` MIME result and preserve attacker-controlled executable filenames, allowing PHP payloads disguised with image magic bytes to land under web-accessible `MyFiles` paths. Affected range: `<= 2025.81`; no patched version listed.
- **Unauthenticated installer `phpinfo()` disclosure** — [GHSA-vrxf-vrc4-22p7](https://github.com/advisories/GHSA-vrxf-vrc4-22p7) / [CVE-2026-42878](https://www.cve.org/CVERecord?id=CVE-2026-42878): a fresh, unconfigured deployment can expose full PHP configuration and environment data through `/?phpinfo=TRUE`. Affected metadata lists `>= 2026, <= 2026.1`; no patched version listed.
- **Stored XSS in product reference rendering** — [GHSA-r736-2678-fcrx](https://github.com/advisories/GHSA-r736-2678-fcrx) / [CVE-2026-42877](https://www.cve.org/CVERecord?id=CVE-2026-42877): product references are inserted into sales/purchases product-search modal `onclick` attributes without JavaScript-context-safe escaping, then decoded through `innerHTML`, enabling stored XSS against users who open the modal.
- **Reflected XSS through `fsNick` cookie rendering** — [GHSA-gq5c-rw37-g46c](https://github.com/advisories/GHSA-gq5c-rw37-g46c) / [CVE-2026-27964](https://www.cve.org/CVERecord?id=CVE-2026-27964): manipulated cookie content can render into HTML and execute before the invalid session is fully rejected.
- **Library image EXIF / metadata leakage** — [GHSA-q7f2-rv22-2xgr](https://github.com/advisories/GHSA-q7f2-rv22-2xgr) / [CVE-2026-27892](https://www.cve.org/CVERecord?id=CVE-2026-27892): uploaded Library images are stored and served without stripping embedded GPS, device, timestamp, thumbnail, XMP/IPTC, or comment metadata, creating a one-to-many PII exposure path inside ERP workflows.

## Why this is durable

This batch is a useful ERP hardening pattern: business apps often combine high-privilege plugin systems, user-uploaded files, installation helpers, browser-rendered operational data, and employee/customer documents. Each boundary must fail closed independently. A MIME check is not an execution policy; a ZIP root-folder check is not path containment; a logout redirect is not output encoding; an installer helper is not safe just because it only exists before configuration; and shared document libraries need privacy processing, not just access control.

## Immediate triage

1. Inventory exposed FacturaScripts instances and record version, deployment state, webroot layout, upload paths, enabled modules, and installed plugins.
2. If plugin upload is enabled, restrict it to trusted administrators only, preserve plugin ZIP/upload logs, and inspect the application tree for files written outside expected plugin directories.
3. Disable direct execution in upload/library directories. At minimum, configure the web server to serve uploaded files as inert content and deny PHP execution under `MyFiles`, plugin staging, and Library storage paths.
4. Remove or block the installer `phpinfo` path on any deployment reachable before setup completes; do not expose fresh installs directly to the Internet.
5. Treat image uploads as untrusted binaries: validate extension, MIME, and decoded content; generate server-side names; strip metadata; and serve through a controller rather than direct webroot paths.
6. Review product references, cookies, and modal-rendered fields for HTML/JavaScript context escaping, especially values inserted into event handlers or later passed through `innerHTML`.

## Hunt prompts

- Plugin ZIP uploads followed by unexpected `.php`, `.phtml`, `.phar`, or newly modified files outside the plugin directory.
- Requests to uploaded paths under `MyFiles/YYYY/MM/` with query parameters such as `cmd`, `exec`, `id`, `whoami`, or shell-like arguments.
- Requests for `/?phpinfo=TRUE`, especially before configuration was completed or from Internet scanners.
- Product references containing quotes, HTML entities, script-like strings, event-handler fragments, or `alert(`/`fetch(`/`XMLHttpRequest` payloads.
- Requests with unusual `fsNick` cookie values containing `<`, `>`, quotes, encoded script tags, or JavaScript URLs.
- Library downloads of images that still contain GPS coordinates, thumbnails, camera serials, author names, or organization metadata.

## Durable controls

- Extract archives into a temporary directory, canonicalize every entry with `realpath`/equivalent, and reject paths escaping the intended destination before moving files into place.
- Never preserve client-supplied executable filenames for uploads. Generate names server-side, allowlist extensions, and enforce storage outside executable webroots.
- Keep installation/debug helpers unavailable in production and require localhost/admin-only access for diagnostics that reveal environment state.
- Encode by sink, not by storage: HTML text, HTML attributes, JavaScript strings, URLs, and JSON/HTML transfer all need different escaping rules.
- Avoid inline JavaScript event attributes for dynamic data; bind event handlers separately and pass IDs through data attributes after encoding.
- Strip EXIF/XMP/IPTC metadata from user-uploaded images by default, and provide an explicit, audited exception path when metadata retention is a business requirement.

## Related Wisdom

- [FacturaScripts immutable identity boundary bypass](2026-05-07-facturascripts-immutable-identity-boundary-ghsa-pp79-hqv6-vmc3.md)
- [FacturaScripts reflected XSS via raw error rendering](2026-02-02-facturascripts-reflected-xss-ghsa-g6w2-q45f-xrp4.md)
- [Archive and file-extraction boundary batch](2026-05-06-archive-and-file-extraction-boundary-batch-ghsa.md)
- [Web app auth, render, and export-boundary batch](2026-05-06-web-app-auth-render-and-export-boundary-batch-ghsa.md)
