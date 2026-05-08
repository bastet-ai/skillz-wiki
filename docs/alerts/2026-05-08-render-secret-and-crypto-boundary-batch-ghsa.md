# Render, secret-storage, and crypto-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-08 16:15 UTC** batch where data-format helpers and application modules crossed trust boundaries: spreadsheet render/load paths, cleartext UI storage, and variable-time cryptography.

## Advisories covered

- **PhpSpreadsheet HTML writer XSS via number-format substitution** — [GHSA-6wpp-88cp-7q68](https://github.com/advisories/GHSA-6wpp-88cp-7q68): formatted cell output using `@` text substitution can bypass expected HTML escaping. Patch to fixed lines: `1.30.4+`, `2.1.16+`, `2.4.5+`, `3.10.5+`, or `5.7.0+`.
- **PhpSpreadsheet IOFactory SSRF/RCE when `$filename` is user-controlled** — [GHSA-q4q6-r8wh-5cgh](https://github.com/advisories/GHSA-q4q6-r8wh-5cgh): already tracked, but still relevant to the same spreadsheet trust boundary. Patch to `1.30.3+`, `2.1.15+`, `2.4.4+`, `3.10.4+`, or `5.6.0+`.
- **TYPO3 CMS cleartext password in user settings module** — [GHSA-xvv6-p4wf-mvx7](https://github.com/advisories/GHSA-xvv6-p4wf-mvx7): `typo3/cms-backend` `14.2.0` stored a password in user settings; patch to `14.3.0+` and rotate exposed credentials.
- **phpseclib AES-CBC padding oracle timing** — [GHSA-94g3-g5v7-q4jg](https://github.com/advisories/GHSA-94g3-g5v7-q4jg): variable-time unpadding in affected 1.x/2.x/3.x lines; patch to `1.0.27+`, `2.0.52+`, or `3.0.50+`.
- **phpseclib SSH2 HMAC comparison timing** — [GHSA-r854-jrxh-36qx](https://github.com/advisories/GHSA-r854-jrxh-36qx): `!=` instead of constant-time comparison in `SSH2::get_binary_packet()`; patch to `1.0.28+`, `2.0.53+`, or `3.0.51+`.

## Why this is durable

Format libraries and admin modules often sit at misleadingly quiet boundaries. A spreadsheet cell can become HTML, a filename can become a URL fetch or parser dispatch, a settings field can become durable credential storage, and a tiny comparison branch can become a remote oracle. Treat conversion helpers and crypto glue as policy-enforcement code, not passive utilities.

## Immediate triage

1. Search dependency inventories for `phpoffice/phpspreadsheet`, `typo3/cms-backend`, and `phpseclib/phpseclib`; patch all affected major lines rather than only the current app path.
2. Find services that accept user-supplied spreadsheets and render them to HTML, PDF, previews, email bodies, tickets, or admin dashboards.
3. Review any use of `IOFactory::load()` or loader auto-detection where filenames, URLs, temp paths, or uploaded file metadata are user-influenced.
4. For TYPO3 `14.2.0`, rotate any password that may have been stored in the user settings module and check backups/log exports for accidental persistence.
5. For phpseclib, prioritize internet-facing SSH/SFTP/VPN/admin integrations and any service exposing padding-oracle feedback through timing, retries, or error differences.

## Durable controls

- Treat all document-to-HTML conversions as untrusted render paths: escape after final formatting, sanitize generated HTML, and serve previews in isolated origins with strict CSP.
- Decouple uploaded object identity from local filenames and remote URLs. Loader APIs should receive a staged, policy-checked file handle, not arbitrary user strings.
- Ban durable cleartext credential storage in preferences, settings blobs, logs, browser-accessible JSON, or backup-friendly config tables.
- Use constant-time comparisons and constant-behavior padding/error handling in crypto-adjacent code; add regression tests for timing-sensitive branches.
- Log render/load decisions with source object, tenant, canonical path/URL, selected parser, output sink, and policy verdict for later reconstruction.
