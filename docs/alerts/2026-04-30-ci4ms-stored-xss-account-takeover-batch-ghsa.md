# CI4MS stored DOM XSS account-takeover batch (GHSA-5ghq-42rg-769x / GHSA-qxpq-82f3-xj47)

**Signal:** GitHub Security Advisories updated **2026-04-30**. CI4MS fixed stored DOM XSS paths that can lead to full account takeover and privilege escalation.

## What it is
Two CI4MS advisories describe attacker-controlled stored DOM XSS reaching privileged users:

- `GHSA-5ghq-42rg-769x` / CVE-2026-35035: System Settings → Company Information content can inject XSS payloads onto public-facing landing pages, creating full platform compromise and account-takeover risk. Affected package `ci4-cms-erp/ci4ms <= 0.31.1.0`; fixed in `0.31.2.0`.
- `GHSA-qxpq-82f3-xj47` / CVE-2026-41201: Backup Management filename handling can be manipulated through an SQL file to store hidden XSS payloads, enabling account takeover and privilege escalation. Affected package `ci4-cms-erp/ci4ms < 0.31.5.0`; fixed in `0.31.5.0`.

References: <https://github.com/advisories/GHSA-5ghq-42rg-769x>, <https://github.com/advisories/GHSA-qxpq-82f3-xj47>

## Triage
1. Inventory CI4MS instances and identify public landing pages, admin panels, and backup-management access.
2. Check installed `ci4-cms-erp/ci4ms` versions; prioritize internet-facing or multi-role environments.
3. Review Company Information fields, landing-page content, and backup filenames/imported SQL metadata for hidden script, event-handler, SVG, iframe, or encoded payloads.
4. Treat admin sessions that viewed tainted pages or backup screens as potentially compromised.

## Mitigation
- Upgrade CI4MS to `0.31.5.0` or later to cover both advisories.
- Sanitize existing Company Information and backup metadata before exposing pages to administrators.
- Restrict backup import/management to trusted administrators and scan imported SQL/metadata for active content.
- Add a restrictive CSP and HttpOnly/SameSite cookies as defense-in-depth, but do not rely on CSP instead of patching.

## Detection ideas
- Search web logs for admin visits to public landing pages or backup pages shortly before role changes, password changes, or new accounts.
- Hunt database fields and backup metadata for `<script`, `onerror=`, `onload=`, `javascript:`, `data:text/html`, SVG payloads, or unusual encoded HTML.
- Review audit logs for privilege changes after backup imports or Company Information edits.

## Durable lesson
Stored XSS in admin-visible CMS metadata is an identity compromise path. Public content fields, backup filenames, and restore metadata need the same output encoding and active-content stripping as rich user input.
