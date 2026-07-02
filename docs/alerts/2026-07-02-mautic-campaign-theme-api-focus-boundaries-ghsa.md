# Mautic campaign import, theme template, API ownership, and Focus SSRF boundaries

**Signal:** GitHub Security Advisories published a July 2 Mautic wave covering campaign import path traversal, theme-template SSTI, API v2 owner-scope authorization drift, and Focus component SSRF.

## Advisories covered

| Advisory | Boundary | Fixed versions |
| --- | --- | --- |
| [GHSA-6r9h-4h75-7q4x](https://github.com/advisories/GHSA-6r9h-4h75-7q4x) / CVE-2026-9559 | ZIP campaign import paths escape the intended temporary extraction root and can write PHP-capable files when the user has `campaign:imports:create`. | `mautic/core 7.1.2` |
| [GHSA-9fx4-7cmj-47vg](https://github.com/advisories/GHSA-9fx4-7cmj-47vg) / CVE-2026-9558 | Uploaded theme Twig templates render without a sandbox or strict function restrictions, crossing from theme authoring into server-side execution. | `7.1.2`, `6.0.9`, `5.2.11`; `4.4.20` via ELTS |
| [GHSA-2jrw-c95w-h43g](https://github.com/advisories/GHSA-2jrw-c95w-h43g) / CVE-2026-9808 | API Platform v2 endpoints fail to enforce owner-scoped roles such as `viewown` / `editown`, allowing access to another user's resources. | `7.1.2` |
| [GHSA-jmv8-8j9j-rcpc](https://github.com/advisories/GHSA-jmv8-8j9j-rcpc) / CVE-2026-9557 | Focus component URL handling can trigger server-originated requests to attacker-chosen destinations. | `7.1.2`, `6.0.9`, `5.2.11`; `4.4.20` via ELTS |

Adjacent Mautic stored-XSS advisories ([GHSA-5hvg-w58j-545m](https://github.com/advisories/GHSA-5hvg-w58j-545m), [GHSA-7h65-whp7-rgqf](https://github.com/advisories/GHSA-7h65-whp7-rgqf)) are useful supporting context but are not the primary operator pattern here.

## Why this is durable

Marketing automation platforms combine privileged content builders, ZIP/theme importers, URL-fetching widgets, and CRM-style owner scopes. This wave gives bug hunters a reusable checklist for **import-to-filesystem**, **template-author-to-runtime**, **API owner-scope**, and **server-side fetch** boundaries in any low-code or campaign-management product.

## Safe validation workflow

Use only an owned lab or an explicitly authorized customer test tenant. Seed canaries; do not use web shells, real campaign assets, customer contacts, production credentials, or internal services.

### 1. Establish role and version preconditions

- Record Mautic version and branch.
- Create two disposable users:
  - `attacker` with only the minimum permission under test.
  - `victim` owning synthetic contacts, companies, reports, campaigns, and assets.
- Capture the exact permission matrix: campaign import, theme create/upload, Focus component access, API credentials, and owner-scoped `viewown` / `editown` grants.

### 2. Campaign import path traversal canary

Evidence should prove whether archive entry names stay confined to the import temp root.

- Build a ZIP with harmless marker files only.
- Include one normal campaign export member and one traversal-looking member targeting a disposable canary path in a lab scratch directory.
- Import as the low-privilege `attacker` user with `campaign:imports:create`.
- Positive evidence is a marker write outside the intended extraction directory or an application log showing the unsafe destination path.
- Stop at marker files. Do not place PHP payloads in web roots, overwrite config/cache files, or attempt command execution.

### 3. Theme-template execution boundary

Evidence should show whether template authoring reaches unsandboxed Twig capabilities.

- Upload a minimal theme containing a benign Twig expression that renders a static canary value.
- If the lab permits, test only inert function/filter availability that proves sandbox absence without reading files or executing commands.
- Record the template filename, rendered canary, user permission, and fixed-version negative control.
- Do not publish or run command-execution templates, file-read probes, or environment-variable dumps.

### 4. API v2 owner-scope drift

Evidence should distinguish owner-only access from cross-owner access.

- As `victim`, create synthetic contacts, companies, and reports with distinctive canary names.
- As `attacker`, authenticate through API v2 with a role limited to `viewown` or `editown`.
- Request or update resources by known victim IDs.
- Positive evidence is a response or mutation for a victim-owned object that the UI or legacy API correctly denies.
- Keep proof to canary objects and redacted response fields; never dump real contacts, companies, reports, or lead histories.

### 5. Focus component SSRF boundary

Evidence should prove server-side fetch behavior without touching internal networks.

- Point Focus URL fields at an owned callback host that records method, path, source IP, and headers.
- Test parser edge cases only against owned domains and loopback services inside a disposable lab.
- Positive evidence is a callback from the Mautic server or a deterministic error difference showing outbound fetch attempts.
- Do not probe metadata services, RFC1918 production ranges, localhost admin panels, or third-party internal hosts.

## Report framing

Lead with the crossed boundary, not with generic advisory language:

- **Campaign import archive member -> outside extraction root file write**
- **Theme author permission -> unsandboxed Twig runtime capability**
- **Owner-scoped API credential -> cross-owner object read/write**
- **Focus URL field -> server-originated callback**

Strong reports include affected version, exact role grants, route or feature path, canary-only request/response evidence, before/after object ownership, callback logs for SSRF, and a fixed-version negative control.

## Sources

- [GHSA-6r9h-4h75-7q4x: Mautic vulnerable to Path Traversal via Campaign Import](https://github.com/advisories/GHSA-6r9h-4h75-7q4x)
- [GHSA-9fx4-7cmj-47vg: Mautic has Server-Side Template Injection in Theme Templates](https://github.com/advisories/GHSA-9fx4-7cmj-47vg)
- [GHSA-2jrw-c95w-h43g: Mautic has an Authorization Bypass in API v2 Endpoints](https://github.com/advisories/GHSA-2jrw-c95w-h43g)
- [GHSA-jmv8-8j9j-rcpc: Mautic Focus component vulnerable to SSRF](https://github.com/advisories/GHSA-jmv8-8j9j-rcpc)
