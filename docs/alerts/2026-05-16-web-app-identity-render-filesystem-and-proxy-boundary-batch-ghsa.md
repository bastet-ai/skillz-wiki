# Web app identity, render, filesystem, and proxy-boundary batch

Sources: GitHub Security Advisories updates on 2026-05-15.

This batch is durable because older commerce stacks, clinical apps, note tools, middleware, identity providers, registries, and Electron clients keep crossing the same boundaries: predictable sessions, template execution, file writes, header forwarding, LDAP filters, redirects, publisher-controlled HTML, and renderer sinks. Any value that started in a request, model, asset name, profile, or upstream error flow needs contextual validation before it becomes identity, code, path, URL, or HTML.

## Advisories covered

- **Magento LTS: Reflected XSS - Import -> Data Flow (profiles) ** — [GHSA-x8jv-q8j2-487c](https://github.com/advisories/GHSA-x8jv-q8j2-487c) / CVE-2026-42458 (medium).
- **Magento LTS Vulnerable to Open Redirect via Unvalidated `uenc` Parameter in `stockAction()`** — [GHSA-qpgq-5g92-j5q8](https://github.com/advisories/GHSA-qpgq-5g92-j5q8) / CVE-2026-42207 (medium).
- **Magento LTS has Weak API Session ID — Predictable MD5 of Time-Derived Inputs** — [GHSA-2cwr-gcf9-pvxr](https://github.com/advisories/GHSA-2cwr-gcf9-pvxr) / CVE-2026-42155 (critical).
- **OpenMRS has Stored Velocity SSTI to RCE via ConceptReferenceRange** — [GHSA-xj4f-8jjg-vx4q](https://github.com/advisories/GHSA-xj4f-8jjg-vx4q) / CVE-2026-41258 (critical).
- **Traefik's errors middleware forwards Authorization and Cookie headers to separate error page service** — [GHSA-p6hg-qh38-555r](https://github.com/advisories/GHSA-p6hg-qh38-555r) / CVE-2026-41181 (medium).
- **ZITADEL has LDAP Filter Injection in Login Flow** — [GHSA-rxvx-hhpj-q6px](https://github.com/advisories/GHSA-rxvx-hhpj-q6px) / CVE-2026-44671 (high).
- **MCP Registry has open redirect via protocol-relative path in trailing-slash middleware** — [GHSA-v8vw-gw5j-w7m6](https://github.com/advisories/GHSA-v8vw-gw5j-w7m6) / CVE-2026-44427 (medium).
- **MCP Registry vulnerable to stored XSS in catalogue UI via attribute-quote breakout in publisher-controlled `websiteUrl`** — [GHSA-rqv2-m695-f8j4](https://github.com/advisories/GHSA-rqv2-m695-f8j4) / CVE-2026-44429 (medium).
- **SiYuan: Electron Renderer RCE via decodeURIComponent-driven tooltip XSS in aria-label sink (incomplete fix for CVE-2026-34585)** — [GHSA-25rp-h46x-2hjm](https://github.com/advisories/GHSA-25rp-h46x-2hjm) / CVE-2026-44588 (critical).
- **Note Mark has a JWT Secret Weakness that allows Full Account Takeover via Token Forgery** — [GHSA-q6mh-rqwh-g786](https://github.com/advisories/GHSA-q6mh-rqwh-g786) / CVE-2026-44523 (critical).
- **Note Mark: Arbitrary File Write via Path Traversal in Asset Names Leads to Remote Code Execution** — [GHSA-g49p-4qxj-88v3](https://github.com/advisories/GHSA-g49p-4qxj-88v3) / CVE-2026-44522 (high).

## Operator triage

1. Prioritize Magento LTS, OpenMRS, ZITADEL, Note Mark, SiYuan desktop/Electron, Traefik error middleware, and MCP Registry deployments that are externally reachable or process untrusted publisher/user content.
2. Test authentication/session generation for predictability, LDAP login filters for injection, and JWT secrets for default/weak values; rotate tokens if weak or guessable material may have been used.
3. Review template/profile/model-description/website URL and tooltip/aria-label render paths for stored or reflected XSS/SSTI, especially where an Electron renderer can reach local APIs.
4. Audit asset upload/write paths for traversal and RCE chains; inspect Note Mark and similar apps for unexpected files under writable static, template, or startup paths.
5. For Traefik error middleware, confirm Authorization/Cookie headers are stripped before forwarding to separate error-page services.

## Durable controls

- Session IDs, JWT secrets, and first-party identity tokens must use high-entropy server-generated material, with rotation paths and telemetry for impossible reuse.
- LDAP filters, redirect targets, and proxy destinations require structured builders/allowlists; string concatenation and protocol-relative paths are boundary failures.
- Template languages such as Velocity are code execution surfaces. Untrusted content should never enter template evaluation contexts without a sandbox designed for hostile input.
- File and asset names must be resolved against an immutable storage root after decoding and normalization; reject traversal, absolute paths, symlinks, and executable destinations.
- Reverse proxies should treat error services as separate origins and explicitly drop credentials, cookies, Authorization, and tenant headers unless the upstream is equally trusted.
