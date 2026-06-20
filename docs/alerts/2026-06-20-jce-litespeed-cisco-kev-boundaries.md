# JCE profile upload, LiteSpeed cPanel symlink, and Cisco SD-WAN file-write boundary checks

Source: hourly offensive-security scan, 2026-06-20. Primary entries: CISA KEV [CVE-2026-48907](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CVE-2026-54420](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [CVE-2026-20262](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); CVE records for [JCE](https://cveawg.mitre.org/api/cve/CVE-2026-48907), [LiteSpeed cPanel plugin](https://cveawg.mitre.org/api/cve/CVE-2026-54420), and [Cisco Catalyst SD-WAN Manager](https://cveawg.mitre.org/api/cve/CVE-2026-20262); LiteSpeed's [June 2026 plugin notice](https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/) and Cisco advisory [cisco-sa-sdwan-arbfw-c2rZvQ](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ).

These KEV additions are worth keeping as operator guidance because each turns a familiar admin surface into a reusable validation boundary: unauthenticated editor-profile creation leading to upload execution, shared-hosting symlink handling reaching root-context plugin behavior, and authenticated appliance uploads writing outside the intended file target.

## What changed

| Item | Confirmed detail | Operator value |
| --- | --- | --- |
| CVE-2026-48907 | The CVE record says the JCE editor extension for Joomla before 2.9.99.5 allowed unauthenticated users to create new editor profiles, ultimately resulting in PHP code upload and execution. | Add JCE profile-creation and file-manager upload paths to Joomla exposure reviews, especially when public sites expose editor or component routes that operators assume require back-office authentication. |
| CVE-2026-54420 | The CVE record and LiteSpeed notice say LiteSpeed's user-end cPanel plugin before 2.4.8, bundled with LiteSpeed WHM Plugin before 5.3.2.0, mishandled symlinks on shared hosting servers running CloudLinux/CageFS. LiteSpeed states exploitation required FTP or web-shell access and could escalate to root; active exploitation was reported in May/June 2026. | Treat shared-hosting plugins as privilege-boundary code, not just customer UI. Validate whether a low-privileged hosting account can influence plugin paths that later run in a more privileged context. |
| CVE-2026-20262 | Cisco says Catalyst SD-WAN Manager's web UI upload handling allowed an authenticated remote attacker with at least write access to create or overwrite files on the underlying filesystem; Cisco notes the written file could later be used to elevate to root. | Add post-auth arbitrary-file-write checks to SD-WAN Manager assessments, but prove only with disposable canaries and avoid production config, package, or service paths. |

## Scope and prerequisites

Validate only in owned labs or with explicit customer authorization.

Required inputs:

- Confirmed ownership and approved testing window for the Joomla, shared-hosting, or Cisco SD-WAN Manager environment.
- Product and version evidence:
  - JCE extension version, Joomla route exposure, and whether anonymous visitors can reach JCE component/profile/file-manager endpoints.
  - LiteSpeed WHM plugin and cPanel user-end plugin versions, plus whether CloudLinux/CageFS shared hosting is in use.
  - Cisco Catalyst SD-WAN Manager version, deployment type, and an approved low-privilege/write-capable test user.
- A pre-agreed canary target for any file-effect proof. Do not use real web shells, production content, customer secrets, or appliance configuration paths.

## Recon workflow

1. **Inventory the management surface.** For Joomla, enumerate installed editor components and public component routes from the application itself, not by scanning unrelated internet sites. For cPanel/LiteSpeed, determine whether the user-end plugin is installed for tenant accounts. For Cisco, map SD-WAN Manager web UI/API exposure and required role gates.
2. **Separate anonymous, tenant, and operator trust zones.** Record which requests are possible as an unauthenticated browser, a shared-hosting user, a low-privileged appliance user, and an administrator. The finding is the crossing between those roles and the resulting file/profile side effect.
3. **Look for path or profile control before impact.** Capture route reachability, form/API availability, upload metadata handling, profile creation behavior, and server-side path normalization decisions before attempting any file write.
4. **Use negative controls.** Compare vulnerable-looking behavior against fixed versions, disabled user-end plugins, or accounts without write permissions where the customer provides them.

## Non-destructive validation boundaries

### JCE editor-profile upload boundary

- Prove anonymous access to profile-management or upload-enabling routes with harmless requests first.
- If file upload validation is approved, use an inert text or image canary with a unique marker. Do not upload PHP, JSP, polyglot shells, or code that the web server can execute.
- Evidence should show the unexpected authorization state and the server-side storage/serving location for the canary. Stop before execution testing unless a separate lab-only exploit-chain approval exists.

### LiteSpeed cPanel shared-host symlink boundary

- Work only in a disposable shared-hosting account provided for the test.
- Use a synthetic symlink/canary directory under the tenant's home directory and a separate disposable target explicitly created for the assessment.
- Show whether user-controlled filesystem objects influence plugin operations that should remain inside the tenant boundary. Do not target `/etc`, WHM/cPanel configs, LiteSpeed configs, other tenants, shell startup files, keys, logs, or package/service paths.
- LiteSpeed's public notice mentions operational log patterns involving `generateEcCert` followed by `packageUserSize`; use those strings only as route/context clues, not as a production exploitation recipe.

### Cisco SD-WAN Manager file-write boundary

- Use an approved low-privilege or write-scoped test account and a lab or maintenance-window appliance where the owner has authorized file-effect proof.
- Target only a disposable canary path agreed in advance. Do not overwrite existing files and do not place content in paths that could be executed, loaded as config, or consumed by services.
- Capture request metadata, role, endpoint class, filename/path normalization evidence, and before/after canary file metadata. Avoid publishing endpoint-specific exploit payloads if they enable arbitrary overwrite.

## Evidence to capture

- Product/version evidence and whether the deployment falls in the affected range.
- Actor role: anonymous visitor, hosting tenant, low-privileged appliance user, or administrator.
- Route or UI/API class reached, with sensitive parameters redacted.
- Authorization expectation versus observed behavior.
- Canary-only file/profile side effect, including why the canary was disposable.
- Negative control from a fixed version, disabled plugin, denied role, or correctly confined path.

## Safety constraints

- Do not publish or reuse web-shell payloads, root-escalation chains, or arbitrary overwrite payloads.
- Do not write to production web roots, Joomla extension directories, cPanel/WHM/LiteSpeed configuration, other tenants' homes, Cisco SD-WAN Manager configuration, package, service, or log paths.
- Do not read secrets or prove impact by collecting credentials, sessions, keys, tenant files, SD-WAN control-plane data, or customer content.
- Keep reporting centered on the crossed boundary: **unexpected role to profile/upload/file operation**.

## Reporting heuristic

Strong finding titles:

- `Unauthenticated JCE profile creation enables unsafe upload surface`
- `Shared-hosting tenant symlink influences privileged LiteSpeed cPanel plugin operation`
- `Low-privilege Cisco SD-WAN Manager upload reaches arbitrary filesystem write boundary`

In the body, include the vulnerable version range, the actor role, the expected authorization or path confinement, the observed bypass, and a canary-only proof. Avoid claiming full remote code execution, root compromise, or tenant data access unless the customer separately authorized and demonstrated that complete chain in a lab.
