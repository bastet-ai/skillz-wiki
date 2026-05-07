# FacturaScripts immutable identity boundary bypass

**Signal:** GitHub Security Advisories REST fallback surfaced **GHSA-pp79-hqv6-vmc3 / CVE-2026-32699** for FacturaScripts allowing the supposedly immutable `nick` account identifier to be changed through a crafted `/EditUser` POST body.

## Advisory covered

- **FacturaScripts `nick` parameter unauthorized modification** — [GHSA-pp79-hqv6-vmc3](https://github.com/advisories/GHSA-pp79-hqv6-vmc3) / [CVE-2026-32699](https://www.cve.org/CVERecord?id=CVE-2026-32699): FacturaScripts `facturascripts/facturascripts` versions `<= 2024.92.x-dev` process the `nick` form-data parameter in the EditUser controller even though the UI treats it as non-editable. No patched version is listed in the advisory at publication time.

## Why this is durable

The bug is a classic UI-only trust failure. A field hidden or disabled in the browser is not protected unless the server enforces the same invariant. For identity fields, this becomes more than profile tampering: usernames often anchor audit logs, ownership references, notification routing, and incident timelines. Letting a user rewrite an immutable identifier can corrupt accountability even when passwords and sessions remain intact.

## Immediate triage

1. Inventory FacturaScripts deployments and confirm whether `facturascripts/facturascripts` is at or below the affected `2024.92.x-dev` line.
2. Until a fixed release is available, block or ignore client-supplied `nick` changes in the server-side EditUser path. Treat `nick` as write-once unless an explicit privileged admin rename workflow exists.
3. Review account records for recent `nick` changes, especially changes involving administrator, finance, integration, or service accounts.
4. Correlate audit logs by stable database user ID, not display name or username alone, when reconstructing activity around the exposure window.
5. Preserve evidence before renaming accounts back; username churn can destroy the very timeline needed to understand abuse.

## Hunt prompts

- POST requests to `/EditUser` containing a `nick` parameter, especially where the authenticated principal is editing their own profile.
- Sudden logouts followed by successful login under a different username with the same account history.
- Audit events where the actor name changes while internal user ID, email, token, or password hash remains constant.
- Administrator-like names reassigned, deleted, or replaced by lookalike usernames.
- Downstream records with orphaned username references that no longer map cleanly to a current account.

## Durable controls

- Enforce immutability server-side for usernames, tenant IDs, owner IDs, role names, account UUIDs, and other identity anchors.
- Use stable opaque IDs for authorization, ownership, and audit joins; reserve mutable display names for presentation only.
- If renames are a product requirement, put them behind explicit privileged workflows with before/after audit records, reason codes, approvals, and notification to the affected user.
- Reject unexpected form fields rather than silently accepting mass-assignment-like parameters.
- Add regression tests that submit disabled, hidden, omitted-from-UI, and manually injected fields through profile update endpoints.

## Related Wisdom

- [FacturaScripts reflected XSS via raw error rendering](2026-02-02-facturascripts-reflected-xss-ghsa-g6w2-q45f-xrp4.md)
- [Web app auth, render, and export-boundary batch](2026-05-06-web-app-auth-render-and-export-boundary-batch-ghsa.md)
