# Container, CMS filesystem, and session-boundary batch

**Signal:** The **2026-05-08 20:15 UTC** advisory scan surfaced another batch of "trusted path or trusted session" failures: symlink traversal during container file copy, CMS Zip Slip/RCE and session-state bypasses, SSRF bypass follow-up, and OpenClaw browser-tab SSRF policy gaps.

## Advisory cluster

- **Kata Containers CopyFile symlink policy subversion** — [GHSA-q49m-57vm-c8cc](https://github.com/advisories/GHSA-q49m-57vm-c8cc): `github.com/kata-containers/kata-containers` builds before `1b9e49eb2763` could let symlinks undermine file-copy policy.
- **Admidio SSRF incomplete fix** — [GHSA-hcjj-chvw-fmw9](https://github.com/advisories/GHSA-hcjj-chvw-fmw9): `admidio/admidio <= 5.0.8` still had a bypass for the CVE-2026-32812 SSRF control.
- **CI4MS session and destructive admin paths** — [GHSA-5hfv-c864-qcq9](https://github.com/advisories/GHSA-5hfv-c864-qcq9), [GHSA-vgrf-pr28-vf98](https://github.com/advisories/GHSA-vgrf-pr28-vf98), [GHSA-xv3r-vr59-95rg](https://github.com/advisories/GHSA-xv3r-vr59-95rg), [GHSA-xp9f-pvvc-57p4](https://github.com/advisories/GHSA-xp9f-pvvc-57p4): `ci4-cms-erp/ci4ms` had deactivated-user session bypass, arbitrary table drop, and two Zip Slip-to-RCE paths. Patch to the fixed train (`0.31.5.0+` for Zip Slip; newer fixed releases where available for the admin/session issues).
- **OpenClaw symlink traversal and browser-tab SSRF bypasses** — [GHSA-35mw-5vvr-vrxc](https://github.com/advisories/GHSA-35mw-5vvr-vrxc), [GHSA-rj2p-j66c-mgqh](https://github.com/advisories/GHSA-rj2p-j66c-mgqh): patch OpenClaw to `2026.4.5+` for symlink containment and `2026.4.10+` for browser tab `select`/`close` SSRF policy enforcement.
- **Grav admin page-title stored XSS** — [GHSA-fmg2-f5r9-24qc](https://github.com/advisories/GHSA-fmg2-f5r9-24qc): `getgrav/grav < 1.7.49.5` could store XSS through `data[header][title]` in admin.

## Why this matters

Containment and authorization checks are often implemented at the obvious API edge, then bypassed by a later path re-resolution, archive extraction, stale session, or alternate route. Treat every filesystem operation and admin mutation as a second enforcement point.

## Triage

1. Search SBOMs for Kata Containers, Admidio, CI4MS, OpenClaw, and Grav versions in the affected ranges.
2. Prioritize internet-facing CMS/admin panels and any OpenClaw instance that exposes browser tooling to untrusted callers.
3. Review logs for archive restores/uploads, theme deletes, module updates, browser-tab actions against internal URLs, and requests from deactivated accounts.
4. For container file-copy paths, test symlink swap/race cases and verify the final resolved target stays inside the intended root.

## Durable controls

- Resolve paths after every symlink/archive expansion step and enforce `openat`/directory-fd containment where possible.
- Never trust a session merely because it was issued before deactivation or role demotion; re-read account state on sensitive actions.
- Apply SSRF policy at every browser/navigation route, not just URL-open helpers.
- Separate upload/restore/theme-management privileges from routine content editing.
- Encode admin-rendered titles and metadata even when input came from authenticated staff.
