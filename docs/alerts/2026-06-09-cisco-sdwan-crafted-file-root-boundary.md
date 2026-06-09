# Cisco Catalyst SD-WAN crafted-file root boundary

Source: hourly offensive-security scan, 2026-06-09. Primary entries: CISA KEV [CVE-2026-20245](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and Cisco advisory [cisco-sa-sdwan-privesc-4uxFrdzx](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx).

This page is durable because it captures a reusable appliance-validation pattern: privileged network-management planes often expose file import, upload, backup, or CLI workflows where crafted file content crosses into shell execution under root.

## What changed

- **Cisco Catalyst SD-WAN root escalation is in KEV** — CISA added CVE-2026-20245 for Cisco Catalyst SD-WAN Controller, Manager, and Validator. Cisco describes an authenticated local command-injection path in the CLI where a crafted file supplied to the affected system can execute commands as root.
- **Required access is high-value but realistic in chained tests** — Cisco states exploitation requires `netadmin` privileges, valid credentials, or prior exploitation of CVE-2026-20182 or CVE-2026-20127. This makes it a post-auth appliance boundary, not an internet spray target.
- **Operational impact reaches managed edges** — Cisco observed limited cases where exploitation resulted in configuration changes pushed to edge devices. For authorized tests, that makes the safe validation boundary the management-plane file/CLI path and a controlled canary configuration, not broad device changes.
- **Root cause class** — the issue is insufficient validation of user-supplied input before CLI handling; CISA maps it to CWE-116, improper encoding or escaping of output.

## Operator triage

1. **Confirm authorized scope:** only test SD-WAN control-plane appliances explicitly in scope: Catalyst SD-WAN Controller/vSmart, Manager/vManage, and Validator/vBond.
2. **Inventory reachable management paths:** identify file upload/import/backup/restore/CLI workflows available to `netadmin` users. Do not assume all upload features are affected; map the actual workflow used by the customer or lab.
3. **Assess chained access realistically:** if `netadmin` is not available, document whether the assessment already includes a permitted path to that role. Do not attempt credential attacks or exploit chaining outside the engagement rules.
4. **Prefer lab reproduction:** build the crafted-file test in an isolated SD-WAN lab or vendor-provided test environment before touching production appliances.
5. **Bound downstream effects:** if validation requires a configuration push, use a harmless synthetic object and a single lab edge. Never alter routing, VPN membership, policy, templates, or production device configuration as proof.

## Replayable validation boundaries

- Use a canary command that writes a harmless marker to a disposable lab path or returns a controlled version string. Do not read keys, tokens, configs, password hashes, tunnel secrets, or customer data.
- Capture only the affected appliance role, software version, privilege level, upload/CLI workflow name, and sanitized evidence of command execution or blocked execution.
- If production validation is approved, stop at version and workflow reachability unless the rules of engagement explicitly allow active crafted-file testing.
- Preserve appliance stability: avoid repeated uploads, long-running commands, process restarts, device template pushes, and config changes that could affect managed edge devices.
- If evidence depends on Cisco-observed exploitation language, cite the advisory and KEV entry rather than inferring a broader unauthenticated remote path.

## Reporting heuristics

- Lead with the **trust boundary**: `netadmin`-controlled file content reaches privileged CLI execution on the SD-WAN control plane.
- Include preconditions explicitly: appliance role, software train, authenticated privilege, upload/import/CLI route, and whether validation was lab-only or production reachability-only.
- Treat this as a post-auth escalation and management-plane blast-radius finding. Do not frame it as unauthenticated remote code execution.
- Include a safe impact statement: root on a control-plane appliance can affect management-plane integrity and, in observed cases, configuration pushed to edge devices.
- Recommend vendor-fixed software and least-privilege management workflows only after the offensive proof narrative; keep the main report centered on the replayable validation boundary.
