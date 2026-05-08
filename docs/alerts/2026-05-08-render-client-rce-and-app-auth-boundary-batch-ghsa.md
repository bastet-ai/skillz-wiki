# Render, client-RCE, and app authorization boundary batch

**Signal:** GitHub Security Advisories REST fallback also surfaced a **2026-05-08 17:15 UTC** app-layer batch where stored/rendered content crossed into privileged UI contexts, action parsers became code execution, and coarse access checks failed on admin-style applications.

## Advisories covered

- **PrestaShop customer-service stored XSS** — [GHSA-w9f3-qc75-qgx9](https://github.com/advisories/GHSA-w9f3-qc75-qgx9): `prestashop/prestashop < 8.2.6` and `>= 9.0.0, < 9.1.1`; patch to `8.2.6+` or `9.1.1+`.
- **SiYuan stored XSS to Electron renderer RCE** — [GHSA-2h64-c999-c9r6](https://github.com/advisories/GHSA-2h64-c999-c9r6): stored XSS via Attribute View name can reach an Electron renderer; no fixed version listed at advisory time.
- **ntfy.sh `parseActions` remote code execution** — [GHSA-pqhx-w72w-m393](https://github.com/advisories/GHSA-pqhx-w72w-m393): `heckel.io/ntfy/v2 < 2.22.0`; patch to `2.22.0+`.
- **Funadmin improper access control** — [GHSA-qhh7-263p-54r3](https://github.com/advisories/GHSA-qhh7-263p-54r3): `funadmin/funadmin <= 7.1.0-rc6`; no fixed version listed at advisory time.
- **MindsDB improper access control** — [GHSA-9f6m-65v9-x9g2](https://github.com/advisories/GHSA-9f6m-65v9-x9g2): `MindsDB <= 26.0.1`; no fixed version listed at advisory time.

## Why this is durable

Admin consoles, notebooks, notification systems, and Electron clients are high-leverage render targets. A stored string is not just HTML when it lands in a customer-service dashboard, desktop renderer, or action parser with filesystem/network privileges. Authorization bugs in these same tools are similarly dangerous because they expose orchestration, data, and credential-bearing workflows.

## Immediate triage

1. Search dependency and deployment inventories for affected PrestaShop, SiYuan, ntfy, Funadmin, and MindsDB versions.
2. Patch PrestaShop and ntfy immediately. For advisories without fixed versions, remove internet exposure, restrict to trusted networks/VPN, and disable risky render/action features where possible.
3. Hunt stored XSS payloads in ticket/customer-service messages, SiYuan Attribute View names, notification action fields, admin notes, and database-backed UI labels.
4. For Electron-backed clients, treat successful stored XSS as possible local code execution: review spawned processes, file reads, credential-store access, and extension/plugin changes.
5. For Funadmin and MindsDB, review authorization logs for direct object access, role changes, new admin/API users, unexpected queries, connector creation, and model/database exfiltration.

## Durable controls

- Escape at the final rendering sink and keep rich-text sanitizers on a deny-by-default allowlist with regression tests for SVG, template, URL, and event-handler contexts.
- Isolate Electron renderers: disable Node integration, enable context isolation, restrict preload bridges, and treat renderer-origin data as untrusted.
- Parse notification/action DSLs with strict schemas; reject shell-like syntax, URLs with dangerous schemes, and unexpected fields before execution.
- Enforce authorization server-side per route, object, and action. UI-hidden buttons are not controls.
- Add content-security policy, Trusted Types where available, and audit logs that tie rendered content to creator, sink, sanitizer version, and resulting action.
