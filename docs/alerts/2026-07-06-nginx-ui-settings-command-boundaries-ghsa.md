# Nginx-UI hidden settings, certificate file-write, and ordered-query boundary checks

Source: hourly offensive-security scan, 2026-07-06. Primary entries: GitHub Advisory Database [GHSA-xvq9-4vpv-227m](https://github.com/advisories/GHSA-xvq9-4vpv-227m) / CVE-2024-23827, [GHSA-8r25-68wm-jw35](https://github.com/advisories/GHSA-8r25-68wm-jw35) / CVE-2024-22198, [GHSA-pxmr-q2x3-9x9m](https://github.com/advisories/GHSA-pxmr-q2x3-9x9m) / CVE-2024-22197, and [GHSA-h374-mm57-879c](https://github.com/advisories/GHSA-h374-mm57-879c) / CVE-2024-22196.

These advisories are durable for operators because they expose a reusable management-dashboard pattern: a low-privilege authenticated API can accept filesystem paths, certificate bodies, or configuration keys that the UI constrains or hides, then later file writers, command runners, or database helpers trust those values. Keep proofs to disposable Nginx-UI labs, inert command markers, disposable certificate-path marker files, SQL parser errors or timing-safe canaries, and explicit role/route decision tables only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-xvq9-4vpv-227m](https://github.com/advisories/GHSA-xvq9-4vpv-227m) / CVE-2024-23827 | Nginx-UI certificate import, versions before `1.9.10-0.20240128060047-8581bdd3c6f4` | authenticated certificate import accepted caller-supplied `ssl_certificate_path` and `ssl_certificate_key_path`, then wrote supplied content to those filesystem paths | Test admin-style import helpers for path controls that let lower-privilege users turn benign upload/import features into arbitrary file writes. |
| [GHSA-8r25-68wm-jw35](https://github.com/advisories/GHSA-8r25-68wm-jw35) / CVE-2024-22198 | Nginx-UI settings API, versions before `1.9.10-0.20231219184941-827e76c46e63` | any authenticated user could submit the hidden `start_cmd` setting, then trigger it through the web terminal path | Test management UIs for API-only settings that become shell command templates when a later feature opens a terminal, runner, job, or maintenance action. |
| [GHSA-pxmr-q2x3-9x9m](https://github.com/advisories/GHSA-pxmr-q2x3-9x9m) / CVE-2024-22197 | Nginx-UI settings API, versions before `1.9.10-0.20231219184941-827e76c46e63` | any authenticated user could submit hidden nginx command settings such as `test_config_cmd`, `reload_cmd`, or `restart_cmd` even though the UI exposed only benign preference fields | Test whether hidden or undocumented configuration fields cross from low-privilege settings APIs into privileged service-control commands. |
| [GHSA-h374-mm57-879c](https://github.com/advisories/GHSA-h374-mm57-879c) / CVE-2024-22196 | Nginx-UI `OrderAndPaginate`, versions before `1.9.10-0.20231219195202-ec93ab05a3ec` | `sort_by` and `order` query parameters were interpolated into a GORM `Order()` clause | Audit list, table, and search endpoints where user-controlled sort keys become SQL fragments instead of allowlisted column identifiers. |

## Operator triage

Prioritize Nginx-UI or similar dashboard targets where all of these are true:

1. You have an authorized low-privilege account or scoped test token, not just admin access.
2. The application exposes settings, preferences, certificate import, node, service-control, terminal, or maintenance APIs separate from what the browser UI renders.
3. API responses or JavaScript bundles reveal configuration keys or path fields that are hidden, disabled, or constrained differently from the visible form.
4. A later route consumes those settings or import values as shell commands, process arguments, nginx control commands, file paths, or SQL order expressions.
5. The target controls real infrastructure, reverse proxies, deployment nodes, web terminals, or service reload paths.

Lower priority: single-admin deployments with no role boundary, patched builds with server-side key allowlists, settings saved only in an isolated lab namespace, or sort parameters that are mapped through fixed column enums before reaching the ORM.

## Replayable validation boundaries

### Certificate import path-to-file-write check

Use this only in a disposable Nginx-UI lab or a staging target where arbitrary-path file-write validation is explicitly authorized.

- Preconditions: affected version, authenticated low-privilege test user, a disposable writable directory, and a marker certificate/key body that contains no real private key material.
- Confirm normal certificate-import behavior with an allowed in-scope path first.
- Submit an import where `ssl_certificate_path` and/or `ssl_certificate_key_path` point to a disposable marker path outside the expected certificate directory but still inside the lab sandbox.
- Positive evidence: Nginx-UI writes the supplied marker body to the caller-selected path even though the UI or policy should confine certificate material to an approved directory.
- Negative controls: patched build, server-side canonicalization and directory allowlist, read-only filesystem path, and a low-privilege user denied at the certificate route.
- Do not write shell startup files, nginx configuration, web roots, service units, cron files, authorized keys, credentials, or production paths. Do not include real certificates or keys in artifacts.

Report this as **certificate import path to arbitrary file write**. Strong evidence includes role, route, requested path, canonicalized path if available, file mode/owner, fixed marker content, and patched or allowlisted-path behavior.

### Hidden settings to command-runner parity check

Use this only in a disposable Nginx-UI lab or an explicitly authorized staging target. Do not alter production nginx commands or open a real shell.

- Preconditions: affected version, a low-privilege authenticated test user, a copy of the normal settings payload, and a harmless marker command such as writing to a disposable temp path inside the lab container.
- Capture the visible UI fields and the API schema/traffic for `GET` and `POST` settings. Identify fields that the API accepts but the UI does not expose, such as terminal or nginx command settings.
- Submit a settings update that changes only one hidden command field to an inert marker action in the lab. Preserve every unrelated field exactly as returned by the application.
- Trigger only the matching non-destructive execution path in the lab: terminal open for `start_cmd`, configuration test for `test_config_cmd`, or a disposable service-control wrapper for reload/restart commands.
- Positive evidence: a low-privilege user can persist a hidden command setting and the later runner executes or attempts that marker.
- Negative controls: patched build, admin-only settings route, server-side allowlist that ignores unknown command fields, and a low-privilege user that cannot save the hidden key.
- Do not run reverse shells, overwrite nginx configuration, reload production services, read environment variables, or store real secrets in evidence.

Report this as **low-privilege settings API to privileged command runner**, not just command injection. Strong evidence includes role, route, hidden field name, before/after settings diff with secrets redacted, trigger route, marker-only execution evidence, and patched/role-negative controls.

### Sort parameter to SQL `ORDER BY` fragment check

Use this for authenticated list/table endpoints that accept `sort_by`, `order`, `field`, `column`, or similar parameters.

- Preconditions: affected endpoint, low-privilege test user, synthetic records you are allowed to list, and a database-safe canary that does not modify data.
- First map normal sorting behavior with allowed columns and directions.
- Try malformed column and direction values that should be rejected by a column allowlist. Prefer syntax-error probes or harmless expression canaries over timing or heavy queries.
- Positive evidence: the endpoint returns a database parser error, changes order according to an injected expression, or otherwise proves the raw parameter entered the SQL `ORDER BY` fragment.
- Negative controls: patched build, fixed enum mapping, unknown-column rejection before ORM execution, and a normal allowed-column sort.
- Do not dump tables, infer unrelated records, run stacked queries, or use destructive SQL functions.

Report this as **user-controlled sort key to SQL order fragment**. Include route, role, parameter name, expected allowlist behavior, observed parser/error/order evidence, and whether the issue affects only authenticated table views or a wider API surface.

## Reporting notes

- Lead with the crossed boundary: **certificate import path to file write**, **hidden API setting to command runner**, or **sort parameter to ORM order expression**.
- Include product/version, authentication role, field names, trigger route, and negative controls. Redact tokens, node secrets, JWT secrets, nginx paths, and real command values.
- Keep proof artifacts synthetic: disposable lab files, fixed marker strings, synthetic table rows, and route/role decision matrices.
- Avoid production side effects. If a reload/restart path is in scope, stop at configuration acceptance and lab-only marker evidence unless the customer explicitly provides a canary service-control target.
