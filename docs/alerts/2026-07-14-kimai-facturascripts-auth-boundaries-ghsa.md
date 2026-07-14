# Kimai business-object auth, FacturaScripts TOTP, and App Store signed-data checks

Source: hourly offensive-security scan, 2026-07-14 GitHub advisory wave. Primary entries: [GHSA-rw46-qg69-vg6h](https://github.com/advisories/GHSA-rw46-qg69-vg6h) / CVE-2026-52828, [GHSA-v8hx-4vx8-wc96](https://github.com/advisories/GHSA-v8hx-4vx8-wc96) / CVE-2026-52827, [GHSA-2xgg-2x8h-8xw4](https://github.com/advisories/GHSA-2xgg-2x8h-8xw4) / CVE-2026-52826, [GHSA-xv4r-4885-gwpg](https://github.com/advisories/GHSA-xv4r-4885-gwpg) / CVE-2026-52825, [GHSA-jr9p-4h4j-6c58](https://github.com/advisories/GHSA-jr9p-4h4j-6c58) / CVE-2026-52824, [GHSA-r8vr-m544-qh4h](https://github.com/advisories/GHSA-r8vr-m544-qh4h) / CVE-2026-52823, [GHSA-c6w6-57jj-62vh](https://github.com/advisories/GHSA-c6w6-57jj-62vh) / CVE-2026-52822, [GHSA-3q6q-26vg-v97x](https://github.com/advisories/GHSA-3q6q-26vg-v97x) / CVE-2026-52821, [GHSA-vrr2-g9gh-c3jc](https://github.com/advisories/GHSA-vrr2-g9gh-c3jc) / CVE-2026-52820, [GHSA-4m8q-55qv-9pwp](https://github.com/advisories/GHSA-4m8q-55qv-9pwp) / CVE-2026-52819, [GHSA-pgcc-vfmc-7cw5](https://github.com/advisories/GHSA-pgcc-vfmc-7cw5) / CVE-2026-49992, [GHSA-c67f-gmxw-mj93](https://github.com/advisories/GHSA-c67f-gmxw-mj93) / CVE-2026-47677, and [GHSA-8f6j-263m-g72x](https://github.com/advisories/GHSA-8f6j-263m-g72x).

This batch is durable because the advisories expose repeatable operator boundaries: billing and time-tracking routes trusting parent IDs, historical records, frontend-hidden options, stale team membership, broad class-level permissions, or pre-2FA session state more than current authorization; a Docker default `APP_SECRET` turning signed cookies and login links into forgeable artifacts; a TOTP validation endpoint that can mint a session without a preceding password check; and signed App Store payload validation that accepts replayed stale OCSP `GOOD` responses.

!!! warning "Authorized validation only"
    Keep proofs to disposable Kimai, FacturaScripts, and signed-data verifier labs. Use synthetic customers, projects, activities, timesheets, team members, users, rates, TOTP accounts, throwaway Docker secrets, fake signed payloads, and locally captured OCSP fixtures. Do not alter production billing, payroll, time records, customer accounts, app-store transactions, real signing material, or user sessions. Do not publish forged cookie values, password-reset links, TOTP seeds, or reusable exploit payloads.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-rw46-qg69-vg6h](https://github.com/advisories/GHSA-rw46-qg69-vg6h) | Kimai export-template web routes | Class-level `create_export` permission exposes create/edit template routes to default teamlead users while API/UI expect `create_export_template` | Add route-family permission-drift checks where UI/API gates differ from direct web controllers. |
| [GHSA-v8hx-4vx8-wc96](https://github.com/advisories/GHSA-v8hx-4vx8-wc96) | Kimai 2FA/API session handling | Password-verified, pre-TOTP `KIMAI_SESSION` cookie satisfies `/api/*` `IS_AUTHENTICATED` checks | Test authentication step-up state separately for UI flows and REST/API firewalls. |
| [GHSA-2xgg-2x8h-8xw4](https://github.com/advisories/GHSA-2xgg-2x8h-8xw4) | Kimai project/customer/activity rate edit routes | Authorized parent object ID can be paired with an unauthorized `rate` ID | Add parent-child consistency checks to billing-rate edit tests. |
| [GHSA-xv4r-4885-gwpg](https://github.com/advisories/GHSA-xv4r-4885-gwpg) | Kimai team member/activity APIs | Permission to edit one team is treated as permission to attach any referenced user/activity | Test backend assignment APIs with IDs hidden by the frontend. |
| [GHSA-jr9p-4h4j-6c58](https://github.com/advisories/GHSA-jr9p-4h4j-6c58) | Kimai Docker image | Public default `APP_SECRET` signs remember-me cookies, login links, resets, and CSRF tokens | Add default-secret fingerprinting to self-hosted app takeover checks. |
| [GHSA-r8vr-m544-qh4h](https://github.com/advisories/GHSA-r8vr-m544-qh4h) | Kimai timesheet stop/restart APIs | Session-authenticated `/api/*` state-changing routes accept CSRFable `GET`/`PATCH` requests | Test browser-triggerable business-state transitions, not just admin forms. |
| [GHSA-c6w6-57jj-62vh](https://github.com/advisories/GHSA-c6w6-57jj-62vh) | Kimai timesheet restart/duplicate | Historical timesheet ownership overrides current project/activity access | Add permission-revocation replay tests to workflow cloning features. |
| [GHSA-3q6q-26vg-v97x](https://github.com/advisories/GHSA-3q6q-26vg-v97x) | Kimai activity/project preset creation | Direct preset routes create objects under unauthorized projects/customers | Test direct route families that accept parent IDs even when selectors filter them out. |
| [GHSA-vrr2-g9gh-c3jc](https://github.com/advisories/GHSA-vrr2-g9gh-c3jc) | Kimai timesheet create/update forms | Symfony `EntityType` query-builder OR branch allows submitted project ID to bypass team scope | Add submitted-ID vs query-filter differential checks to form-backed APIs. |
| [GHSA-4m8q-55qv-9pwp](https://github.com/advisories/GHSA-4m8q-55qv-9pwp) | Kimai timesheet list API | `user` / `users[]` filtering skips target-user teamlead validation | Test list endpoints separately from per-record endpoints. |
| [GHSA-pgcc-vfmc-7cw5](https://github.com/advisories/GHSA-pgcc-vfmc-7cw5) | Kimai default team creation shortcuts | `GET` routes create/reuse teams and bind target objects using the victim session | Add login-CSRF checks to convenience routes that mutate authorization structure. |
| [GHSA-c67f-gmxw-mj93](https://github.com/advisories/GHSA-c67f-gmxw-mj93) | FacturaScripts 2FA login handler | TOTP validation accepts only `fsNick` + TOTP and issues a full session without password/CSRF guards | Test auth sub-steps as standalone session-minting endpoints. |
| [GHSA-8f6j-263m-g72x](https://github.com/advisories/GHSA-8f6j-263m-g72x) | Apple App Store Server Python Library | `SignedDataVerifier` validates OCSP signature/CertID but not freshness fields | Add stale-status replay checks to signed receipt/JWS validation harnesses. |

## Replayable validation boundaries

### Kimai parent-child and hidden-ID authorization drift

1. Stand up a Kimai lab with two customers, two projects, two activities, two teams, and only marker data such as `KIMAI-AUTHZ-CANARY`.
2. Give the tester account access to Team A and no access to Team B. Record the object IDs for one allowed project/activity/rate and one denied project/activity/rate.
3. Exercise the intended UI first and confirm the denied objects are hidden.
4. Replay backend requests that pair an allowed parent ID with a denied child ID: rate edit routes, team member/activity assignment APIs, activity creation with preset project, and timesheet create/update `project` fields.
5. Capture a decision table: role, route, allowed ID, denied ID, expected status, observed status, and whether the marker changed or became visible.
6. Add negative controls for a patched build, a full admin account, a no-permission account, and nonexistent IDs.

Report this as **frontend-hidden or current-scope object ID -> backend trust in submitted ID / wrong parent relation -> cross-customer/team business-object mutation**. Keep evidence to marker names and route/status tables; do not include real customer/project/rate data.

### Kimai permission-revocation workflow cloning

1. Create a timesheet for User A under Project A, then revoke User A's access to Project A while leaving the historical timesheet visible to the user.
2. Attempt only non-billing marker operations against `restart` and `duplicate` on the historical entry.
3. Check whether Kimai creates a fresh timesheet under the now-unauthorized project/activity because it trusts the old record ownership.
4. Compare with direct creation under Project A, which should fail after revocation.
5. Include controls for allowed projects, revoked projects, patched behavior, and users without historical entries.

Report this as **historical authorized record -> restart/duplicate workflow -> new object under currently unauthorized scope**. Do not alter production timekeeping or payroll data.

### Kimai list-vs-record authorization mismatch

1. Seed a lab with one teamlead, one unrelated user, and one timesheet containing only a marker description and fake rate.
2. Request the per-record endpoint for the unrelated timesheet and confirm expected denial.
3. Request `GET /api/timesheets?user=<id>` and `GET /api/timesheets?users[]=<id>` from the same session.
4. Record whether the list endpoint returns the unrelated record or rate despite the per-record voter denying access.
5. Repeat across projects with no team scope, shared team membership, and true teamlead relationships to separate membership from leadership.

Report this as **list filter user ID -> missing target-user teamlead check -> cross-user timesheet disclosure**. Use synthetic time entries only.

### Kimai CSRFable business-state shortcuts

1. Use a disposable browser profile logged into Kimai as a user with only lab permissions.
2. Build harmless proof pages or raw requests for the `GET` state-change routes: timesheet stop/restart and default team creation shortcuts for projects, customers, or activities.
3. Trigger only marker records and record whether a top-level navigation, image, or form causes the action with the existing session.
4. Confirm the same route changes authorization structure or business state, not just UI state.
5. Add controls for missing session, wrong role, non-GET patched route, and valid CSRF-tokened intentional action.

Report this as **browser-triggerable route -> session-authenticated state change -> team/timesheet mutation**. Do not send links to real users or manipulate production work records.

### Kimai route-family permission drift

1. Create a Kimai lab with a default `ROLE_TEAMLEAD`, an admin, and a regular user. Seed only marker export templates such as `EXPORT-TEMPLATE-CANARY`.
2. From the UI and documented API, confirm which roles can see or call export-template create/edit actions that require `create_export_template`.
3. Replay the direct web controller routes for export-template create and edit from the teamlead session.
4. Record whether the teamlead can create or mutate a global template despite the stricter API/UI gate.
5. Add controls for admin success, regular-user denial, patched method-level permission checks, and attempts against unrelated export actions that only require `create_export`.

Report this as **broad class-level permission -> direct web route bypasses stricter API/UI gate -> global export-template mutation**. Keep evidence to role/route/status tables and marker template names; do not alter production exports or templates used for billing, payroll, or customer delivery.

### Kimai pre-2FA API session acceptance

1. Enable TOTP for a disposable Kimai account and use a clean browser or HTTP client that records only lab cookies.
2. Submit a valid username/password and stop before entering the TOTP code. Capture whether the login response sets a `KIMAI_SESSION` cookie tied to a two-factor-pending token.
3. Replay that cookie against harmless `/api/*` endpoints that should require full authentication, using marker-only reads or non-destructive profile/status checks first.
4. Verify whether the web UI remains at `/auth/2fa` while the API accepts the same session as authenticated.
5. Add controls for no cookie, wrong password, completed 2FA, patched firewall behavior, and a non-2FA account.

Report this as **password-verified pre-2FA session -> API firewall treats step-up token as authenticated -> REST access before second factor**. Redact cookies and never use real user passwords, production sessions, or high-impact API actions.

### Kimai default `APP_SECRET` takeover check

1. In a local Kimai Docker lab, deploy once with the image default secret and once with an explicit random `APP_SECRET`.
2. Fingerprint the exposed app version and deployment style without reading environment variables from the target.
3. In the default-secret lab only, generate an inert remember-me/login-link/reset-token canary for a disposable account and verify whether the application accepts it.
4. Confirm the random-secret control rejects the same artifact.
5. If assessing a real authorized target, stop at evidence of default-secret deployment risk unless the program explicitly permits account-takeover proof.

Report this as **public image default secret -> forgeable Symfony signed artifact -> disposable account session**. Redact all signed values and never target real admins.

### FacturaScripts standalone TOTP validation

1. Create a disposable FacturaScripts user with 2FA enabled and a known lab TOTP seed.
2. Start from a clean browser session with no prior password login flow.
3. Submit only `fsNick` and a current TOTP value to the 2FA validation action.
4. Record whether the server issues full session cookies without password, CSRF token, or incident/rate-limit checks.
5. Add controls for wrong TOTP, disabled 2FA, normal password-first login, patched handler, and locked/incident-heavy account state.

Report this as **auth sub-step endpoint -> TOTP-only proof -> full session minting**. Use owned lab accounts and do not brute-force real TOTP windows.

### Signed-data OCSP freshness replay

1. Build an offline harness around `appstoreserverlibrary.signed_data_verifier.SignedDataVerifier` with `enable_online_checks=True` and synthetic or vendor-provided test-chain material.
2. Capture a legitimate OCSP `GOOD` fixture for the test certificate chain, then alter the harness clock or fixture metadata so `producedAt`, `thisUpdate`, or `nextUpdate` is stale.
3. Verify whether the library still accepts a signed JWS when the OCSP status signature and CertID match but freshness is expired.
4. Compare with a patched library or wrapper that enforces the OCSP freshness window.
5. Keep all payloads synthetic; do not replay real App Store receipts, purchase tokens, or production signing certificates.

Report this as **signed payload -> stale OCSP `GOOD` replay -> revoked/expired status not enforced**. Evidence should be harness logs and redacted certificate metadata.

## Reporting notes

- Lead with preconditions: Kimai role/team topology, object IDs under allowed and denied scopes, route family under test, 2FA step-up state, Docker deployment defaults, browser-session state, FacturaScripts 2FA-enabled accounts, or App Store verifier `enable_online_checks=True` usage.
- Prefer decision tables over payload dumps: route, method, actor role, submitted object ID, expected authorization predicate, observed status, marker effect, authentication step, and patched control.
- Redact cookies, signed URLs, login links, reset tokens, TOTP seeds/codes, `APP_SECRET` values, customer names, billing rates, export-template bodies from real tenants, user IDs from real tenants, purchase/JWS payloads, and OCSP/certificate material tied to production systems.
- The same wave included a `json_repair` circular `$ref` CPU DoS advisory; skip it for wiki publication unless a future source ties the parser issue to a bounded, non-availability exploit workflow.
