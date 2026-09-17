# User input as CLI argv: MISP → CakePHP path-switch phar RCE, SAP multitenant credential endpoint, and Android exported-activity filename injection

Source: GitHub advisory wave published 2026-09-17T18:32–19:05Z (plus a `critical` updated-feed resurfacing at 19:05Z). A sibling MISP finding (Overmind statistics legend stored XSS) is folded into the [Sept 7 MISP page](2026-09-07-389-directory-server-auth-bypasses-and-jetbrains-librenms-trust-boundaries-ghsa.md#september-17-follow-up-overmind-statistics-legend-innerhtml-stored-xss-ghsa-rfmv-f8jw-7mhw).

This batch is durable because all three entries are the same meta-pattern in different runtimes: **user-controlled fields that arrive at a *structural* sink** — a command-line dispatcher, a multitenant metadata endpoint, or an OS file-staging path — where the framework, not the app, does the dangerous interpretation.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-2q9g-8hcw-6c23](https://github.com/advisories/GHSA-2q9g-8hcw-6c23) | MISP (events/contact form → background job dispatch) | Job arguments are passed **directly as `argv` of the CakePHP console process**. `ShellDispatcher::_parsePaths()` scans the *entire* argv for path switches (`-app`, `--app`, `-working`, `--working`, `-root`, `--root`, `-webroot`, `--webroot`) and takes the next element as the application root. The contact endpoint forwards the user-controlled `person` and `message` fields into job arguments unvalidated → set `person=-app`, `message=phar://<uploaded archive>` → bootstrap `include`s `Config/core.php` from the attacker's archive → **deterministic unauthenticated RCE as the web user** | The reserved-flag-in-argv class: any feature that concatenates user fields into a CLI invocation must be tested against the invoked framework's *own* option grammar, not the app's. PHAR-deserialization bootstrap includes are the PHP execution leg |
| [GHSA-955m-rr6m-2f9v](https://github.com/advisories/GHSA-955m-rr6m-2f9v) / [CVE-2026-76969](https://nvd.nist.gov/vuln/detail/CVE-2026-76969) | `@sap/cds-mtxs` (SAP CAP multitenancy library) < 1.18.4, 2.x < 2.7.7, 3.x < 3.9.7, 4.0.1–4.0.2 (critical) | With extensibility enabled, certain mtxs endpoints lack sufficient checks: an **unauthenticated** attacker sends crafted requests to **obtain tenant credentials**, then abuses them to replace/delete tenant data (high integrity/availability impact, partial confidentiality) | Multitenant SaaS plumbing libraries expose a *tenant-credential* API surface that is often outside the app team's threat model. Audit question for any CAP/mtx-style stack: which endpoints mint or return per-tenant service credentials, and what authenticates them? |
| [GHSA-x3gc-cx3q-fw5m](https://github.com/advisories/GHSA-x3gc-cx3q-fw5m) | Verizon Cloud for Android (`com.vcast.mediamanager`) < 26.7.10 (medium) | Exported activities `OneTouchUploadActivity` / `PrintShopCloudActivity` accept `ACTION_SEND(_MULTIPLE)` intents; the file-staging sink concatenates the intent-supplied `_display_name` without sanitization → **path traversal out of the staging dir, arbitrary file write** → attacker-controlled content injected into the authenticated user's cloud account with no user interaction | Android co-resident-app attack surface: exported activity + Intent-extras filename = classic unsanitized-filename file-write sink, reachable by any installed app without permissions. Mobile-recon heuristic: enumerate exported components (`dumpsys package` / `aapt dump xmltree`) and fuzz filename-ish extras (`_display_name`, `title`, `name`) with `../` markers |

## Operator validation patterns

### 1. Framework-option injection in delegated argv (MISP pattern)

1. Find every sink where app code spawns a console/CLI process with fields that include user input (job queues, export jobs, report generators, webhook relays).
2. Do not test for shell metacharacters — the spawn is usually array-based (`execve`, no shell). Test the **invoked framework's option grammar** instead: for CakePHP consoles send `-app`/`--app`/`-root`/`-webroot` in one field and a controlled path/URI in the neighbor field; for other frameworks enumerate their dispatcher's switches the same way.
3. PHP targets: pair a path-switch with a `phar://` pointer at an archive you can upload somewhere on the host (avatar/attachment fields are common); the execution leg is the bootstrap `include` of a config file inside the archive. Non-PHP targets: pair the switch with any file-read/import sink the CLI supports.
4. Proof discipline: lab MISP/CakePHP only, synthetic archive with an inert marker in `Config/core.php`, and confirm at import time (log/marker), not on shared tenants. Never drop real PHP shells on engagements — stop at the include-triggered marker.

### 2. Tenant-credential endpoint sweep (SAP cds-mtxs pattern)

- On any multitenant platform with an extension/tenancy sidecar library (CAP mtxs, multi-tenant OAuth bridges, extensibility services): enumerate routes that mention `tenant`, `subscribe`, `credentials`, `extension`, `bound` and test them **unauthenticated** and with cross-tenant tenant IDs.
- The reportable finding is credential *issuance/return* to an unauthorized caller; stop before using any obtained credential against other tenants' data (replace/delete is out of bounds outside an approved lab).
- Version fingerprinting matters here: the library version is often reflected in response headers or error shapes of `/mtx` routes — a cheap recon signal that the app runs an unpatched train.

### 3. Exported-component filename fuzz (Android pattern)

- Static recon: list exported activities/providers; flag any handling `ACTION_SEND*` (share targets) since they accept extras from arbitrary apps by design.
- Dynamic proof with two test apps you control (or `adb shell am start` as the co-app proxy): send `ACTION_SEND` with `ClipData` + `_display_name=../../marker` and confirm the write lands outside the staging dir using a synthetic marker file in a world-readable location.
- Impact framing for reports: co-resident malicious app → arbitrary write into the target app's storage → content injection into the victim's cloud account without user interaction; do not demo against real user accounts.

## Durable operator value

1. **argv is a parser target, not just a string sink.** Array-exec eliminates shell injection but leaves the *program's own* flag grammar exposed. Audit = read the dispatcher's option table, then test each reserved switch against neighbor-field control.
2. **Three runtimes, one shape:** framework dispatcher (CakePHP), tenancy library (cds-mtxs), and OS intent delivery (Android exported activity) all trusted an upstream field that the *platform* interprets structurally. Wherever the platform interprets, the app's validation vocabulary is the wrong vocabulary.
3. **PHAR-in-bootstrap is still the PHP RCE leg** for "path switch + uploadable archive" primitives — treat any attacker-influenced "application root" as a code-execution candidate, not a read primitive.

## Safety

- Authorized lab instances only for the MISP/CakePHP and CAP proofs; inert archive markers, synthetic tenant IDs, no real tenant credentials captured or replayed.
- Android testing on your own device profile with your own test app and marker files; never target another user's account or install surveillance payloads.
- Keep credentials, tenant identifiers, and device data out of wiki and report evidence.

---

*Sources: [GHSA-2q9g-8hcw-6c23](https://github.com/advisories/GHSA-2q9g-8hcw-6c23) · [GHSA-955m-rr6m-2f9v](https://github.com/advisories/GHSA-955m-rr6m-2f9v) · [CVE-2026-76969](https://nvd.nist.gov/vuln/detail/CVE-2026-76969) · [SAP note 3798315](https://me.sap.com/notes/3798315) · [GHSA-x3gc-cx3q-fw5m](https://github.com/advisories/GHSA-x3gc-cx3q-fw5m)*
