# Koel Subsonic SSRF and MantisBT SOAP/configuration boundary checks

Source: hourly offensive-security scan, 2026-07-15 GitHub advisory wave. Primary entries: [GHSA-6p96-cfg5-4vhp](https://github.com/advisories/GHSA-6p96-cfg5-4vhp), [GHSA-w79m-f3jx-779v](https://github.com/advisories/GHSA-w79m-f3jx-779v), [GHSA-c2xg-qjqw-2v98](https://github.com/advisories/GHSA-c2xg-qjqw-2v98), [GHSA-v84x-qvhg-f36r](https://github.com/advisories/GHSA-v84x-qvhg-f36r), [GHSA-mw6p-33vw-46cc](https://github.com/advisories/GHSA-mw6p-33vw-46cc), and [GHSA-m7ph-9558-mrx3](https://github.com/advisories/GHSA-m7ph-9558-mrx3).

This batch is durable because the advisories expose reusable operator boundaries: compatibility API routes that create the same media objects as the primary API but omit SSRF validation, SOAP authentication that trusts a caller-supplied username plus a reusable cookie string, administrator configuration paths that cross into PHP `eval()` or SQL `ORDER BY` construction, and REST/SOAP issue-update routes that apply a broader update permission than the workflow status-change permission.

!!! warning "Authorized validation only"
    Keep proofs to disposable Koel and MantisBT labs, owned callback listeners, synthetic audio/feed responses, marker-only bug reports, fake users, and harmless configuration values. Do not fetch metadata services, internal production URLs, private bugtracker data, real attachments, password hashes, API tokens, cookie strings from real users, web roots, or database files. Do not publish weaponized SOAP/RCE/SQL payloads or trigger destructive project/issue operations.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-6p96-cfg5-4vhp](https://github.com/advisories/GHSA-6p96-cfg5-4vhp) | Koel Subsonic `createInternetRadioStation.view` / `updateInternetRadioStation.view` | Subsonic radio routes accept `streamUrl` without the `SafeUrl` and content-type validation used by the primary radio API, then playback returns the fetched upstream body | Add compatibility-route parity checks to media SSRF testing and distinguish full-read SSRF from blind callbacks. |
| [GHSA-w79m-f3jx-779v](https://github.com/advisories/GHSA-w79m-f3jx-779v) | Koel Subsonic `createPodcastChannel.view` | Subsonic podcast creation accepts a URL with only generic URL validation and immediately passes it to the podcast parser | Test server-side fetch guards on alternate client/protocol APIs, not only the web UI or main REST API. |
| [GHSA-c2xg-qjqw-2v98](https://github.com/advisories/GHSA-c2xg-qjqw-2v98) | MantisBT SOAP API `mci_check_login()` | SOAP login accepts a valid `cookie_string` while trusting a caller-supplied username, enabling user impersonation through SOAP even when Web UI/REST derive identity server-side | Add identity-binding tests for legacy SOAP/XML-RPC APIs next to modern REST routes. |
| [GHSA-v84x-qvhg-f36r](https://github.com/advisories/GHSA-v84x-qvhg-f36r) | MantisBT admin `adm_config_set.php` non-string config parser | Non-string configuration values pass through a tokenizer using PHP `eval()`; declarations can be hoisted past a prefixed `return` and collide with later autoloading | Treat admin configuration DSLs as code-execution surfaces and prove only inert class/function collision markers. |
| [GHSA-mw6p-33vw-46cc](https://github.com/advisories/GHSA-mw6p-33vw-46cc) | MantisBT `history_order` config value | Admin-controlled sort configuration is concatenated into an issue-history SQL `ORDER BY` clause | Add config-key-to-query-construction checks where stored admin settings are later executed in user-triggered views. |
| [GHSA-m7ph-9558-mrx3](https://github.com/advisories/GHSA-m7ph-9558-mrx3) | MantisBT REST/SOAP issue status update | API issue updates use the general update threshold instead of the stricter status-transition threshold | Test workflow-state permissions separately from generic object-edit permissions across every API family. |

## Replayable validation boundaries

### Koel Subsonic media SSRF parity checks

1. Stand up Koel `v9.6.0` or an explicitly vulnerable lab image with one disposable authenticated user and no access to production libraries.
2. Configure three owned targets: a public audio/feed canary, a loopback/private canary service under your control, and a blocked destination class that should fail `SafeUrl` through the primary API.
3. First exercise the primary web/API radio and podcast creation routes and record the expected `SafeUrl` rejection for the private canary.
4. Repeat through the Subsonic-compatible routes: radio `streamUrl` on create/update and podcast `url` on channel creation.
5. For radio, trigger playback only against your owned canary and record whether Koel streams the upstream marker body back to the client. For podcast, record whether channel creation causes the server-side callback while parsing the feed.
6. Add controls for unauthenticated access, a patched build, public-only URLs, invalid schemes, redirects from public to private URLs, DNS rebinding if explicitly in scope, and content-type handling for the radio stream.

Report this as **alternate Subsonic route -> missing primary API SSRF validator -> server-side fetch / full-read stream**. Evidence should be route, authenticated role, target class, callback or returned marker body, and primary-API negative control. Do not probe metadata endpoints, Kubernetes APIs, Redis/admin panels, or third-party hosts.

### MantisBT SOAP identity-binding bypass

1. Build a MantisBT `2.28.3` or vulnerable lab with self-registration enabled, one low-privilege user, and one administrator account containing only marker projects/issues.
2. Log in as the low-privilege user and capture only that user's lab `MANTIS_STRING_COOKIE` value class; redact the value from notes and reports.
3. Send a minimal SOAP request that pairs the low-privilege user's valid cookie-string proof with the administrator username.
4. Call only harmless read or marker-list operations first, then marker-only create/update operations if the assessment permits proving administrator capability.
5. Compare with Web UI and REST controls where identity is derived server-side and the same username spoofing should fail.
6. Add controls for disabled signup, invalid cookie strings, nonexistent usernames, patched `mci_check_login()`, and SOAP disabled at the web server.

Report this as **valid cookie string from User A -> SOAP caller-supplied username User B -> API session authorized as User B**. Keep evidence to role/operation/status tables and synthetic issue IDs; never export real private issues, attachments, user emails, password hashes, or API tokens.

### MantisBT admin configuration code/SQL sinks

1. Use only a disposable administrator account in a local MantisBT lab; these are post-admin configuration-sink checks, not unauthenticated probes.
2. For the `adm_config_set.php` parser issue, set a harmless non-string configuration value designed to prove PHP declaration handling with an inert marker class/function name. Do not include shell commands, file writes, or autoload collisions outside the lab marker.
3. Trigger only the code path needed to show whether the marker declaration is compiled or later autoload behavior changes.
4. For the `history_order` issue, set a marker-only sort expression that should be rejected or whitelisted, then view a synthetic issue with history entries and record whether the database receives attacker-shaped `ORDER BY` grammar.
5. Use a dedicated test database user without `FILE` privilege and avoid time-heavy expressions; stop at marker query-shape evidence.
6. Add controls for REST `ConfigsSetCommand` where relevant, patched commits, string-only values, whitelisted sort directions, and non-admin accounts.

Report these as **administrator configuration value -> unsafe interpreter/query sink -> code or SQL execution boundary**. Evidence should be config key, value grammar class, triggered route, marker output/query log, and patched negative control. Do not write web shells, dump tables, read credentials, or rely on real users to trigger the view.

### MantisBT workflow status permission drift

1. Create a lab project with a user who has the default `UPDATER` capability but does not meet a deliberately higher `set_status_threshold` such as `DEVELOPER`.
2. Through the Web UI, confirm the user cannot perform the restricted status transition on a synthetic issue.
3. Replay equivalent REST and SOAP issue-update calls that attempt to set only the status field to a marker state.
4. Record whether the API accepts the transition because it checks the general update threshold instead of the workflow status threshold.
5. Add controls for a user below `update_bug_threshold`, a user above `set_status_threshold`, patched MantisBT `2.28.4`, closed/resolved workflow rules, and unrelated issue-field edits.

Report this as **API issue edit -> generic update permission accepted for status field -> workflow transition bypass**. Keep evidence to role matrices and marker issue IDs; do not mutate production bug state or notify real users.

## Reporting notes

- Lead with preconditions: Koel authenticated user and Subsonic route exposure, target URL class, primary API rejection evidence, MantisBT version, SOAP availability, self-registration state, cookie-string provenance, configured thresholds, administrator requirement for config sinks, database privileges, and patched controls.
- Prefer decision tables over payload dumps: route family, actor role, supplied URL/username/config key/status field, expected validator or permission, observed fetch/identity/query/state effect, marker object, and negative control.
- Redact cookies, API tokens, usernames from real tenants, issue summaries, attachment names, callback tokens, upstream response bodies beyond synthetic markers, SQL expressions beyond grammar class, and any configuration value that could be reused as a payload.
- The same scan included sparse CISA KEV additions for Oracle E-Business Suite improper privilege management and KNX lockout behavior plus low-signal availability/cache advisories. They were marked processed without promotion because this run did not identify a safe, durable operator workflow beyond existing authorization and availability-exclusion guidance.
