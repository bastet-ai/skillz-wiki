# Koel Subsonic SSRF and MantisBT SOAP/configuration boundary checks

Source: hourly offensive-security scan, 2026-07-15 GitHub advisory wave. Primary entries: [GHSA-6qvr-wjmv-v8mm](https://github.com/advisories/GHSA-6qvr-wjmv-v8mm) / CVE-2026-54491, [GHSA-rjg7-r26h-cfp2](https://github.com/advisories/GHSA-rjg7-r26h-cfp2), [GHSA-jr4p-4xjh-fwvw](https://github.com/advisories/GHSA-jr4p-4xjh-fwvw), [GHSA-8q6q-m837-fv64](https://github.com/advisories/GHSA-8q6q-m837-fv64), [GHSA-6p96-cfg5-4vhp](https://github.com/advisories/GHSA-6p96-cfg5-4vhp), [GHSA-w79m-f3jx-779v](https://github.com/advisories/GHSA-w79m-f3jx-779v), [GHSA-c2xg-qjqw-2v98](https://github.com/advisories/GHSA-c2xg-qjqw-2v98), [GHSA-v84x-qvhg-f36r](https://github.com/advisories/GHSA-v84x-qvhg-f36r), [GHSA-mw6p-33vw-46cc](https://github.com/advisories/GHSA-mw6p-33vw-46cc), [GHSA-m7ph-9558-mrx3](https://github.com/advisories/GHSA-m7ph-9558-mrx3), [GHSA-4vpf-w7qv-5h3q](https://github.com/advisories/GHSA-4vpf-w7qv-5h3q), and [GHSA-3v2j-6fw9-f57c](https://github.com/advisories/GHSA-3v2j-6fw9-f57c).

This batch is durable because the advisories expose reusable operator boundaries: compatibility API routes that create the same media objects as the primary API but omit SSRF validation, URL guards that miss IPv6 transition wrappers or keep evaluating network-fetching validators after a failed safe-URL check, SOAP authentication that trusts a caller-supplied username plus a reusable cookie string, administrator configuration paths that cross into PHP `eval()` or SQL `ORDER BY` construction, and REST/SOAP issue-update routes that apply broader update permissions than the specific workflow, note-type, billing, and unreleased-version controls enforced elsewhere.

!!! warning "Authorized validation only"
    Keep proofs to disposable Koel and MantisBT labs, owned callback listeners, synthetic audio/feed responses, marker-only bug reports, fake users, and harmless configuration values. Do not fetch metadata services, internal production URLs, private bugtracker data, real attachments, password hashes, API tokens, cookie strings from real users, web roots, or database files. Do not publish weaponized SOAP/RCE/SQL payloads or trigger destructive project/issue operations.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-6qvr-wjmv-v8mm](https://github.com/advisories/GHSA-6qvr-wjmv-v8mm) / CVE-2026-54491 | Koel podcast/radio server-side fetchers through native and Subsonic APIs | The earlier `SafeUrl` fix applied redirect-hop validation to one episode-playable path, while sibling fetchers still perform only point-in-time host checks or no check; HTTP redirects and DNS rebinding can move a public-looking URL to private targets | Treat SSRF fixes as call-site coverage problems: enumerate every fetcher, redirect policy, and DNS-resolution boundary rather than retesting only the patched path. |
| [GHSA-rjg7-r26h-cfp2](https://github.com/advisories/GHSA-rjg7-r26h-cfp2) | Koel podcast enclosure fetcher | `isPublicHost()` relies on PHP private/reserved IP flags that do not classify NAT64 `64:ff9b::/96` or 6to4 `2002::/16` wrappers of internal IPv4 addresses as blocked; affected episode downloads can return the fetched body | Add IPv6 transition-address fixtures to SSRF guard testing, especially for full-read media or feed enclosures in IPv6-capable labs. |
| [GHSA-jr4p-4xjh-fwvw](https://github.com/advisories/GHSA-jr4p-4xjh-fwvw) | Koel native `POST /api/radio/stations` validation chain | The URL field lacks Laravel `bail`, so `HasAudioContentType` still sends HTTP requests after `SafeUrl` rejects a private/reserved URL; distinct validation errors create a blind reachability oracle | Test whether validation chains stop before network side effects, not just whether a safe-url rule eventually reports an error. |
| [GHSA-8q6q-m837-fv64](https://github.com/advisories/GHSA-8q6q-m837-fv64) | Koel Subsonic `createPodcastChannel.view` and podcast stream helper | Feed URLs are fetched before the safe URL checks that later cover episode enclosures; stream helpers validate the original URL but accept followed redirect targets | Add direct-feed and redirect-target checks to Subsonic compatibility-route SSRF testing. |
| [GHSA-6p96-cfg5-4vhp](https://github.com/advisories/GHSA-6p96-cfg5-4vhp) | Koel Subsonic `createInternetRadioStation.view` / `updateInternetRadioStation.view` | Subsonic radio routes accept `streamUrl` without the `SafeUrl` and content-type validation used by the primary radio API, then playback returns the fetched upstream body | Add compatibility-route parity checks to media SSRF testing and distinguish full-read SSRF from blind callbacks. |
| [GHSA-w79m-f3jx-779v](https://github.com/advisories/GHSA-w79m-f3jx-779v) | Koel Subsonic `createPodcastChannel.view` | Subsonic podcast creation accepts a URL with only generic URL validation and immediately passes it to the podcast parser | Test server-side fetch guards on alternate client/protocol APIs, not only the web UI or main REST API. |
| [GHSA-c2xg-qjqw-2v98](https://github.com/advisories/GHSA-c2xg-qjqw-2v98) | MantisBT SOAP API `mci_check_login()` | SOAP login accepts a valid `cookie_string` while trusting a caller-supplied username, enabling user impersonation through SOAP even when Web UI/REST derive identity server-side | Add identity-binding tests for legacy SOAP/XML-RPC APIs next to modern REST routes. |
| [GHSA-v84x-qvhg-f36r](https://github.com/advisories/GHSA-v84x-qvhg-f36r) | MantisBT admin `adm_config_set.php` non-string config parser | Non-string configuration values pass through a tokenizer using PHP `eval()`; declarations can be hoisted past a prefixed `return` and collide with later autoloading | Treat admin configuration DSLs as code-execution surfaces and prove only inert class/function collision markers. |
| [GHSA-mw6p-33vw-46cc](https://github.com/advisories/GHSA-mw6p-33vw-46cc) | MantisBT `history_order` config value | Admin-controlled sort configuration is concatenated into an issue-history SQL `ORDER BY` clause | Add config-key-to-query-construction checks where stored admin settings are later executed in user-triggered views. |
| [GHSA-m7ph-9558-mrx3](https://github.com/advisories/GHSA-m7ph-9558-mrx3) | MantisBT REST/SOAP issue status update | API issue updates use the general update threshold instead of the stricter status-transition threshold | Test workflow-state permissions separately from generic object-edit permissions across every API family. |
| [GHSA-4vpf-w7qv-5h3q](https://github.com/advisories/GHSA-4vpf-w7qv-5h3q) | MantisBT REST/SOAP issue note update path | API issue updates accept caller-controlled `note_type` values that create time-tracking notes, and SOAP can also register reminder notes, without the note-type-specific authorization expected by billing/reminder workflows | Add field-family controls to API update tests: generic issue-update permission should not imply permission to create billable-hours or reminder note classes. |
| [GHSA-3v2j-6fw9-f57c](https://github.com/advisories/GHSA-3v2j-6fw9-f57c) | MantisBT REST/SOAP product-version assignment | Users below the unreleased-version reporting threshold can still assign unreleased product versions through API issue updates | Test lifecycle-state and release-channel invariants separately from generic issue-edit access. |

## Replayable validation boundaries

### Koel Subsonic media SSRF parity checks

1. Stand up Koel `v9.6.0` or an explicitly vulnerable lab image with one disposable authenticated user and no access to production libraries.
2. Configure three owned targets: a public audio/feed canary, a loopback/private canary service under your control, and a blocked destination class that should fail `SafeUrl` through the primary API.
3. First exercise the primary web/API radio and podcast creation routes and record the expected `SafeUrl` rejection for the private canary.
4. Repeat through the Subsonic-compatible routes: radio `streamUrl` on create/update and podcast `url` on channel creation.
5. For radio, trigger playback only against your owned canary and record whether Koel streams the upstream marker body back to the client. For podcast, record whether channel creation causes the server-side callback while parsing the feed.
6. Add controls for unauthenticated access, a patched build, public-only URLs, invalid schemes, redirects from public to private URLs, DNS rebinding if explicitly in scope, and content-type handling for the radio stream.

Report this as **alternate Subsonic route -> missing primary API SSRF validator -> server-side fetch / full-read stream**. Evidence should be route, authenticated role, target class, callback or returned marker body, and primary-API negative control. Do not probe metadata endpoints, Kubernetes APIs, Redis/admin panels, or third-party hosts.

### Koel incomplete SSRF-fix coverage checks

1. Build a Koel lab at an affected version such as `<= 9.7.0` plus, if possible, a patched `9.7.1` negative-control target.
2. Inventory every server-side fetcher reachable by an authenticated user: podcast add/refresh, podcast stream resolution, podcast-obsolete checks, radio content-type validation, native API routes, and Subsonic compatibility routes.
3. For each fetcher, run owned canary classes: direct public URL, public URL that returns a single 302 to a loopback/RFC1918 canary you control, an in-scope DNS-rebinding hostname if the assessment explicitly permits rebinding tests, NAT64/6to4 transition-address hostnames that map only to synthetic lab canaries, and URLs that should fail `SafeUrl` before any content-type validator can send a request.
4. Compare sibling call sites against the path that has per-redirect-hop validation. The operator finding is strongest when one call site blocks the redirect or transition address while another follows it under the same target class.
5. Record whether validation happens before the request, after following redirects, on each redirect hop, after DNS resolution, after IPv6 transition normalization, or not at all. Include whether validation stops before network side effects and whether the response is blind callback-only, a validation-error reachability oracle, reflected as a parsed feed/stream URL, or returned as a full-read media body.
6. Add controls for unauthenticated users, disabled Subsonic API, patched redirect callbacks, manual redirect-follow disabled, ordinary IPv4/IPv6 private-range hostnames, blocked NAT64/6to4 wrappers, Laravel `bail` or stop-on-first-failure behavior, and content-type gates.

Report this as **incomplete SSRF remediation -> sibling fetcher or validator lacks redirect-hop/DNS/transition-address/side-effect guard -> authenticated user can steer Koel server-side requests**. Evidence should be a call-site matrix, target class, redirect chain or DNS decision table, validation-chain trace, canary hit, full-read versus blind classification, and patched-path negative control. Never use cloud metadata, production internal services, or third-party redirectors as proof targets.

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

### MantisBT API workflow, note-type, billing, and version permission drift

1. Create a lab project with a user who has the default `UPDATER` capability but does not meet a deliberately higher `set_status_threshold` such as `DEVELOPER`.
2. Through the Web UI, confirm the user cannot perform the restricted status transition on a synthetic issue.
3. Replay equivalent REST and SOAP issue-update calls that attempt to set only the status field to a marker state.
4. Add one synthetic time-tracking report window and one synthetic unreleased product version. Through the Web UI, confirm the same user cannot create restricted billable time/reminder note classes or assign unreleased versions unless the relevant thresholds allow it.
5. Replay REST/SOAP issue-update calls that attempt only marker-safe changes: a status transition, a `TIME_TRACKING` note type with harmless marker hours, a SOAP reminder note that does not notify real users, and an unreleased product-version assignment on a disposable issue.
6. Record whether the API accepts these fields because it checks the general update threshold instead of the specific workflow, time-tracking/reminder, billing-report, or unreleased-version threshold.
7. Add controls for a user below `update_bug_threshold`, a user above each specific threshold, patched MantisBT `2.28.4`, closed/resolved workflow rules, REST versus SOAP differences, Web UI negative controls, and unrelated issue-field edits.

Report this as **API issue edit -> generic update permission accepted for protected status/note/version fields -> workflow, billing, reminder, or release-lifecycle control bypass**. Keep evidence to role matrices, marker issue IDs, fake billing windows, and synthetic version names; do not mutate production bug state, create real billable hours, notify real users, or expose customer project/release data.

## Reporting notes

- Lead with preconditions: Koel authenticated user and Subsonic route exposure, target URL class, primary API rejection evidence, MantisBT version, SOAP availability, self-registration state, cookie-string provenance, configured thresholds, administrator requirement for config sinks, database privileges, and patched controls.
- Prefer decision tables over payload dumps: route family, actor role, supplied URL/username/config key/status field, expected validator or permission, observed fetch/identity/query/state effect, marker object, and negative control.
- Redact cookies, API tokens, usernames from real tenants, issue summaries, attachment names, callback tokens, upstream response bodies beyond synthetic markers, SQL expressions beyond grammar class, and any configuration value that could be reused as a payload.
- The same scan included sparse CISA KEV additions for Oracle E-Business Suite improper privilege management and KNX lockout behavior, MantisBT admin-install reflected XSS and export-page stored XSS items, plus low-signal availability/cache advisories. They were marked processed without promotion because this run did not identify a safe, durable operator workflow beyond existing authorization, trusted-render, and availability-exclusion guidance.
