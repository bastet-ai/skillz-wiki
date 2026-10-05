---
title: "Joomla extension wave — token-existence authz, public save controllers, and unauthenticated task triggers (Oct 5 18:34Z)"
---

# Joomla extension wave: token-existence authz, public save controllers, and unauthenticated task triggers (Oct 5 18:34Z)

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-10-05. The 18:34Z wave carried a Joomla-extension cluster from distinct vendors. Four legs carry reusable operator axes; the rest land on canonical classes (reflected/stored XSS, classic IDOR-by-ID) and are tracked without publication. Joomla/CMS-extension surfaces remain high-yield because third-party extensions ship their own controllers beside the core's hardened ones — the core's CSRF/ACL model protects nothing the extension never calls.

Advisories:

- [GHSA-6qrr-hhgq-84g9 / CVE-2026-102775](https://github.com/advisories/GHSA-6qrr-hhgq-84g9) — Phoca Cart 5.0.0–6.1.8 order-file download (high)
- [GHSA-5q6m-pwqm-wmc9 / CVE-2026-102780](https://github.com/advisories/GHSA-5q6m-pwqm-wmc9) — TF Content 2.9.0–2.9.4 cross-record publication + mass assignment
- [GHSA-hqjq-hvr2-rrg3 / CVE-2026-102779](https://github.com/advisories/GHSA-hqjq-hvr2-rrg3) — TF Content unauthenticated task execution
- [GHSA-2gw6-8g27-32rm / CVE-2026-102777](https://github.com/advisories/GHSA-2gw6-8g27-32rm) — Event Gallery < 6.6.0 Google Photos picker SSRF with token attach
- [GHSA-ch52-jhqg-qhvj / CVE-2026-102428](https://github.com/advisories/GHSA-ch52-jhqg-qhvj) — OrdaSoft Joomla CCK < 8.3.16 unauthenticated order-column SQLi (critical)

!!! warning "Authorized validation only"
    Disposable Joomla install, synthetic orders/products/records/tasks, guest and low-role lab accounts, owned callback listeners for the SSRF leg, and marker values only. The Phoca leg is a *digital-goods download* endpoint — prove with a synthetic product file you uploaded yourself, never a real customer's order. The task-trigger leg must fire only lab tasks whose executor is a no-op marker.

## 1. Token *existence* checks are not token checks (Phoca Cart CVE-2026-102775, high)

Phoca Cart's order-file download endpoint takes a download token `d` and order token `o` and **verifies only that they are non-empty** — never compared to the stored `download_token`/`order_token`. Any remote user, including a guest, downloads any customer's digital goods by enumerating sequential `id` values with arbitrary non-empty tokens.

Operator axis:

1. **Sweep every token-bearing parameter for the equality-vs-existence split.** The handler pattern to hunt (white-box) or probe (black-box): a guard like `if (empty($token)) throw` and no `===` against the stored value anywhere in the path. Black-box shape: request the same object twice — once with the *real* token, once with a sentinel value like `0` or `x` — and compare. Identical 200/file-body responses mean the token is decorative.
2. **Sequential IDs + decorative tokens = enumeration download.** On e-commerce/learning/CMS extensions with "secure link" file delivery, always test token substitution before assuming link-sharing is the worst case. This is the same non-empty-only guard class as the missing-`allowAccess()`-call family on the Sept 21 pages, narrowed to a single predicate.
3. Report framing: state that *possession of the URL is not the secret* once existence-check-only is proven, and quantify enumerability (ID stride, order count exposure from any public counter).

## 2. The public frontend controller that trusts `jform` (TF Content CVE-2026-102780 + CVE-2026-102779)

Two legs from one extension show how a "public submission" feature re-implements authorization badly:

- **Shared save controller** (`RecordController`) unconditionally authorizes *both create and edit*, accepts the raw Joomla `jform` array, honors a **request-selected existing record ID**, and saves **without filtering submitted properties** through the configured form. A Guest obtains a valid CSRF token from Joomla's own public login form and modifies any row — mass-assigning `published`, `access`, `created_by`.
- **Site task `records.custom_action`** is exposed with no authentication, ACL, CSRF, or cron-token enforcement: supply the numeric ID of any published automation task and the server dispatches its configured executor immediately.

Operator axes:

1. **Joomla's public token supply is an attacker resource.** CSRF tokens minted for public forms (`com_user` login, com_config, module-rendered forms) are valid session tokens for component controllers that merely check "token present and session-matched." Every extension route that gates on token presence *instead of* user identity inherits guest reach. Enumerate public-token endpoints, then replay task/controller requests as a logged-out session holding a login-form token.
2. **Mass-assignment surface = raw request array forwarded to a table store.** Any `jform`/`data`/`properties` array that lands in `bind()`+`store()` without a whitelist lets you set *state columns*, not just content columns: `published`, `access`, `state`, `created_by`, `checked_out`. Differential test: submit the benign field set (baseline accepted) vs the benign set plus one state column on your own synthetic record — if the state column changes, the guard is absent; then prove cross-record effect only against a second disposable record you also own.
3. **Task/trigger endpoints are hidden action APIs.** Joomla site tasks (`?task=<component>.<action>`), WordPress `wp_ajax`/`wp-cron`, and CMS webhook shims are frequently shipped "for the scheduler" and left unauthenticated. Fuzz task names from the extension's XML manifest / routed controller class names and probe each with ID-only payloads against synthetic objects. The TF Content record is the CMS sibling of the message-bus and credential-test legs — the trigger verb skipped every control the CRUD verbs had.
4. Chain awareness: publication-state mass assignment + unauthenticated task execution compose into guest-driven content activation — test the *sequence*, not just each leg (set a gated record `published=1`, then trigger the task that consumes it).

## 3. Picker SSRF with the admin's OAuth token riding along (Event Gallery CVE-2026-102777)

The Google Photos picker's thumbnail fetch takes the fetch address from the request, unchecked and token-less, and attaches the **configured account's OAuth access token** to it. A prepared page on *another website* makes the server fetch any address — or internal network addresses — **in the name of a logged-in administrator** (cross-site trigger, no backend interaction needed), and a "Manage"-permission backend user can drive it directly. The token lasts about an hour and reaches everything the picker session reaches.

Operator axis: **third-party "asset picker" integrations are credential-riding SSRF with a zero-click trigger leg.** Same shape as the Eclipse Che devfile fold on the Sept 21 automation-platform page and the UTMStack PDF render leg: platform-stored OAuth/SA credential + user-chosen URL + server-side fetch. Cross-site request leg means the CSRF-tokenless GET-style task is driven from victim-context navigation — test pickers/preview/thumbnail proxies with an owned listener, capture the forwarded `Authorization` header client-side, and never store or replay real tokens. Proof: token-bearing outbound request to owned listener from both the logged-in-backend path and a cross-site page load.

## 4. Order/ORDER BY columns are user input (OrdaSoft CCK CVE-2026-102428, critical)

Unauthenticated SQLi because **the order column for records was user-provided and unvalidated**. Canonical sort-parameter class (see the Fleet `ORDER BY`+cursor page and the ORM query-grammar page) — one durable reminder for extension hunting: Joomla list views take `list ordering`/`list Direction`/`limitstart` params through `Joomla\CMS\MVC\Model\BaseDatabaseModel` helpers; extensions that interpolate them into raw SQL rather than through `$db->quote()`/whitelists are injectable, and the *public* frontend views are unauthenticated by default. Probe: `&list[ordering]=<expr>` / `&list[direction]=<fragment>` differential on any guest-visible listing.

## Tracked without publication (same wave)

- Phoca Cart separate IDOR leg already counted above; joomlafry CSRF-of-backend-list-tasks and share-page XSS/open redirect (canonical classes).
- LearnPress stored XSS through 4.4.9.1, Adsmonetizer reflected XSS, Image Slider Widget stored XSS (WP class-covered, Sept 19 page).
- Quay OAuth-callback XSS (fjvc/CVE-2026-102295) + post-login redirect XSS (f2m3/CVE-2026-102576, DB-auth precondition): XSS classes canonical; revisit if a registry-specific token-flow axis lands.
- dormakaba evolo .NET SYSTEM RCE (c2jx/CVE-2026-37719, zero sink detail, physical-access appliance product); GouGuOA/ApiAdmin/WookTeam/HospitalManagementSystem sparse Chinese-CMS singles; TallCMS low-sev single.
- @orpc/zod smart-coercion prototype injection (gcgf/CVE-2026-103918) was already tracked at 17:3xZ.
