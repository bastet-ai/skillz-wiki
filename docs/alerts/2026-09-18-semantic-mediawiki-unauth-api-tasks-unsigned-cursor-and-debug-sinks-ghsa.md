# Semantic MediaWiki server-side boundary wave: unauthenticated admin API, unsigned cursor tokens, and debug-output XSS sinks (GHSA, 2026-09-18)

Sources: GitHub Security Advisories published 2026-09-18T16:40–16:59Z (one 10-advisory Semantic MediaWiki wave; the stored `data-subtab` XSS from the same product family is covered on the [media client-side render sinks page](2026-09-18-opencast-caption-track-stored-xss-carrier-ghsa.md)).

- [GHSA-jr78-w6w5-m8f8: `api.php?action=smwtask` has no authorization check — unauthenticated admin-only maintenance tasks](https://github.com/advisories/GHSA-jr78-w6w5-m8f8)
- [GHSA-cx86-7xwp-w9wf / CVE-2026-77616: `Special:Ask` reflected XSS via forged unsigned cursor pagination token](https://github.com/advisories/GHSA-cx86-7xwp-w9wf)
- [GHSA-q5fm-9mx6-44f4 / CVE-2026-77610: `format=debug` / `DebugFormatter` reflected XSS (raw SQL + EXPLAIN echo)](https://github.com/advisories/GHSA-q5fm-9mx6-44f4)
- [GHSA-9rcc-pmj8-ffhr: `Special:FacetedSearch` `cstate` reflected XSS gated only by `crc32(q)` checksum](https://github.com/advisories/GHSA-9rcc-pmj8-ffhr)
- [GHSA-hw3m-8j5x-94ff / CVE-2026-77609: `Special:URIResolver` open redirect via interwiki-prefixed subpage](https://github.com/advisories/GHSA-hw3m-8j5x-94ff)
- [GHSA-7xv3-gf2g-498h / CVE-2026-77607: `Special:Ask` table `sep` separator reflected XSS (also via `request_type=raw`)](https://github.com/advisories/GHSA-7xv3-gf2g-498h)
- [GHSA-59xw-qv23-j3rc / CVE-2026-77608: `Special:SearchByProperty` `property`/`value` reflected XSS in form + error text](https://github.com/advisories/GHSA-59xw-qv23-j3rc)
- [GHSA-3jp5-3h47-28qf / CVE-2026-77606: `Special:Ask` `headers=plain` header reflection](https://github.com/advisories/GHSA-3jp5-3h47-28qf)

The durable lesson: **every alternate programmatic surface (API module, debug format, raw output mode, pagination token, checksum-gated state) is a separate trust boundary that must be tested even when the human-facing feature is locked down or escaped.**

## Why this is worth an operator pattern

- **API module vs Special page authorization parity.** `api.php?action=smwtask` runs admin-only maintenance tasks (`table-statistics`, `duplicate-lookup`, `insert-job`, `update`, `check-query`, `run-joblist`) while the equivalent `Special:SMWAdmin` UI requires `smw-admin`. The module's only gates were `needsToken('csrf')` + `mustBePosted()` — and MediaWiki hands **anonymous** users the fixed public CSRF token `+\`, so a token check is not an authorization check. Reusable sweep: for every privileged Special page or admin UI on any platform, enumerate `api.php?action=*` (or the REST equivalent) for modules that back the same operations and diff the permission gates; run the read tasks anonymously as a state oracle and note that `insert-job` + `smw.entityIdDisposer` with a chosen `id` turns disclosure into targeted mutation of stored data.
- **Unsigned "opaque" tokens are attacker-controlled input.** The `Special:Ask` cursor is base64url JSON with **no signature** — decode, edit `sort_prop`/`sort_order`, re-encode. When the anchor mismatches the request `sort=`, the error text interpolates those values into a raw string that bypasses the message-layer sanitizer and lands in `Html::errorBox()` raw. Rule: any pagination/state/cursor/token that decodes to readable JSON/JWT-without-verification is a reflected-XSS candidate at every sink that echoes its fields into error paths.
- **Checksum gates are compute-and-bypass controls.** `Special:FacetedSearch` only preserves `cstate` when `csum == crc32(q)` (or `filtered=1`). Both are trivially computable client-side (`crc32` of your own `q`), so the "gate" filters nobody. Whenever a request parameter survives only if it satisfies a deterministic function of *other attacker-controlled parameters*, compute the function and pass the gate.
- **Debug/verbose output paths are forgotten XSS sinks.** `format=debug` echoes the re-serialized query (escaping only `[`), the generated SQL verbatim (SQL-quoted ≠ HTML-escaped), and `EXPLAIN` plan text containing the value literals — as raw `addHTML`, never through the parser sanitizer. On MediaWiki-family and any query UI: request `format=debug`/`debug=1`/trace/verbose variants with an inert markup canary in a text-typed property value, on both the special page and any inline-parser context (the inline `{{#ask|format=debug}}` leg was safe here because output re-enters the sanitizer — the special-page leg was not).
- **Raw/alternate output modes double the sink count.** The `sep` injection was reachable through standard render **and** `request_type=raw`; test every output-format parameter variant (`format=raw/json/csv/debug`) as its own render pipeline.
- **Redirect validation belongs at the sink.** `Special:URIResolver` 303-redirected to a title resolved from a user-controlled subpage without host checks; an interwiki prefix (`Special:URIResolver/mw:Foo`) hops off-host from a trusted wiki URL. Always re-validate the **final target URL** (host + no userinfo component), not the input path — and sweep interwiki/alias-prefix resolution as an off-host channel.

## Validation workflow (authorized scope only)

!!! warning "Lab wiki, anonymous read-only proofs, inert canaries"
    Run against a lab or explicitly authorized Semantic MediaWiki / MediaWiki target. All proofs below are anonymous or low-privilege; use inert DOM markers (`<img src=x onerror="window.__canary=1">`-style) and no network callbacks.

1. **API parity sweep:** enumerate `api.php?action=*` modules (`action=query&meta=siteinfo`siprop=apimodules`) and fingerprint SMW (`action=smwtask`, `smwprops`, etc.). For each module backing an admin UI feature, replay it anonymously with the public token `+\`: `curl -s 'HOST/api.php?action=query&meta=tokens&type=csrf&format=json'` then POST `action=smwtask&task=table-statistics&token=+\`. HTTP 200 with store statistics = authorization-parity finding; record the task list you reached. Do not run `insert-job`/`run-joblist` beyond a single benign enqueue in a lab, and never against production wikis.
2. **Cursor-token XSS:** fetch a normal `Special:Ask` pagination cursor, base64url-decode it, set `sort_prop` to an inert structural marker, re-encode, submit with mismatched `sort=`; diff submitted → served bytes → parsed DOM (no CSP means inline markup survives here).
3. **Debug sink:** `Special:Ask?q=[[Text::<inert-marker>]]&debug=1` as anonymous; check all three echo legs (query string, prettified SQL, EXPLAIN) — escaping one sink is not escaping the path.
4. **Checksum gate:** pick `q`, compute `csum=crc32(q)` in any language (or just send `filtered=1`), inject an inert marker into `cstate[0]`, confirm raw mustache `{{{hidden}}}` output.
5. **Redirect + separator controls:** resolve `Special:URIResolver/<interwiki>:Foo` and observe 303 off-host with a user-info-bearing target rejected post-fix; re-request a table query with `sep` set to a marker and with `request_type=raw`.
6. **Version control:** patched release must return 403/permission errors for smwtask and encode all marker legs.

## Reporting checklist

- State the anonymous-token detail explicitly (`+\` fixed public CSRF token) — it preempts the "but a token was required" triage dismissal.
- Separate the classes: missing authorization (smwtask, CVSS 7.3, state-changing), reflected XSS (cursor, debug, cstate, sep, headers, SearchByProperty — note absence of CSP), open redirect (URIResolver).
- For smwtask, name the reachable tasks and the disclosure→mutation bridge (object-ID enumeration via `duplicate-lookup` feeding `entityIdDisposer` id parameter).
- Cite the sink chain (`Query::addErrors()` → `ErrorWidget::queryError()` → `Html::errorBox()` raw) — error-path text is attacker-influenced and must not be treated as trusted.

## October 23 follow-up: BlueSpice (MediaWiki platform) — empty-string config fails the IP gate open, REST endpoints skip the UI's permission check

Two BlueSpice advisories published 2026-10-23T09:31Z extend the same MediaWiki-family axis:

- [GHSA-xrr7-cjx6-x9j2 / CVE-2026-25784 (critical): BlueSpice container default `$mwsgTokenAuthenticatorServiceCIDR` — intended to restrict internal service token authentication to the container network — evaluated to an **empty string** when env var `WIKI_SERVICE_TOKEN_AUTH_ALLOWED` was unset; the token authenticator treats empty as "no IP restriction," so **any reader (including anonymous on public wikis) could obtain an application token from the REST API and mint a sysop session as the internal service user](https://github.com/advisories/GHSA-xrr7-cjx6-x9j2) (affected 5.2.3–5.2.7 and container images published before 2026-10-19 15:37 UTC — image republish date is the fingerprint, not the version tag).
- [GHSA-vr6v-xrj8-f9m9 / CVE-2026-25716 (high): `BlueSpiceUserManager` REST endpoints `/bs-usermanager/v1/block/create|delete` call `UserManager::blockUser()/unblockUser()` with **no permission verification at all** — any authenticated user blocks/unblocks arbitrary accounts including admins](https://github.com/advisories/GHSA-vr6v-xrj8-f9m9) (fixed 5.1.11/5.2.7).

Operator rules reinforced:

1. **Empty-container semantics battery on every config gate.** A restriction list that is empty because "not configured" must be probed: does empty mean allow-all (here it did) or deny-all? Send the unconfigured-default shape (no env var, empty string, empty array) against any CIDR/allowlist/domain gate before testing injection against it. Container images make this worse: the shipped `LocalSettings.php` default, not the upstream extension default, is what runs.
2. **Token-forge ladder on wikis:** anonymous read → REST application token → sysop session is the highest-ladder anonymous finding in this product family; on any BlueSpice/MediaWiki deploy, request the service-token endpoint from a non-container-network source as the negative control.
3. **Extension REST endpoints are a separate authorization surface from the Special-page UI** — same API-parity rule as `api.php?action=smwtask` above: `block/unblock` reached via `/bs-usermanager/v1/*` with a base-user token is the proof shape (block a disposable account, then unblock; also a lockout-admin DoS primitive).
4. **Image-republish fix dates:** BlueSpice 5.2.7 "fixed" only in images rebuilt after 2026-10-19 15:37 UTC — pull-time fingerprinting (image digest/created timestamp) beats version tags when validating this band.

Related pages: [Semantic MediaWiki stored `data-*` client-side sink](2026-09-18-opencast-caption-track-stored-xss-carrier-ghsa.md) (same product, opposite half: front-end dataset sink), the [Sept 18 Nextcloud app-layer authority drift](2026-09-18-nextcloud-app-layer-authority-drift-circles-keyid-ssrf-webdav-locks-and-deck-config-ghsa.md) (REST-vs-alternate-transport authorization parity is the same axis), and the [Sept 16 sanitizer-gap page](2026-09-16-rmcp-oauth-resource-spoofing-mdc-sanitizer-gaps-and-vllm-route-guard-parity-ghsa.md).
