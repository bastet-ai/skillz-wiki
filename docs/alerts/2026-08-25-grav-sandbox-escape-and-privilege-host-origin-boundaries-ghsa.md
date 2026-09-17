# Grav sandbox-escape, privilege-validation, and host/origin trust boundaries

Source: GitHub Security Advisories `unreviewed` feed, 2026-08-25 (all first published 2026-08-25): [GHSA-3625-697m-q29v](https://github.com/advisories/GHSA-3625-697m-q29v) (Email plugin unsandboxed Twig → OS command, high 8.8), [GHSA-crrc-vpp2-f5x7](https://github.com/advisories/GHSA-crrc-vpp2-f5x7) and [GHSA-mw85-cjh9-8hp7](https://github.com/advisories/GHSA-mw85-cjh9-8hp7) (Twig sandbox config-secret read, high 7.5 / 6.5), [GHSA-8vp7-8q4w-vv7m](https://github.com/advisories/GHSA-8vp7-8q4w-vv7m) (`offsetGet`/`offsetexists` User-field read, high 6.5), [GHSA-qw9m-fc79-372g](https://github.com/advisories/GHSA-qw9m-fc79-372g) (login unlock handler missing privilege check, critical 9.8), [GHSA-92vc-67q9-382j](https://github.com/advisories/GHSA-92vc-67q9-382j) and [GHSA-px9v-979x-qmh9](https://github.com/advisories/GHSA-px9v-979x-qmh9) (non-constant-time token/nonce compare, high 7.5 / medium 3.7), [GHSA-55hc-4r2f-h6wr](https://github.com/advisories/GHSA-55hc-4r2f-h6wr) (email enumeration, critical 5.3), [GHSA-qh7h-6c7g-x8m6](https://github.com/advisories/GHSA-qh7h-6c7g-x8m6) (unanchored `Referer` prefix origin bypass, critical 5.4), [GHSA-6c2c-797q-5r9x](https://github.com/advisories/GHSA-6c2c-797q-5r9x) (`sendInvitationEmail` untrusted `Host`, high 7.5), [GHSA-896w-cw95-xq7w](https://github.com/advisories/GHSA-896w-cw95-xq7w) (`deleteFile` path traversal, high 8.1), [GHSA-cpcf-vm8j-257x](https://github.com/advisories/GHSA-cpcf-vm8j-257x) (scheduler lock-file symlink, high 8.4), [GHSA-h2w4-jr6m-7c52](https://github.com/advisories/GHSA-h2w4-jr6m-7c52) (webhook DNS-rebinding SSRF, medium 5.3), and [GHSA-f549-r4pw-jw3m](https://github.com/advisories/GHSA-f549-r4pw-jw3m) (Flex Objects shortcode authorization bypass, high 7.7). Core Grav affects `2.0.16`/`3.9.2`, Login plugin `3.9.1`/`1.0.16`, Email plugin `4.2.2`, API plugin `1.0.16`, Flex Objects `1.4.0–1.4.7`.

Grav is a flat-file CMS whose page model lets content editors render Twig. This wave is durable because it concentrates a reusable set of editor-to-authority boundaries: page-editor content crossing into unsandboxed Twig evaluation, a sandbox denylist that misses config/user fields, an API row-action that omits a privilege check, and host/origin validation that trusts untrusted headers. The "editor can render a template but the template is not sandboxed" chain (Email plugin) and the "sandbox allowlist method leaks a sensitive object" chain (`offsetGet`) are the same trust-confusion family that recurs in any CMS that exposes a template engine to non-admin editors.

!!! warning "Canaries only"
    Run these checks in a disposable Grav install with synthetic users, marker files, and owned no-content peers. Use denied command/file/network sinks. Never execute a real OS command, read or delete real files, enumerate real user accounts, exfiltrate config secrets, or reach internal services.

## Boundary map

| Surface | Caller-controlled value | Privileged transition | Safe positive |
| --- | --- | --- | --- |
| Email plugin form field | Twig expression in `email.body` | page-editor content evaluated **unsandboxed** as OS command | expression is sandboxed or not evaluated; canary command is denied |
| Twig sandbox | `config.get`/`config.toArray`, `offsetGet`, dot-notation arrays | page-editor reads config/user secrets | denied paths + filtered methods block the read |
| login unlock row-action | `api.users.write` session | clears lockout on `admin.super` without privilege check | target-account privilege validated |
| `Referer`/`Host` header | attacker `Referer`/`Host` prefixing the site | origin/redirect validation treated as same-origin | anchored + scheme/port-anchored validation |
| `deleteFile` | `../`-shaped media filename | authenticated delete escapes media root | path confined to media root |
| lock-file create | pre-placed symlink at predictable temp path | scheduler overwrites an arbitrary writable file | target validated / symlink rejected |
| webhook hostname | attacker-controlled DNS | rebinding passes public validation, reaches private delivery | re-validate final resolved peer |

## Email plugin unsandboxed-Twig command execution

The most severe item. The Email plugin renders page-editor-controlled form `process.email.body` as a **non-sandboxed** Twig template. A user with only `api.access` + `api.pages.write` can place a Twig OS-command expression, publish the page, and submit the form to run a command as the PHP account.

1. In a disposable Grav with the Email plugin, create a page with a form whose `process.email.body` is a harmless Twig marker (e.g. one that would print a canary).
2. Publish and submit as a low-priv editor.
3. Record whether the expression is evaluated in a sandbox or as arbitrary Twig with full function access.

| Input | Expected secure result |
| --- | --- |
| ordinary text body | rendered, no evaluation |
| `{{ ... }}` expression | sandboxed to a denied allowlist; no OS/`system`/process access |

A bounded positive is the expression reaching an unsandboxed evaluation path that *would* reach a process sink. **Do not run a real command.** Prove the sandbox is absent with the recorded evaluation path and a denied command sink; execution is the downstream risk, reported as such without a live payload.

## Sandbox allowlist leaks: config and user fields

Three related leaks show an incomplete sandbox denylist:

- **Config secrets** — `config.get()` / `config.toArray()` (and dot-notation array access) return `system.cache.redis.password`-style values when `config_access` is enabled; `config_denied_paths` is bypassed by dot notation.
- **User fields** — allow-listed `offsetGet()`/`offsetexists()` on `User` objects lack field filtering, exposing hashed passwords and 2FA secrets to any page editor.

Test each with a synthetic user and a config containing only fake canary values:

| Probe | Expected secure result |
| --- | --- |
| `config.get('system.cache.redis.password')` | denied path; no value returned |
| `config.toArray()` | filtered arrays, no secrets |
| `user.offsetGet('password')` / `offsetGet('two_factor')` | field filtered out |

A positive is a canary config value or a synthetic user's marker password/2FA field appearing in rendered output. Report the specific allow-listed method and the missing field filter; never capture a real credential.

## Login unlock handler privilege gap

`onApiUserListRowAction` (unlock) with `api.users.write` clears login lockout counters on `admin.super` accounts without validating the target account's privilege. In a lab: as a low-priv user, clear the lockout on a synthetic admin account and record whether the highest-privilege account's brute-force protection is removed. A positive is the `admin.super` lockout cleared by a lower-privilege principal. Report the missing target-privilege check; do not target real accounts.

## Host/origin validation trust confusion

- **Unanchored `Referer` prefix match** — `Uri::referrer()`/`Pages::referrerRoute()` use `str_starts_with($referrer, $base)` with no trailing delimiter, so `https://example.com.attacker.tld` is treated as same-origin. Test with an owned domain that prefixes the victim origin and record the origin decision. A positive is the attacker origin passing the same-origin check.
- **`sendInvitationEmail` untrusted `Host`** — invitation links are built from the unvalidated `Host` header; `require_trusted_host` only guards password reset. Manipulate `Host` and record the resulting token-bearing link target. A positive is the invitation link pointing to the attacker-controlled host.
- **Email enumeration** — `register()` throws a distinct `EMAIL_NOT_AVAILABLE` for existing addresses with no rate limit. Note this as an enumeration primitive; do not enumerate real accounts, only confirm the differential response on synthetic data.

## File/symlink sinks

- **`MediaUploadTrait::deleteFile` traversal** — only the basename is validated; `../` in the directory portion reaches `unlink()`. Use a sibling marker file in a scratch root and record whether it is deleted.
- **Scheduler `createLockFile` symlink** — a pre-placed symlink at the predictable, world-writable temp lock path can be followed to overwrite an arbitrary writable file. Place a symlink to a scratch marker and record whether the scheduler writes through it. Stop at the denied `write`/`unlink`/ownership syscall against the sibling canary; do not target real files.

## Webhook DNS-rebinding SSRF

The Grav API plugin validates the configured webhook hostname with one lookup and delivers with another. Use two owned DNS answers (public for validation, private for delivery) and record the validation peer vs the delivery peer. A bounded positive is validation on an owned public peer while delivery reaches an owned private/loopback peer. Never reach cloud metadata, loopback admin routes, or internal services.

## Reporting heuristics

- Frame the Email item as "Grav Email plugin evaluates page-editor form fields as unsandboxed Twig," citing the low-priv capability set and the process sink.
- Keep the sandbox-leak items scoped to the specific allow-listed method and the missing field/denied-path filter, with a synthetic canary.
- For the host/origin items, cite the exact comparison (`str_starts_with` without delimiter, unvalidated `Host`) and the route it gates.
- Cite the per-plugin version bounds; the core CMS fixes land in `2.0.16`/`3.9.2`, plugins in their own lines.

## Safety

- Authorized, in-scope targets only; Grav sites are commonly shared hosting where "editor" may mean any content author.
- Synthetic users, fake config canaries, marker files, and owned no-content peers; denied command/file/network sinks.
- No real command execution, no real file read/delete, no real account enumeration, no config-secret exfiltration, no internal/metadata reach.
- Report the primitive at each boundary without performing the high-impact action on a live host.

## September 4 follow-up: 2FA secret rotation, sandbox exfil, decompression, and blueprint callable

Four later Grav advisories extend the 2026-08-25 editor-to-authority and sandbox work on this page. They belong here because each is a Grav-specific trust boundary in the same families already mapped above.

- **[GHSA-7mgc-c7pq-3rr3](https://github.com/advisories/GHSA-7mgc-c7pq-3rr3) / CVE-2026-62669 — 2FA bypass via `login.regenerate2FASecret` secret rotation.** The `regenerate2FASecret` row-action re-derives the TOTP secret and, in the vulnerable state, can be driven by a caller who should not control secret rotation, letting an attacker replace a target's 2FA secret with one they can compute. Reusable check: for any 2FA/TOTP row-action that *rotates or regenerates* the secret, confirm the actor is bound to the target account and the rotation is not callable by a different principal or by a self-service path the account owner does not own.
- **[GHSA-mc5q-6hpj-rp7j](https://github.com/advisories/GHSA-mc5q-6hpj-rp7j) / CVE-2026-61842 — Twig sandbox config exfiltration via `grav.offsetGet`.** A second, distinct sandbox-leak path to config: `offsetGet` (offset-access) reaches a config object the sandbox denylist does not cover. This is the same family as the existing `offsetGet`/`offsetexists` User-field read item, extending it to the config namespace. Reusable check: enumerate *every* object-accessor method the Twig sandbox allows and test each against config, user, and process objects, not just the originally-reported method.
- **[GHSA-928x-9mpw-8h56](https://github.com/advisories/GHSA-928x-9mpw-8h56) / CVE-2026-61690 — decompression bomb via `ZipArchiver` missing extraction limits.** An attacker-supplied archive reaches `ZipArchiver` with no size/entry/entropy bounds, so a high-compression-ratio archive expands to exhaustion during extraction. Reusable check: for any archive-unpack path that handles user content (media uploads, backup import, theme/plugin install), verify explicit bounds on uncompressed total size, entry count, and per-entry expansion, and test with a benign high-ratio canary archive that stops at the limit decision.
- **[GHSA-fj2p-qj2f-74v5](https://github.com/advisories/GHSA-fj2p-qj2f-74v5) / CVE-2026-64850 — RCE via unrestricted callable in Blueprint.** A Blueprint (plugin/config schema) field is passed to a callable without allowlisting, so a value that reaches `call_user_func`/dynamic invocation executes arbitrary code. Reusable check: for any CMS blueprint/config that stores a value later passed to a PHP callable, confirm the callable name is allowlisted or the value is treated as data; test with a marker callable that would be invoked if the allowlist were absent.

All four are canary-only: synthetic users, marker config values, a benign high-ratio archive, a marker callable, and a lab TOTP secret. No real secret rotation, no real config exfiltration, no real decompression, and no real command execution.

## September 5 follow-up: asset-escape XSS, reset-link host trust, cross-page form authz, and super-flag stripping (5 GHSAs)

Five later Grav records published 2026-09-05 extend the editor-to-authority and host-trust axes already mapped on this page. All five are canary-only: synthetic editors/admins, marker assets, owned no-content peers, marker invitation payloads, and denied write/exec sinks.

- **[GHSA-5pmv-xr2f-mrf8](https://github.com/advisories/GHSA-5pmv-xr2f-mrf8) — Twig sandbox asset-method XSS (Grav core < 2.0.20).** The sandbox allowlists `addJs`/`addCss` on `Grav\Common\Assets` without output escaping, so a page editor can register a malicious asset (script src or injected attributes) that renders unescaped into the document head and executes for **all visitors, including administrators**. Reusable check: for every sandbox-allowlisted object/method, test not only what the method *reads* but what it *emits into HTML* — allow-listing a method is not an escaping guarantee. Proof is a marker asset whose tag appears unescaped in the rendered head on a second user's page.
- **[GHSA-gg9g-7x93-5gq2](https://github.com/advisories/GHSA-gg9g-7x93-5gq2) — forgot-password reset links built from untrusted `Host` (grav-plugin-api < 1.0.20).** The forgot-password endpoint assembles the reset URL from the request `Host` header, so an attacker can request a reset for any account with a malicious `Host`, capture the token from the victim email, and complete account takeover including super-admin. This extends the existing `sendInvitationEmail` untrusted-`Host` item: the `require_trusted_host` guard covers only the invitation/reset paths it was written for, not the API plugin's own reset link builder. Reusable check: for every token-bearing email link, map the exact URL-construction call site and confirm the base URL comes from server configuration, not the request.
- **[GHSA-99h4-pmfq-pv63](https://github.com/advisories/GHSA-99h4-pmfq-pv63) — Form plugin cross-page form-name resolution without page authorization (Form < 9.1.22).** The plugin resolves a form *by name* across all pages and does not re-check page access for the page that owns the form, so an anonymous visitor can POST to any public page with a restricted form's name and trigger its save/upload/email/call actions. Reusable check: when an action is resolved by an attacker-chosen name/ID that spans multiple objects, the authorization must check the *resolved object's* access tier, not the entry page's.
- **[GHSA-rg66-gwrp-wj75](https://github.com/advisories/GHSA-rg66-gwrp-wj75) — invitation super-flag stripping misses dot-keyed variants (grav-plugin-api < 1.0.20).** `InvitationsController::stripSuperFlags()` removes nested super flags but not dot-keyed equivalents such as `api.super`; a non-super user manager with `api.access` + `api.users.write` can embed the dot-keyed flag in an invitation's access payload, and accepting the public invitation endpoint mints a **super-admin account with a valid JWT** with no real invitee interaction. Reusable check: whenever a guard strips forbidden keys from a user-supplied structure, test every notational variant (nested array key, dot-notation string, URL-encoded, case variants) against the same payload — key-stripping is a canonicalization problem, not a key-list problem.
- **[GHSA-6rq7-cjmj-rc58](https://github.com/advisories/GHSA-6rq7-cjmj-rc58) — group-inherited super permissions not validated in user-management guards (grav-plugin-api < 1.0.20).** The user-management guards check the *target account's own* flags but not group-inherited super status, so a non-super manager with `api.users.write` can patch password fields on group-super accounts to gain full administrative control. Reusable check: for any guard that decides "is this target privileged?", confirm it evaluates *effective* privilege (account flags + group + role inheritance), matching how the authorization engine resolves it elsewhere — a guard that re-derives privilege from a single field is the drift.

Durable axes this follow-up adds to the Grav map: **sandbox allow-list vs. output-escaping is two different controls** (a method can be safely callable yet still emit attacker HTML); **token-link URL builders are per-plugin**, so a trusted-host guard in core does not cover plugin-built links; and **privilege guards fail on canonicalization** — both the dot-keyed flag variant and the group-inheritance gap are the same class: the guard's key/privilege model is a simplified copy of the real one.

## September 16 late-night follow-up: pre-render validation bypass via Twig concatenation, and media-action CSS injection (2 GHSAs)

Two later Grav records published 2026-09-16T22:13Z extend the editor-to-rendered-content axis:

- **[GHSA-2c4f-86xc-cr74](https://github.com/advisories/GHSA-2c4f-86xc-cr74) / CVE-2026-61453 — XSS blueprint validator bypass via Twig string concatenation (Grav `= 2.0.0`, fixed 2.0.1).** `Security::detectXss()` scans the **raw page content before Twig processing**. `{% set %}` is an allowed tag and the `~` concatenation operator is a core operator never gated by the sandbox, so `{% set x = "on" ~ "error" %}<img src=1 {{ x }}=alert(1)>` passes validation (the validator's `on_events` regex sees no `on*=`, and `{` is outside its boundary character class) and then renders `<img ... onerror=...>` into `{{ content|raw }}`. The same technique reconstructs any blocked token: `<s{{"c"~"r"~"i"~"p"~"t"}}>` defeats the `dangerous_tags` blocklist, and `href="{{"java"~"script"}}:..."` defeats `invalid_protocols`. Reachable with `twig_content.process_enabled: true` plus `api.pages.write`. Reusable check: **any validator that runs on pre-template-engine input is bypassable by any construct that defers literal assembly to render time** — test the bypass with concatenated fragments for every blocked pattern family (event handlers, tag names, schemes), not just the originally reported vector. This is the exact dual of the Sept 5 lesson: guards fail both on canonicalization *downward* (dot-keys) and on *deferred* assembly (render-time reconstruction).
- **[GHSA-ffmg-hfvg-jhg9](https://github.com/advisories/GHSA-ffmg-hfvg-jhg9) / CVE-2026-58657 — stored CSS injection via Markdown image `resize()` media action (Grav `= 2.0.0-rc.9`).** Prior media hardening rejects direct `?style=` payloads and unsafe `attribute()` fallbacks, but the adjacent `resize()` action writes caller-controlled values straight into `styleAttributes`: `![logo](image.png?resize=100;position:fixed;top:0;left:0;width:100vw;height:100vh;background:white;z-index:9999,200)` renders a full-viewport overlay in the reviewer/admin view — no JavaScript needed. Reusable check: enumerate **every** media-action/parser hook that emits into the same style/attribute sink the sanitizer was written for; the sanitizer covers the named parameter, not the sink. Same sibling-miss family as the @nuxtjs/mdc `xlink:href` gap on the Sept 16 sanitizer-parity page.

Tracked adjacent without promotion: [GHSA-2vcx-h8p2-9pg9](https://github.com/advisories/GHSA-2vcx-h8p2-9pg9) / CVE-2026-59193 — `Installer::unZip()` calls `ZipArchive::extractTo()` with no uncompressed-size/entry-count/depth limits (zip bomb + disk exhaustion, admin-authenticated Direct Install path); availability-only, no new privilege boundary.

## September 17 follow-up: unauthenticated Clockwork profiler history and a sandbox guard that checks the wrong flag (2 GHSAs)

Two Grav records published 2026-09-17T12:32Z extend the debug-surface and sandbox families on this page.

- **[GHSA-q3g2-wjhw-4rmj](https://github.com/advisories/GHSA-q3g2-wjhw-4rmj) / CVE-2026-92916 — unauthenticated Clockwork profiler endpoint leaks sessions, plaintext passwords, and config secrets (Grav 1.7.0–1.7.53.2, 2.0.0–2.0.21, fixed 1.7.53.4 / 2.0.22).** With `system.debugger.enabled: true` (non-default), `InitializeProcessor::handleDebuggerRequest()` intercepts **any path containing** `/__clockwork/` during bootstrap and dispatches to `Debugger::debuggerRequest()` with **no user lookup, no IP restriction, no Clockwork authenticator check**, plus anonymous pagination over the entire stored history. With the shipped `censored: false` default, each stored record contains raw request cookies (including Grav's session cookie — the value *is* the PHP session id, so one read resumes any user's session, admin included), the full parsed request body (login form posts `data[username]`/`data[password]`, stored **plaintext** because Clockwork's password filter only inspects **top-level** keys), and the whole system/plugin config including SMTP credentials, API keys, and licence keys. `Authorization` and `X-API-Token` headers are stored **even when `censored: true`**. On Grav 2, setting `provider: debugbar` is not an avoidance — Grav forces the Clockwork provider for requests preferring a JSON response. Fixes restrict `/__clockwork/` to server-local requests or requests presenting a new `system.debugger.token`.
  - Reusable checks: **profiler/debug history endpoints (Clockwork, Telescope, Debugbar, `/__profiler/`, `/__clockwork/`, `/debugbar/`) are feature-named recon targets — path-substring routing means try `anything/__clockwork/1` if the direct path is filtered.** Test the `Accept: application/json` differential because provider selection can differ by content negotiation. A censoring filter that walks only top-level keys is a key-shape gap, same family as the dot-keyed flag-strip miss above. When triaging any CMS instance, probe the documented debug endpoints even if "non-default" — operators enable debuggers on production far more often than they remember.
- **[GHSA-rv7g-323x-h2q2](https://github.com/advisories/GHSA-rv7g-323x-h2q2) / CVE-2026-92917 — Twig content sandbox fails open for `dump`/`serialize` filters because the guard checks the global flag (Grav 2.0.0-rc.1–2.0.21, fixed 2.0.22).** `GravExtension::assertSandboxDumpSafe()` calls `SandboxExtension::isSandboxed()` **without a `Source` argument**, which returns only the *global* sandbox flag that Grav never enables — so the guard added for GHSA-mc5q-6hpj-rp7j above never executes. A page editor with Twig processing enabled can render `{{ config|print_r }}` and dump the entire merged configuration: `print_r` reflects the real `Config` object held in a **private property** of the `SandboxConfig` facade, bypassing the facade's path redaction — plugin SMTP creds, API tokens, webhook secrets, cache backend passwords. Grav 1.7 is unaffected (it ships no Twig content sandbox at all — an older-version target can be the *easier* sandbox story or the harder one, check per line). Fixed by registering the filters with Twig's `needs_is_sandboxed` flag.
  - Reusable checks: **a sandbox-state guard must be evaluated per-source, not globally — grep any `isSandboxed()`-style call for a missing source/context argument; if the caller-supplied flag defaults to "off", the guard is dead code, and "a guard was added for the previous CVE" is not evidence it runs.** Reflection-style output filters (`print_r`, `var_dump`, `json_encode`, `yaml_encode`) reach an object's private state and therefore bypass *any* facade that censors only its public surface — enumerate every filter/function registered in the sandbox and test each against the config/user objects, exactly the lesson from the Sep 4 `grav.offsetGet` item, now with a second distinct mechanism.

Both proofs are canary-only: a lab Grav with the debugger enabled and fake config secrets, synthetic users/cookies, and a lab page with a marker config key; never harvest real session ids, real request bodies, or real credentials.

## Reviewed but not promoted here

All six remaining Grav records in this wave (the second timing/nonce item, the two duplicate config-secret records, and the Flex Objects shortcode authorization bypass) are covered by the boundary map above and tracked in the source index.
