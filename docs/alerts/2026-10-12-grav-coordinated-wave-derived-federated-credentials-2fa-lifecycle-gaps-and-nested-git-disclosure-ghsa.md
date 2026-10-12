# Grav coordinated wave: derived federated credentials, 2FA lifecycle gaps, profiler-token exposure, and nested-git disclosure

Source: GitHub Security Advisories published 2026-10-12 18:31Z (Grav core `2.0.22–2.1.6`, Login plugin `1.2.0–3.9.8`, Login OAuth `<1.4.3`, API plugin `<1.0.36`, Git Sync `1.0.2–3.4.12`, Data Manager `1.4.0–1.4.5`, Guestbook/Star Ratings/Reset Route singles).

**Why this is worth an operator page.** Grav is a flat-file CMS that ships everywhere PHP flat-file hosting lives — marketing sites, intranets, documentation portals — and its plugin ecosystem is where the boundaries actually break. This wave clusters three durable axes: **provisioning flows that mint real, derivable passwords from public identifiers**, **MFA enforced at the login screen but not at the state-change handlers behind it**, and **debugger/profiler/git surfaces that leak config to roles that "shouldn't care."** Several legs are directly replayable bug-bounty patterns.

## Boundary map

| GHSA / CVE | Surface | Boundary crossed |
| --- | --- | --- |
| [GHSA-9qx4-jr52-5c2w](https://github.com/advisories/GHSA-9qx4-jr52-5c2w) / CVE-2026-109321 (critical) | Login OAuth plugin | Federated account provisioned as normal user: username `<provider>.<id>`, password = **unsalted MD5 of the provider identifier**, password login left enabled → unauthenticated login = full admin takeover |
| [GHSA-mp6q-9gmf-c5j2](https://github.com/advisories/GHSA-mp6q-9gmf-c5j2) / CVE-2026-109313 | Login plugin remember-me | Password-only attacker obtains persistent remember-me cookie after step 1, restores it as a **fully authorized post-2FA session** |
| [GHSA-m37v-wpv7-2x4p](https://github.com/advisories/GHSA-m37v-wpv7-2x4p) / CVE-2026-109312 | Login plugin `processUserProfile()` | Pending-2FA session can invoke `update_user` (`update_user` reachable from any published page form without an access rule) and **set `twofa_enabled` off before completing the factor** |
| [GHSA-7cwq-9cr7-g8jf](https://github.com/advisories/GHSA-7cwq-9cr7-g8jf) / CVE-2026-109314 | Login plugin reset route | Publisher can **author a page that shadows the password-reset route**; when the victim opens the emailed reset link, `Login::getPage()` renders the page **with the username + bearer reset token in scope** |
| [GHSA-pm6p-v8qr-5mmg](https://github.com/advisories/GHSA-pm6p-v8qr-5mmg) / CVE-2026-109325 | Clockwork profiler | Profiler trusts **loopback `REMOTE_ADDR`**; anyone behind a same-host HTTP proxy reads profiler records: system/plugin config, secrets, request metadata, queries |
| [GHSA-r6g3-r4xj-3p43](https://github.com/advisories/GHSA-r6g3-r4xj-3p43) / CVE-2026-109315 | Clockwork token vs editor sandbox | Redaction list omits `system.debugger.token` — **page editor renders the token through editor-authored Twig**, then reads profiler records with `X-Clockwork-Auth` (chains with the row above when a proxy is in front) |
| [GHSA-7mh9-rw55-r7vq](https://github.com/advisories/GHSA-7mh9-rw55-r7vq) / CVE-2026-109326 | Bundled nginx/lighttpd/IIS/Caddy configs | `.git` blocked **only at document root**; nested repos such as `/user/.git` serve config, refs, objects — reconstruct unpublished history and committed secrets |
| [GHSA-cp28-795p-j89g](https://github.com/advisories/GHSA-cp28-795p-j89g) / CVE-2026-109318 | Git Sync `gravuser`/`gravfull` author mode | Editor-controlled username/full-name/email reach `git commit --author` → **shell substitution → PHP `exec()` as web-server user** |
| [GHSA-wcc2-xcpr-vc5h](https://github.com/advisories/GHSA-wcc2-xcpr-vc5h) / CVE-2026-109320 | API plugin `SessionAuthenticator` | **Disabled accounts keep API access** via already-authorized browser or remember-me session until expiry — deactivation ≠ revocation |
| [GHSA-7ghm-8q85-6h4j](https://github.com/advisories/GHSA-7ghm-8q85-6h4j) / CVE-2026-109317 | API plugin access maps | `api.users.write` holder edits account access maps/invitations with **positive scalar `admin`/`api` parent grants** → inheriting resolver satisfies `requireSuper` |
| [GHSA-43jm-rfw2-wchv](https://github.com/advisories/GHSA-43jm-rfw2-wchv) / CVE-2026-109316 | Data Manager plugin | Missing authorization on record CRUD (low-priv read/write of CMS data) |
| [GHSA-6xrw-24fx-4qcf](https://github.com/advisories/GHSA-6xrw-24fx-4qcf), [GHSA-44rc-569f-hxfg](https://github.com/advisories/GHSA-44rc-569f-hxfg), [GHSA-pwp7-4hgc-rjhr](https://github.com/advisories/GHSA-pwp7-4hgc-rjhr) / CVE-2026-109319/-109322/-109323 | Guestbook / Star Ratings | Missing authorization + CSRF + stored XSS in comment plugins (known WP-style comment classes, recorded for inventory) |

## Derived federated credentials (the critical leg)

The Login OAuth plugin provisions every OAuth login as an **ordinary Grav user account** with:

1. username = `<provider>.<id>` (deterministic from the provider identifier — Google subject, GitHub login, etc.), and
2. password = **unsalted MD5 of the provider identifier**, and
3. **password authentication left enabled** on that account.

Anyone who learns or guesses a privileged user's provider identifier (public GitHub profile, email-derived subject, a leaked ID in page metadata) can compute both halves of the credential and log in with a password — including admin accounts. The federation path is a credential *factory*, not a replacement.

Operator pattern that generalizes beyond Grav — **audit every federated/SSO provisioning flow for whether it also creates a password-backed account**:

- Does provisioning write a user record with a password hash? If yes, what is the preimage? Provider IDs are usually public or low-entropy.
- Is local password login disabled on federated accounts? Test: attempt `POST` login as `<provider>.<id>` with `md5(<provider-id>)` on a disposable account you provisioned in a lab IdP you control.
- Sweep alternate usernames: the deterministic scheme itself (`github.someuser`, `google.10812345`) is a username-enumeration oracle when login errors differ.

## 2FA enforced at the door, not in the house

Two legs share one rule: **the second factor gates the login transition, but not the session state behind it.**

- Remember-me cookie restoration after the password step yields a session treated as fully 2FA-complete (GHSA-mp6q-9gmf-c5j2). A stolen or brute-forced password plus one cookie = bypass.
- A **pending** 2FA session (password verified, factor outstanding) can already reach `update_user` from any page form and clear `twofa_enabled` (GHSA-m37v-wpv7-2x4p).

Replayable check on any CMS/IdP with MFA: enumerate what the *pre-factor* session can do. The decision battery: can it read profile? update profile? change password/email? invoke plugin actions? A pending session should be a zero-capability placeholder; any writable verb reachable pre-factor is the bypass. Pair it with the cookie/lifecycle battery: capture every credential issued at each login step and replay them independently (the same rule that caught Joomla's pre-MFA `rememberme` cookie on 2026-10-06).

## Route-shadowing leaks reset tokens

Login's `getPage()` fallback renders **whatever page an editor authored at the reset route** when the reset flow serves that URL — so a publisher (low-trust content role) plants a page there, waits for a victim to open the emailed link, and harvests `username` + bearer reset token from the render context (GHSA-7cwq-9cr7-g8jf).

Durable axis: **route namespaces are shared between the app's auth flow and user-authored content.** For any app with page-author roles, enumerate auth-family routes (login, reset, oauth callback, device approval, magic-link) and test whether a user-authored page/template can shadow or render alongside them. The sink is render-time variable scope leaking flow parameters into page-visible markup.

## Debugger and profiler as config-reading surfaces

Clockwork-style profilers are a recurring second-order boundary:

- Trusting `REMOTE_ADDR` loopback for the profiler UI means **any same-host proxy (SSRF included) is "local"** — combine with any request-forwarding bug to read recorded config/secrets (GHSA-pm6p-v8qr-5mmg). Loopback-decision-table rule applies: probe with loopback-shaped origins before assuming the profiler is unreachable.
- The sandbox redaction list omitted the debugger's own token key, so a Twig-capable editor role **renders the key that unlocks the profiler API** (GHSA-r6g3-r4xj-3p43). Redaction lists are deny-lists of *names*; enumerate the config tree for keys the list never mentions (`config.get()` style probes in any sandboxed template engine, then diff what renders).

## Nested-git disclosure via root-only deny rules

Bundled web-server configs deny `.git` at the document root only; flat-file CMS layouts keep **nested repositories** (e.g. `user/.git` under Grav) deeper in the tree, fully servable (GHSA-7mh9-rw55-r7vq). Standing recon step for flat-file/static hosts: probe `/user/.git/config`, `/user/.git/HEAD`, `/backup/.git/refs` and siblings — not just `/.git/`. Committed secrets and unpublished content reconstruct from refs/objects.

## Editor-to-shell via VCS metadata (Git Sync)

When Git Sync runs in `gravuser`/`gravfull` author mode, the commit `--author` string carries editor-controlled username/name/email into a shell-backed `exec()`; `$(...)`/backtick substitutions in the profile execute as the web-server user (GHSA-cp28-795p-j89g). Generalized rule already on this wiki (metadata-to-command class): **identity strings that reach a command line are command injection points** — test with inert `$(touch marker)` markers in every author/committer/label field of any UI-driven VCS automation.

## Revocation and privilege-resolution drift

- **Disabled ≠ revoked**: the API plugin's `SessionAuthenticator` never re-checks account state, so disabled users keep calling API endpoints on existing sessions/remember-me cookies (GHSA-wcc2-xcpr-vc5h). Add "disable account → replay every transport" (web, API, WS, remember-me, CLI token) to the revocation battery — the same artifact×path matrix that caught Vikunja's webhook leak.
- **Scalar parent grants satisfy `requireSuper`**: a delegated user-manager (`api.users.write`) writes positive scalar `admin`/`api` grants into access maps the inheriting resolver treats as super-equivalent (GHSA-7ghm-8q85-6h4j). When a permission model supports inheritance, test the *shape* of grant values (scalar vs map, true vs list), not just the role labels.

## Validation boundaries

- Lab Grav install with disposable users at each tier (admin, editor, publisher, user-manager, disabled user) plus a lab OAuth provider you control.
- OAuth derived-credential proof: provision your own lab account, compute `md5(provider_id)`, log in over the password form; stop at session confirmation.
- Pending-2FA capability sweep: enumerate reachable actions on a password-verified, factor-outstanding session against marker-only endpoints; never modify a real account.
- Nested-git probe is unauthenticated read of `.git/config`/`HEAD` only — no object-stream dumping of real content beyond what confirms exposure.
- Git Sync injection: inert marker substitution in a lab profile field; never run commands on production hosts.
- Keep tokens, cookies, reset links, and profiler config values out of the wiki and out of reports.

## October 12 18:3xZ wave — remainder tracked without publication

- **MarkLogic Server ~16-leg review dump** (CVE-2026-85957–85976): XXE-on-by-default across server paths + SAML-parser XXE on 11.x + cleartext transport + Azure-deployment leg. Detail-free vendor mirrors; XXE/transport classes already covered on the May 4 XML/XXE lineage — revisit on vendor-bulletin detail.
- **SurrealDB third wave** (10 legs) folded on the June 19 SurrealDB page — same product, third sweep.
- **ZITADEL four-leg wave** folded on the Sept 16 IdP authority page.
- **LibreNMS pair** (LDAP filter-injection wildcard admin + array-param SQLi to password-hash read) folded on the Sept 7 page.
- **MONAI pair**: SENet pretrained weights fetched over **plaintext HTTP** and `load_state_dict_from_url` unpickled without `weights_only=True` (on-path RCE), plus `nnUNetV2Runner` unpickling a path read from `inference_information.json` without containment. Model-supply-chain/pickle classes already on the AI pages; watch for KEV.
- **ExLlamaV3** model-supplied CUDA kernel index → out-of-bounds function-pointer dispatch at model load: crash proven, controlled dispatch speculative — tracked under the June 30 model-parser page lineage.
- **OpenShift console** Helm-chart URL SSRF from any authenticated console user (blind port-scan + error disclosure): SSRF class covered; tracked.
- **Quarkus REST Data Panache** unvalidated `sort` on generated endpoints (info-disclosure/DoS): ordering-side-channel class covered on the ORM/query-grammar pages.
- **Adminer BOM-prefix ATTACH/VACUUM INTO bypass** folded on the Aug 25 Adminer page.
- **better-auth device-approval UI omission** folded on the June 4 Better Auth page.
- **Open WebUI 0.11.4 wave** (terminal WS revocation gap, disabled-backend index, tools/export source disclosure) folded on the May 16 Open WebUI authz page.
- **Network-AI ClaudeHookBridge deny-pattern first-field bypass + dashboard CSWSH** folded on the June 19 developer-control page.
- **SiYuan** plugin-handler absolute-path read + Sprig function-map OOM folded on the July 10 SiYuan page.
- Edimax BR-6208AC detail-free quartet, Semtech LR11xx SPI OOB, WP singles (WP-Members, Forminator, Patreon CSRF pair, Booktics, Salevo, VillaTheme), Zebra gossip/DoS pack, Contrast coordinator legs, Grav remainder, DOMPurify 3.4.16 pair (mutable-config class covered), vLLM PyAV audio fallback (media-pipeline class), Craft DOM XSS — known classes or detail-free.
