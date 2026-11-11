---
title: AdminNeo coordinated wave — ATTACH blocklist bypass to web shell, token self-disclosure, nonce-carrying XSS, and the follow-up-fix family
---

# AdminNeo coordinated wave — ATTACH blocklist bypass to web shell, token self-disclosure, nonce-carrying XSS, and the follow-up-fix family

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-11-06 (catch-up over the Oct 28 – Nov 6 gap; eight advisories published 2026-10-30T18:53Z–22:53Z, all fixed in AdminNeo 5.5.1).

AdminNeo is the maintained fork of Adminer — which makes this wave doubly valuable as an operator map, because almost every leg explicitly credits an earlier Adminer advisory it re-introduces or bypasses. **A fork is a snapshot of its upstream's bug history; re-run the upstream's whole advisory corpus against the fork.** Every advisory below links its Adminer predecessor GHSA — collect the pair and diff the fix.

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
| [GHSA-q4f2-39gr-45jh (upstream anchor)](https://github.com/vrana/adminer/security/advisories) | — | — | Adminer predecessor corpus this fork re-inherits |

## The VACUUM INTO leg is the headline: function-neighborhood enumeration beats denylists

The `ATTACH` blocklist (the fix for the 2021 PHP-file-creation advisory) is a one-word denylist on the SQL statement head. SQLite's `VACUUM INTO '<path>'` — available since 3.27.0 — does the same thing (writes an attacker-influenced database file to an arbitrary absolute path with an arbitrary extension) and is not on the list. The published chain, valid for any authenticated SQLite user:

```sql
CREATE TABLE "<?php system($_GET['c']); ?>" (i int);
VACUUM INTO '/var/www/html/shell.php';
```

The table name is attacker-chosen bytes stored verbatim in the file; PHP's parser finds the `<?php` block wherever it sits. This is the same **SQL-write-primitive to web-root** family the wiki tracks (MCP URI-to-SQL, July 10 page; AdminNeo is the cleanest single-request instance of it: no multi-hop, the file *is* the shell).

Operator rules:

1. **Blocklist-of-one → enumerate the function neighborhood.** Whenever a SQL guard denies named statements (`ATTACH`, `LOAD_FILE`, `INTO OUTFILE`), list every other statement/pragma in that engine that writes a file: `VACUUM INTO`, `ATTACH DATABASE`, `DETACH`, `.backup`, FTS virtual-table create with content tables, `readfile()`/`writefile()` CLI helpers, `COPY ... TO PROGRAM`. The guard names the author's mental model; the engine's grammar is the attack surface.
2. **Every file-write primitive needs a co-located injection carrier.** `VACUUM INTO` writes controlled bytes (the schema text) — pair the traversal probe with the byte-carrier probe. The pair (write-where + write-what) is the finding; either alone is a half.
3. **Registry-of-known-shells probe:** on any authorized assessment of a DB admin panel behind SQLite, one request of `CREATE TABLE '<marker>'; VACUUM INTO '<webroot-writable path>'` — bounded to paths the web user owns — settles whether the primitive exists. Fingerprint AdminNeo/Adminer versions from the login page footer.

## The follow-up-fix family: three generations of the same blocklist, all still bypassable

- **ReDoS as a bypass mechanism** (GHSA-p96f-p2p2-2g3h): the hardened matcher `^$space*+ATTACH\b` is itself defeated — not by alternate spelling, but by *catastrophic backtracking* on crafted comment padding, so the guard's verdict becomes computationally unavailable. Third bypass of CVE-2021-43008's lineage in this wave alone. This joins the wiki's incomplete-fix corpus (Sunhillo `%0a/%26` separator re-run, Composer symlinked-bin, Copernik XInclude): **every fix generation of a guard must be fuzzed with its predecessor's full bypass vocabulary plus the new guard's own implementation weaknesses.** A guard that can be made to *hang* is a guard that can be made to *fail open* — test CPU-exhaustion inputs against validation logic, not just against parsers.
- **Two users, one crash** (GHSA-jm85-8cpp-9cjc): the version-check endpoint accepts any POST without origin validation and writes the value to a shared 24-hour cache file; an array-shaped `version[]` poisons the cache so `rawurlencode()` throws and every UI request 500s for a day. Durable axis: **client-callback endpoints that write shared server state are unauthenticated state-mutation surfaces** — probe type confusion (array vs scalar) on any endpoint whose caller is "the product's own JS."
- **CSRF token = key + key** (GHSA-wm25-49w3-5qrg): the token is `(rand XOR secret):rand` — both operands transmitted; the secret is recoverable from a single observation, and `rand(1,1e6)` is ~20 bits of entropy with loose `==` comparison on top. When a scheme publishes its own masking arithmetic in the token format, the token is the key. Probe: capture one token from your own session, XOR, confirm the recovered value forges tokens for a second disposable session; sweep for `rand(`-style session entropy in PHP admin tools generally.

## Nonce-carrying XSS and forwarded-header cookie theft

- **Rogue-server version string into a nonce'd script tag** (GHSA-rx7m-wxwq-vxr9): `Connection::get()->getVersion()` is interpolated raw into `script(...)` — which emits `<script nonce="VALID">`. The rogue MySQL server (an 80-line Python fake that accepts any login and returns a crafted version string) therefore executes inside a CSP the page itself considers trustworthy. Two durable rules: (1) **DB-server version strings are attacker-controlled input** wherever the client renders them — probe from a rogue server, not just from the UI; this is the server-side twin of header-injection-into-JS-context. (2) **A valid nonce does not sanitize the content** — CSP nonces gate *who* executes, never *what*; any sink that interpolates data inside a nonce'd tag inherits the nonce. Grep template helpers (`script(`, `nonce`) for raw interpolation of peer-supplied strings.
- **`X-Forwarded-Prefix` → `Set-Cookie` attribute injection** (GHSA-79wv-8rh2-9vp2): the header is concatenated into `REQUEST_URI` unvalidated, then the manually-built cookie header echoes it; semicolons inject `Domain=`, `Path=`, `Secure=`, `SameSite=` attributes, scoping `neo_sid` and the DB-password-encryption key cookie to an attacker domain. This is the forged-original-URI header family (Anubis `X-Original-URI`, Sept 15; NGINX ingress relay, Oct 14) with a **persistence twist: the injected header is not just trusted for this request — it is baked into stored cookie state.** Battery addition: on any app that echoes `X-Forwarded-*` into response headers, fuzz for semicolon/CR-LF and check whether the effect survives the request (cookie jar diff before/after).

## Arbitrary unlink via the un-guarded verb

GHSA-6vfx-w7q3-42gq: SQLite create/rename validate extensions (`check_sqlite_name()`); the drop path passes `db[]` straight to `unlink()`. Same validation-vs-verb parity drift the wiki scores repeatedly (Fission archive CRUD, Budibase storage): **enumerate every destructive verb on the same resource and diff each one's guard set against the write verb's.** Probe: authenticated drop request with a relative path to a canary file outside the database directory.

## Fork-inheritance sweep procedure

1. Identify the fork (AdminNeo of Adminer; any maintained fork in scope) and pull the upstream's full security-advisory list.
2. For each upstream advisory, check whether the fork's snapshot predates the fix, and whether the fork later inherited a *partial* fix (version-diff the guard functions).
3. Re-run the upstream PoCs against current fork HEAD — this wave shows the fork can reintroduce fixed bugs *and* carry unfixed bypasses of fixes it did inherit.
4. Report with both advisory links; the fork-vs-upstream diff is the evidence spine.

Validation boundary: lab instances only, disposable SQLite/MySQL backends, a rogue MySQL server bound to your own listener, marker files in directories the lab web user owns; never test shell-write primitives against third-party hosts, and redact any real credentials observed in cookie-theft proofs.

Sources: the eight advisory links above; Adminer upstream advisories at <https://github.com/vrana/adminer/security/advisories>; upstream VACUUM INTO precedent GHSA-gmx3-g29w-77wf.
