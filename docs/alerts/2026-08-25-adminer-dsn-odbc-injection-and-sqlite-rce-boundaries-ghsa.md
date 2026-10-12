# Adminer DSN/ODBC injection, SQLite RCE, and admin-panel CSRF boundaries

Source: GitHub Security Advisories `unreviewed` feed, 2026-08-25 (all first published 2026-08-25): [GHSA-34q8-53jm-qc2r](https://github.com/advisories/GHSA-34q8-53jm-qc2r) (unauthenticated PDO DSN/ODBC `TraceFile` RCE, critical 9.8), [GHSA-j4fh-9p52-f987](https://github.com/advisories/GHSA-j4fh-9p52-f987) (authenticated SQLite `VACUUM INTO` RCE, high 7.2), [GHSA-vfp8-hfj6-qmr2](https://github.com/advisories/GHSA-vfp8-hfj6-qmr2) (SQLite database-list arbitrary file deletion, high 8.1), [GHSA-wjcm-7h7g-36vh](https://github.com/advisories/GHSA-wjcm-7h7g-36vh) (CSRF token XOR + low-entropy + loose compare, medium 6.8), [GHSA-gx46-wch5-wp5p](https://github.com/advisories/GHSA-gx46-wch5-wp5p) (rogue-MySQL version-string script-tag break-out, medium 6.1), and [GHSA-fh9x-8h7v-rwhv](https://github.com/advisories/GHSA-fh9x-8h7v-rwhv) (`X-Forwarded-Prefix` trust confusion, medium 4.7). All affect Adminer before `5.4.3` (the CSRF/session items also note a `5.5.0` line for the prefix item).

Adminer is a single-file, frequently internet-facing database admin panel, which makes it a recurring recon target. This wave is durable because it chains several reusable admin-panel boundaries: an unauthenticated `server` field crossing into a PDO/ODBC DSN, a query-language feature (`VACUUM INTO`) not being blocked despite a sibling restriction, a file-delete sink trusting a caller-supplied path, and a client-supplied `X-Forwarded-Prefix` being trusted for redirects and cookie paths. The DSN-to-trace-file primitive and the "restricted one operation but not its sibling" pattern generalize to any DB admin tool or DB-backed application that builds driver strings from user input.

!!! warning "Canaries only"
    Run these checks in a disposable Adminer instance with fake credentials and a scratch web root. Use marker files and a denied execution/file-write sink. Never write a real PHP file to a live web root, delete real files, exfiltrate real database contents, or run arbitrary SQL against production data.

## Boundary map

| Surface | Caller-controlled value | Privileged transition | Safe positive |
| --- | --- | --- | --- |
| DB connect `server` field | ODBC params via `;` (`TraceFile`, `TraceOn`) | unauthenticated DSN injection writes a trace file | DSN is sanitized; no `TraceFile` parameter reaches the driver |
| SQLite query | `VACUUM INTO '<path>'` | authenticated query writes a file to an arbitrary path | `VACUUM INTO` is blocked the way `ATTACH` is |
| SQLite db list drop | `db[]` relative path with `..` | drop action deletes an arbitrary writable file | extension/path validated to the media/data root |
| CSRF token | observed `mask:masked` token | one XOR recovers the session secret; loose `==` allows type juggling | token not split-publishable; `hash_equals` compare; high-entropy rand |
| DB server version | crafted MySQL version string | inserted into a CSP-nonce `<script>`, breaks out of JS context | version string escaped/validated before embedding |
| `X-Forwarded-Prefix` | absolute URL | prepended to `REQUEST_URI` for redirects + cookie path | trusted-proxy check; no client prefix honored |

## Unauthenticated DSN/ODBC `TraceFile` injection

The highest-impact item: Adminer builds a PDO DSN from the `server` field without sanitizing, and ODBC-flavored DSNs accept `;`-separated driver parameters. An attacker can inject `TraceFile=<web-root>/canary.php` and `TraceOn=1`, so the driver writes a trace (including PHP) to a web-accessible path.

1. Stand up a disposable Adminer instance pointed at a fake ODBC/MySQL backend in a lab, with a scratch, world-writable web root.
2. Submit a connect form whose `server` field carries `;TraceFile=<marker>.txt;TraceOn=1` (use a non-executable extension first to prove the write without claiming execution).
3. Record whether the marker file appears in the web root and what the DSN string looked like.

| Input class | Expected secure result |
| --- | --- |
| ordinary host:port | clean DSN, no extra driver params |
| `;TraceFile=...;TraceOn=1` | rejected or parameters stripped before the driver |

A bounded positive is the marker file being created in the scratch web root from an unauthenticated connect. Report the DSN-injection-to-trace-write primitive. Do **not** write an executable `.php` to a live host or execute it; the write primitive is the finding, execution is inferred only if separately authorized and proven.

## SQLite `VACUUM INTO` vs `ATTACH` (restricted-sibling gap)

Adminer blocks `ATTACH` but not `VACUUM INTO`, which also writes a file. This is the classic "one sibling operation restricted, its twin not" gap.

1. In a disposable Adminer + SQLite setup, run an ordinary `VACUUM` to confirm the baseline.
2. Run `VACUUM INTO '<scratch-root>/canary.db'` and record whether the write succeeds to a path the operator chose.
3. Compare against `ATTACH` to show the asymmetric restriction.

A positive is the file being written to the attacker-chosen path under an authenticated session. Report the missing block with the exact query; prove only with a marker inside the scratch root.

## SQLite database-list file deletion

The drop action for a SQLite database trusts the `db[]` path. Supply a relative path with `../` segments and record whether `unlink()` removes a file outside the data root. Use a sibling marker file in the scratch root; never target real config or data. A positive is the marker being deleted from outside the intended directory.

## Admin-panel CSRF: token split-publish + weak compare

Three compounding weaknesses make the CSRF control effectively forgeable:

- The token is sent as `rand XOR secret : rand`; observing one token (sniff, log, `Referrer`, XSS) lets an attacker XOR once to recover the secret and mint unlimited valid tokens.
- `rand(1, 1e6)` is ~20 bits — brute-forable blind.
- Verification uses loose `==`, enabling PHP type juggling.

Check each edge in a lab: capture a single token, recover the secret, and forge; test `==` with a juggling candidate. Report the token-design flaw and the weak compare; do not forge a real admin action against a live deployment.

## Rogue-MySQL version-string script break-out

Adminer inserts the database server's version string into a CSP-nonce `<script>`. A rogue MySQL server (an attacker-controlled backend) can return a version string that breaks out of the JS context. Test with a fake backend returning a crafted version string and record whether the embedded string escapes the script context; do not load real payloads on a live panel.

## `X-Forwarded-Prefix` trust confusion

Adminer prepends the client-supplied `X-Forwarded-Prefix` to `REQUEST_URI` with no trusted-proxy check. Supply an absolute URL and record its flow into `Location`, `Set-Cookie` path, and self-links. A positive is an unauthenticated attacker controlling the cookie path and redirect target; note that CR/LF is not injectable, so this is open-redirect/cookie-path confusion, not header splitting or XSS.

## Reporting heuristics

- Frame the unauthenticated DSN item as "Adminer `server` field builds an unsanitized ODBC DSN; `TraceFile` writes to the web root," with the connect request and the marker-file evidence.
- Keep the SQLite RCE and file-delete items explicitly authenticated and scoped to the query/drop sink, so they are not conflated with the unauthenticated DSN path.
- For the CSRF and prefix items, cite the specific weakness (XOR-recoverable token, low-entropy rand, loose `==`, untrusted prefix) and the affected routes.
- Cite the version bounds (`< 5.4.3`; the prefix note references a `5.5.0` line).

## Safety

- Authorized, in-scope targets only; Adminer panels are commonly exposed and often front real databases.
- Fake credentials and a scratch web root; marker files only, never real config/data.
- No executable writes, no real file deletion, no real SQL execution, no exfiltration of live database contents.
- Do not run forged CSRF actions or execute a written trace file on production hosts.

## Reviewed but not promoted here

No separate items in this Adminer wave exceed the boundaries above; all six are covered.

## October 12 follow-up: UTF-8 BOM prefix defeats the ATTACH/VACUUM INTO blocklist → authenticated SQLite RCE ([GHSA-q48c-r4q8-5c57](https://github.com/advisories/GHSA-q48c-r4q8-5c57)/CVE-2026-109347, high, Adminer < 6.1.1)

The August page's `VACUUM INTO`-vs-`ATTACH` sibling-gap now has its mirror: Adminer blocks those statements by **statement-prefix matching**, and a leading **UTF-8 byte-order mark (EF BB BF)** slips past the matcher while SQLite still parses and executes `ATTACH`/`VACUUM INTO`. Authenticated SQLite users attach a database file at a PHP-served path and create a table whose *name* is PHP code — executed as the web-server user.

Sharpened rules for this page's standing axis:

- **Blocklists that match the first token of a statement have an invisible-character shadow grammar**: BOM, leading whitespace forms, comments (`/*x*/ATTACH`), and encoding-prefix variants all deserve a spot in the differential battery. Test byte-level prefixes (raw `\xEF\xBB\xBF`, UTF-16 BOM, NBSP) before concluding a statement-class block is airtight.
- The sink shifted from "write a file to a path" to "write a file whose *name* is code at a PHP-served path" — in DB admin panels, object *names* (table, index, function) are file paths or markup on some engines; enumerate naming sinks, not just COPY/OUT/INTO verbs.
- Proof stays lab-bounded per this page's safety section: disposable Adminer + scratch web root + a table named with a harmless `phpinfo()`-free marker statement; never write runnable files to live hosts.
