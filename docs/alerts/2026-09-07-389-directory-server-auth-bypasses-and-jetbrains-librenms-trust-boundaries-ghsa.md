# 389 Directory Server auth-boundary cluster, plus JetBrains, LibreNMS, and MISP trust boundaries (12 GHSAs, Sept 7 wave)

**Why this is worth an operator page.** The 2026-09-07 unreviewed advisory wave is dominated by one product — **389 Directory Server** — and four of its five findings share a single durable theme: *identity state that outlives the credential that set it, and string fields that cross trust boundaries unescaped*. 389 DS is a default LDAP backend for RHEL, FreeIPA, and countless internal PKI/SSO stacks, so these boundaries recur on every engagement that touches enterprise directory services. Alongside it: a **JetBrains** cluster (YouTrack Helpdesk self-asserted email ATO, Hub unauth trusted-service superuser, cross-tenant token cache), a **LibreNMS** pair (numeric-token type-coercion auth bypass + `graph_title` argument injection), and a **MISP** feed-redirect SSRF that forwards configured feed credentials across redirect hosts.

## 389 Directory Server — SASL PLAIN stale-identity crossbind (CVE-2026-18922, GHSA-pr87-24g5-hphv)

Critical, CVSS 9.8, unauthenticated. During SASL PLAIN authentication, a **stale identity carried in a Cyrus SASL auxiliary property from a prior failed bind can be installed on the connection following a subsequent, unrelated successful bind** — regardless of which SASL mechanism completes the second bind. Documented attack shape:

1. `SASL PLAIN` bind as `cn=Directory Manager` with an **incorrect password** (failed, but the DN lingers in the SASL aux property on the connection).
2. Complete a `SASL ANONYMOUS` bind on the **same connection**.
3. The server grants **Directory Manager authority with no valid credentials**.

A variant replaces step 2 with a *valid low-privileged account's* own successful bind — same result, escalated identity.

Durable operator pattern: **connection-scoped SASL state is not reset across mechanisms.** Auth state that should be per-bind is actually per-connection, so a failed high-priv bind primes a later low-priv/anonymous bind on the same socket. This is a reusable audit question for any SASL/SSO stack:

- *Does a failed bind as an admin DN leave residue (aux properties, cached identities, context objects) that a later different-mechanism bind inherits?*
- Prove with two binds on one connection: fail a Directory Manager PLAIN, then anonymous (or a low-priv account) bind, and check the effective identity of the second. Stop at identity confirmation — do not read directory contents.

## 389 DS — Cockpit 389 Console DN → shell RCE (CVE-2026-19843, GHSA-p34m-7cj2-q64p)

High, CVSS 8.4. The Cockpit 389 Console LDAP editor builds an `ldapsearch` command by **embedding the entry's DN into a shell command string without escaping**. An LDAP user with delegated create/rename rights can craft a DN containing shell metacharacters; when a **Cockpit administrator** later views the entry, the embedded command executes **as root on the directory server host**.

Durable pattern: **low-priv write → admin-read code execution.** The attacker never needs shell access; they only need to write a directory object that a *more-privileged UI consumer* later interpolates into a shell command. Reusable audit checklist for any admin console with a directory/file browser:

- Which objects can a low-priv user create/rename with attacker-controlled names (DNs, filenames, display names)?
- Does any privileged consumer (admin UI, cron, report generator) interpolate those names into shell, SQL, or query strings?
- Prove with a marker DN containing inert metacharacters and confirm escaping at the sink boundary in the lab; do not execute commands on a live server.

## 389 DS — SELFDN ACI empty-DN match (CVE-2026-76560, GHSA-g4xg-g9jg-549h)

High, CVSS 7.5. The SELFDN ACI bind-rule evaluator incorrectly matches an anonymous client's **empty bind DN against an empty stored attribute value**, letting an unauthenticated client satisfy access-control rules that were intended to require a matching authenticated identity. Consequence: anonymous add/modify of entries under SELFDN-protected ACIs.

Durable pattern: **empty-string equivalence at authorization decision points.** Whenever an authorization check is `user_dn == attribute_value`, an empty/missing attribute or an anonymous (empty) bind DN can satisfy it. Reusable audit heuristic: for every equality-based ACI/ACL, enumerate the case where one side is the empty string.

## 389 DS — SASL I/O layer unsigned underflow (CVE-2026-18355, GHSA-r5vv-79fp-2427)

High, CVSS 7.5. In `sasl_io_start_packet()`, the wrapped-record length from the wire is validated only against an **upper bound**. A tiny wire length (0–2) makes `encrypted_buffer_count` fall below the already-consumed `encrypted_buffer_offset`, and the subsequent subtraction in `sasl_io_read_packet()` underflows the unsigned counter — `PR_Recv` then requests ~4 GiB into a 1024-byte heap buffer. Requires a completed SASL bind with integrity protection (SSF > 0); DoS with potential RCE. Distinct from CVE-2026-11774, whose fix guarded only the upper-bound overflow.

Durable pattern: **bounds checks that validate one direction only.** If a parser validates `len <= MAX`, also confirm the downstream arithmetic assumes `len >= consumed`. Underflow-after-validated-overflow is a recurring C-library bug class; it pairs naturally with the stale-identity finding above when scoping 389 DS in an engagement.

## JetBrains — unauth trusted-service superuser + Helpdesk self-asserted email ATO (3 GHSAs)

Three high-value trust-boundary breaks in the JetBrains product family:

- **Hub — unauth trusted-service registration (CVE-2026-86480, GHSA-3hfh-j9g4-36r5, 9.8).** An unauthenticated attacker can register a *trusted service* and gain superuser privileges. Durable pattern: the trusted-service registration endpoint does not authenticate the registrant — "who may register a trusted principal" is an authorization question, not an assumption.
- **YouTrack Helpdesk — self-asserted email ATO (CVE-2026-86478, GHSA-w44j-qc22-m82h, 9.8).** Unauthenticated account takeover via a self-asserted email address: identity is claimed by the caller rather than proven by a verifier. Reusable audit heuristic for any support/Helpdesk flow: *which fields are caller-asserted identity vs. verifier-proven identity?*
- **YouTrack — cross-tenant GitHub App token cache (CVE-2026-86492, GHSA-p8f6-44xp-3cp8, 8.5).** A shared token cache allowed cross-tenant theft of GitHub App installation tokens. Reusable pattern: **cache keys that omit the tenant/principal field** — the same class as the 389 stale-identity bug (state outlives its scope).

Secondary YouTrack items in the same wave (tracked, lower value): iP spoofing via HTTP headers to forge Bitbucket webhooks (CVE-2026-86485), and the generic VCS webhook handler **failing open when its secret is blank** (CVE-2026-86486) — the "blank credential disables the check" pattern.

## LibreNMS — numeric token type-coercion auth bypass + graph_title argument injection (CVE-2026-86426 + CVE-2026-86427)

Critical. The REST API token check is vulnerable to **MySQL type coercion**: sending a small integer (0–9) instead of a string token matches token hashes, bypassing authentication on protected endpoints. Reach extends to device credentials and admin features, and RCE is possible through alert templates. Fixed in 26.8.0.

Durable pattern: **string-vs-numeric type confusion at credential-comparison sinks.** When an API parameter is meant to be a string token but the database or ORM accepts a numeric literal, `0`/small-int inputs probe the coercion path. Reusable heuristic: for every token/secret comparison, test the numeric input class and check whether the comparison happens in a typed context (DB column, ORM filter) rather than string equality.

Second LibreNMS finding in the same wave (GHSA-j7jc-m6xg-rrcw / CVE-2026-86427, high): `graph_title` **argument injection** — the value is interpolated into an `rrdtool` command with only double-quote escaping, so an authenticated attacker breaks out to inject arbitrary `DEF`/`LINE` arguments (reading RRD files from unauthorized devices) or uses newline injection to execute arbitrary rrdtool commands, bypassing per-device authorization. Durable pattern: **per-device authorization is only as strong as the tool-invocation layer** — when a UI field becomes arguments to an external tool (`rrdtool`, `awk`, `find`, …), the quote-escaping is the real control.

## MISP — feed-redirect SSRF with credential forwarding (CVE-2026-86419, GHSA-qp9m-r348-236g)

High. MISP's feed retrieval follows redirects **without validating the redirect scheme or destination**, and reuses the original request headers across redirect hops — so API credentials configured for a feed are forwarded to an attacker-influenced redirect host, and redirects can reach internal network resources (SSRF). The TAXII discovery path had a weaker companion issue: its `gethostbyname()`-based check only compared against a few literal addresses, missing `::1`, numeric encodings (`0x7f000001`), and multi-record DNS.

Durable pattern: **credentials travel with redirects until you explicitly strip them.** For any product that does server-side outbound fetches with configured auth (feeds, webhooks, integrations), the audit questions are: what happens to auth headers on a cross-host redirect? Is DNS re-resolved after validation (TOCTOU)? Reusable probe: an owned HTTP peer returning a 302 to a second owned peer; observe which headers arrive at the second hop. Also note the sibling MISP finding (CVE-2026-86452, unauth pre-auth reset-path persistence with no bounds/rate-limit) — tracked, lower operator value.

## September 17 follow-up: Overmind statistics legend innerHTML stored XSS (GHSA-rfmv-f8jw-7mhw)

MISP's Overmind theme statistics views built donut-chart legend labels by concatenating user-controllable object names / category keys directly into an `innerHTML` string in `event_general.ctp` and `preview_general.ctp` — no HTML-encoding. Any authenticated user able to create or rename an object (attribute names, event names, server/feed identifiers) plants markup that fires as live HTML/JS in every viewer's browser on the dashboard (session hijack, actions-as-victim). Deterministic, no race.

Durable pattern extension of the same page's dashboard-render class: **aggregate/legend/chart label renderers are the most-missed escaping sink in admin UIs** — the data path is "name field → label string → innerHTML" and it rarely appears in XSS audits that focus on detail views. Audit sweep: grep dashboard/statistics templates for string concatenation into `innerHTML`/`dangerouslySetInnerHTML` fed from rename-able entities, and prove with a renamed object carrying a harmless marker (`<svg onload=...>` on your own lab account), never against shared instances.

New page companion for the same Sept 17 MISP wave: the events/contact → CakePHP `argv` path-switch + `phar://` unauthenticated RCE is covered on the [Sept 17 argv/phar boundary page](2026-09-17-misp-cakephp-argv-phar-rce-sap-cds-mtxs-tenant-credentials-and-android-exported-activity-file-write-ghsa.md).

## Durable operator value

1. **State that outlives its scope is the unifying bug class of this wave.** Stale SASL identity, cross-tenant token cache, and blank-secret fail-open all share one root: an identity/credential/context object persists past the lifetime that should bound it. Audit question: *what state survives a bind/session/tenant boundary, and who can reach it next?*
2. **One-directional bounds checks (upper-only) leave underflow open** in C-network libraries; 389 DS's SASL I/O layer is a textbook example.
3. **Low-priv write → high-priv read is the RCE enabler pattern** (Cockpit DN → root shell). Find the low-priv write surface first; the admin consumer is the sink.
4. **Empty-string and numeric-input equivalence** at auth decision points (SELFDN empty DN, MySQL numeric coercion) are cheap, high-yield differential tests.
5. **Self-asserted vs verifier-proven identity** is a recurring ATO axis in Helpdesk/support flows (YouTrack, and historically reset-link origin trust).

## Safety

- **Authorized scope / lab only.** All of these are network-reachable auth boundaries; treat any successful bind escalation or token read as a confirmed finding and stop there.
- **Do not** read directory contents, extract device credentials, or execute alert templates/Cockpit shell commands on live systems; prove boundaries with identity/permission confirmation in a lab or owner-approved scope.
- **Do not** register trusted services or register accounts on production JetBrains instances; use the endpoint-existence + auth-gate differential instead.
- Keep credentials, tokens, and directory data out of the wiki and out of reports.

---

*Sources: [GHSA-pr87-24g5-hphv](https://github.com/advisories/GHSA-pr87-24g5-hphv) · [Red Hat CVE-2026-18922](https://access.redhat.com/security/cve/CVE-2026-18922) · [GHSA-p34m-7cj2-q64p](https://github.com/advisories/GHSA-p34m-7cj2-q64p) · [Red Hat CVE-2026-19843](https://access.redhat.com/security/cve/CVE-2026-19843) · [GHSA-g4xg-g9jg-549h](https://github.com/advisories/GHSA-g4xg-g9jg-549h) · [Red Hat CVE-2026-76560](https://access.redhat.com/security/cve/CVE-2026-76560) · [GHSA-r5vv-79fp-2427](https://github.com/advisories/GHSA-r5vv-79fp-2427) · [Red Hat CVE-2026-18355](https://access.redhat.com/security/cve/CVE-2026-18355) · [GHSA-w44j-qc22-m82h](https://github.com/advisories/GHSA-w44j-qc22-m82h) · [GHSA-3hfh-j9g4-36r5](https://github.com/advisories/GHSA-3hfh-j9g4-36r5) · [GHSA-p8f6-44xp-3cp8](https://github.com/advisories/GHSA-p8f6-44xp-3cp8) · [JetBrains issues-fixed](https://www.jetbrains.com/privacy-security/issues-fixed) · [GHSA-84cr-xjpw-q9mc](https://github.com/advisories/GHSA-84cr-xjpw-q9mc)*
