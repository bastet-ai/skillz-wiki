# Admidio log credential-sink and Aurora PostgreSQL wrapper privilege-boundary validation

Source: hourly offensive-security scan, 2026-06-15. Primary entries: GitHub advisories [GHSA-4rgq-38mh-9xqg / CVE-2026-47232](https://github.com/advisories/GHSA-4rgq-38mh-9xqg), [GHSA-mch8-wf3h-6x88 / CVE-2026-47234](https://github.com/advisories/GHSA-mch8-wf3h-6x88), and [GHSA-r236-5pc3-3qcp / CVE-2026-11401](https://github.com/advisories/GHSA-r236-5pc3-3qcp). Upstream references include the Admidio advisories for [CSRF on PKCS#12 export](https://github.com/Admidio/admidio/security/advisories/GHSA-4rgq-38mh-9xqg) and [session/auto-login cookie logging](https://github.com/Admidio/admidio/security/advisories/GHSA-mch8-wf3h-6x88), plus the AWS Go Wrapper advisory [GHSA-r236-5pc3-3qcp](https://github.com/aws/aws-advanced-go-wrapper/security/advisories/GHSA-r236-5pc3-3qcp) and [AWS security bulletin 2026-039](https://aws.amazon.com/security/security-bulletins/2026-039-aws).

These advisories are durable for operators because they expose reusable boundaries, not just product-specific patch facts:

- **Admidio debug logs:** session identifiers and persistent auto-login cookies can cross into application logs as bearer-style credentials when debug logging is enabled.
- **AWS Advanced Go Wrapper for Aurora PostgreSQL:** a low-privilege authenticated database user can influence function/search-path behavior so code runs with another RDS user's permissions, potentially reaching `rds_superuser`.

The Admidio PKCS#12 export CSRF item is included here because it appeared again in the GitHub updated feed, but the replayable CSRF proof is already covered in the earlier [TinyMCE / skillctl / Admidio export-CSRF batch](2026-06-05-tinymce-skillctl-admidio-boundary-batch-ghsa.md). This page focuses on the newly promoted log credential-sink and Aurora database privilege-boundary workflows.

## What changed

| Advisory | Product / package | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-4rgq-38mh-9xqg / CVE-2026-47232 | `admidio/admidio` 5.0.9 and related affected versions | CSRF protection missing on SSO PKCS#12 private-key export | Already published as a reusable admin-session CSRF proof; pair with the log workflow when assessing Admidio SSO administration. |
| GHSA-mch8-wf3h-6x88 / CVE-2026-47234 | `admidio/admidio` 5.0.9 and related affected versions | Raw session IDs and auto-login cookie values written to logs when debug logging is enabled | Test whether application logs become credential sinks without collecting live user secrets. |
| GHSA-r236-5pc3-3qcp / CVE-2026-11401 | `github.com/aws/aws-advanced-go-wrapper/awssql/v2`, AWS Go Wrapper 2026-04-06 | PostgreSQL function/search-path behavior in Aurora wrapper flows can elevate database permissions | Validate database wrapper privilege boundaries using a disposable low-privilege role and benign canary functions. |

## Operator triage

1. **Split web-admin and database scope.** Admidio tests belong in web-app/admin-console scope; Aurora wrapper tests belong in database/application-integration scope. Do not blend evidence across tenants or environments.
2. **Confirm affected components.** Capture Admidio version evidence and whether SSO keys/debug logging are configured. For Aurora, confirm use of the AWS Advanced Go Wrapper around Aurora PostgreSQL, not merely the presence of PostgreSQL.
3. **Use canary-only secrets.** Create disposable sessions and synthetic log markers for Admidio. Use synthetic database roles, schemas, and functions for Aurora. Never export production private keys, real cookies, service-account tokens, or customer data.
4. **Prefer negative controls.** Strong evidence shows the expected safe behavior first: CSRF rejection, redacted log values, and low-privilege database functions that cannot execute as privileged users.
5. **Stop at the boundary proof.** The report should prove a crossed boundary, not perform account takeover, private-key abuse, production database mutation, or persistence.

## Admidio log credential-sink workflow

### Goal

Determine whether debug logging stores bearer-style session values, while avoiding capture of real user cookies.

### Preconditions

- Customer approval to inspect a test log sink or receive a redacted log excerpt from the application owner.
- A disposable test account and fresh session created for the proof.
- Agreement that no production logs or unrelated user sessions will be searched.

### Safe validation steps

1. **Start with a synthetic session.** Log in with a disposable account and set a unique canary value in a benign profile field or user-agent suffix to correlate log entries.
2. **Trigger cookie-setting paths.** Use normal login/logout and optional remember-me flows only for the disposable account.
3. **Inspect only scoped log output.** Search the validation window for the canary marker and session-cookie field names. Do not grep entire production logs for all cookie values.
4. **Redact values immediately.** Evidence should show that fields such as cookie value or `sessionId` are present, with values truncated or replaced by a hash generated by the customer.
5. **Confirm exploitability constraints.** Record whether debug logging was enabled, who can read the logs, and whether the exposed values were still valid during the test window.

### Evidence to collect

- Debug logging state and log sink location at a high level.
- Redacted log lines showing cookie/session fields for the disposable account only.
- Session lifetime and auto-login preconditions if tested.
- A statement that no third-party user sessions were collected or replayed.

## Aurora PostgreSQL wrapper privilege-boundary workflow

### Goal

Prove whether a low-privilege authenticated Aurora PostgreSQL user can cause wrapper-mediated function execution with another RDS user's privileges, stopping at a benign canary effect.

### Preconditions

- A lab or customer-approved Aurora PostgreSQL environment using the affected AWS Advanced Go Wrapper version.
- A disposable low-privilege database role and a separate disposable higher-privilege test role provided by the owner.
- A throwaway schema and table for canary evidence.
- No production extensions, application schemas, or privileged operational roles in the proof path.

### Safe validation steps

1. **Inventory the wrapper path.** Confirm that the application or test harness uses the AWS Advanced Go Wrapper for Aurora PostgreSQL and record the wrapper version. Do not assume all Aurora PostgreSQL deployments are affected.
2. **Baseline role boundaries.** As the low-privilege role, show that direct writes to the privileged canary table or privileged function are denied.
3. **Create an inert function canary.** In a disposable schema, create a function whose only observable effect is writing `role_name`, `current_user`, and a static marker into a canary table controlled by the test team.
4. **Exercise the affected wrapper/search-path flow.** With customer-approved harness code, invoke the wrapper behavior that can resolve or execute the crafted function across privilege boundaries. Keep SQL limited to synthetic schemas and canary rows.
5. **Compare results.** The proof is sufficient if the canary row records execution as a role the low-privilege user could not directly assume. Do not create users, alter privileges, read production tables, or test arbitrary function bodies.

### Evidence to collect

- Wrapper package and version evidence.
- Aurora PostgreSQL cluster identifier redacted to a non-sensitive alias.
- SQL transcript showing low-privilege denial for direct access.
- SQL transcript showing only the inert canary row if the boundary is crossed.
- `search_path`, schema names, and role names sanitized or synthetic.

## Reporting heuristics

- Lead with the crossed boundary: **session token to log sink** or **low-privilege database role to higher-privilege execution context**. If pairing with the earlier Admidio export item, keep **admin browser to private-key export** as a separate proof section.
- Keep product claims narrow. For Aurora, the target is the AWS Advanced Go Wrapper around Aurora PostgreSQL, not PostgreSQL or RDS broadly.
- Separate prerequisites from impact: authenticated admin session for Admidio CSRF, debug logging and log access for Admidio credential sinks, low-privilege DB credentials plus affected wrapper flow for Aurora.
- Use canary artifacts in screenshots and transcripts. Do not attach private keys, real cookies, live database secrets, or production object names.
- When bundling with adjacent findings, group by reusable boundary rather than severity score.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, GitHub Security Blog, and CISA KEV. No new CISA, PortSwigger, Trail of Bits, ProjectDiscovery, or Disclosed item added a higher-signal workflow in this run. GitHub published-feed items from 2026-06-12 remain covered by the existing File Browser/Fleet/Fabric/Cordova, esbuild/mise/Tomcat/Radius/TYPO3, TYPO3/Budibase/GeoServer/Appsmith, and Budibase/SwiftNIO/LangGraph/Chisel pages; this page promotes the later GitHub updated-feed items with reusable credential-log and database privilege-boundary value.

## October 1 21:3xZ follow-up: pgvector IVFFlat index build — ordinary DB-user DDL reaches memory corruption (folded)

**pgvector <0.8.7** ([GHSA-pw7q-9788-x566](https://github.com/advisories/GHSA-pw7q-9788-x566), 8.8): building an **IVFFlat index** lets a *database user* (no superuser, no OS access) write data out-of-bounds, which can lead to arbitrary code execution. Same shape as this page's Aurora wrapper findings: an operation that looks like routine schema DDL crosses from the SQL privilege plane into the server-process memory plane.

Operator rule for any Postgres deployment with extensions (pgvector is now ubiquitous in AI/RAG stacks): **every extension-provided DDL path — index builds, analyzer/operator registration, cast/serializer hooks — is a native-code execution context running as the postgres user, reachable with only table-level privileges.** If your authorized scope includes a Postgres instance (common foothold after app-level SQLi or leaked low-priv creds), enumerate installed extensions (`SELECT extname FROM pg_extension;`) and treat index-build/`USING <ext>` operations on attacker-influenced data as candidate memory-safety sinks: reproduce only in a disposable lab instance with the affected extension version, prove the crash/OOB signal there, and report the *surface* (extension + version + reachable operation under low privileges) rather than running corruption primitives on the customer's server. Never claim OS-level code execution from a server crash alone.

## October 19 follow-up: openGauss `pg_read_binary_file_blocks()` — block-level file reader checks path shape but never caller privilege (CVE-2026-111439 / [GHSA-cr5j-x763-5676](https://github.com/advisories/GHSA-cr5j-x763-5676), medium, 3.0.0–6.0.x, fixed 7.0.0-LTS, [PR #9374](https://gitcode.com/opengauss/openGauss-server/pull/9374))

openGauss's built-in `pg_read_binary_file_blocks()` validates only start-block/block-count ranges and delegates to `ReadBinaryFileBlocksFirstCall()`, which performs path normalization plus `..`/data-directory confinement — but **no permission check** (no `SELECT` grant required; the `is_row_data_file()` helper only classifies file shape). Any user with a plain database connection who can obtain a relation's physical path — trivially via `pg_relation_filepath()`, including compressed-data `_compress` side files — reads arbitrary table data as raw binary blocks without the table's `SELECT` privilege. Row-level security, column ACLs, and grant-based read control are all bypassed because the read never enters the executor.

Operator rules for this page's "SQL-plane privilege boundary" lineage (Aurora wrapper, pgvector DDL):

- **Path-confinement != authorization.** Admin functions that read files under the data directory routinely ship *shape* checks (no `..`, inside datadir, recognized file form) while forgetting the *principal* check (`has_table_privilege`-class gate). Audit fingerprint in any Postgres-family source: `ReadBinaryFile*`/`pg_read_file`-family wrappers where the permission check present on the canonical sibling (`pg_read_file()` requires pg_read_server_files role) is absent on the extended/variant function. Sibling-differential again — the correct sibling is the attack map.
- **Raw-path oracle chain:** `pg_relation_filepath()` (or extension/vendor equivalents listing physical files, e.g. compressed-relation `_compress` artifacts) → block reader → binary heap/segment contents. On an authorized Postgres-family target with only public connect rights, enumerate admin file-read builtins and try them against a table you were *denied* `SELECT` on — a positive read is the finding, and it doubles as an RLS/row-filter bypass for compliance-scoped databases.
- **Version-band fingerprint:** openGauss 3.0.x–6.0.x vulnerable, 7.0.0-LTS fixed; the advisory feed also shows same-train `HllObjectUnpack()` (8rj5, tracked) and the JDBC `LogFactory` leg (4fmq, promoted). Same-product re-sweep applies — third openGauss leg this week; see the companion replication-auth-lane fold on the Sept 21 precedence page.
- Validation boundary: disposable openGauss instance, synthetic table with marker rows, deny-then-read differential proof only; never read customer tables or backups on live systems.

## October 19 follow-up: RisingWave `posix_fs` sources / `fs` sinks — schema CREATE privilege becomes arbitrary server file read+write (CVE-2026-112262 / [GHSA-55ch-h383-9r92](https://github.com/advisories/GHSA-55ch-h383-9r92), high, before 3.1.0)

RisingWave < 3.1.0: a low-privileged SQL user holding only **schema CREATE** privilege can `CREATE SOURCE ... FROM posix_fs` with `posix_fs.root` set to any directory, or `CREATE SINK ... FROM fs` with `fs.path` anywhere on the server — the streaming database's connector configuration accepts arbitrary host paths with no server-side confinement or privilege gate, so the SQL plane reaches credentials/keys read out of the filesystem and files written **as the server (root) user**.

Operator rules continuing this page's SQL-plane → OS-plane lineage (Aurora wrapper, pgvector index-build, openGauss block reader):

- **Connector/extension config fields are filesystem paths, not labels.** On any Postgres-family or Postgres-wire database with foreign-data wrappers, CDC connectors, or import/export extensions (`posix_fs`, `fs`, `file_fdw`, `s3_fdw`, table-function importers), the path-ish config parameters deserve the traversal/absolute-path battery from a *low-privilege* session. Audit question: does DDL permission alone choose the server-side path, or is there a server-directory allowlist plus a superuser/pg_read_server_files-class gate (the correct `file_fdw` shape)? Missing principal gate on the vendor's own connector = this finding.
- **Bidirectional is worse:** RisingWave shipped both a read leg (source) and a write leg (sink) in the same unguarded config namespace — a write-as-root primitive on a DB server is a persistence/lateral pivot, and the report's impact anchor is the *minimum* DDL privilege needed (schema CREATE), same least-priv-anchor rule as the wrapper legs above.
- **Fingerprint on authorized DB engagements:** after any app-level foothold with database connect rights, enumerate connector types (`CREATE SOURCE/SINK` accepted grammars, `SELECT * FROM pg_foreign_data_wrapper`-class catalogs) and try a marker path outside the data directory with a denied-then-allowed differential. Disposable RisingWave lab, marker files only; never read server credentials or write outside a temp dir on live systems.
