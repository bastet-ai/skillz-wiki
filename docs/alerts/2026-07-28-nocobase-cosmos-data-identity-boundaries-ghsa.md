---
title: NocoBase SQL-scope and Cosmos proxy-identity boundaries
---

# NocoBase SQL-scope and Cosmos proxy-identity boundaries

A July 28 reviewed-advisory wave exposes three reusable operator checks: an application SQL feature whose `SELECT` blacklist does not bind queries to the intended collection namespace, a tunnel-authentication shortcut that forwards caller-supplied identity headers, and an API route that treats any bearer-shaped value as proof of authorization.

Sources:

- [GHSA-v8vm-cqh8-q87q / CVE-2026-52888: NocoBase SQL blacklist bypass](https://github.com/nocobase/nocobase/security/advisories/GHSA-v8vm-cqh8-q87q)
- [NocoBase metadata-query fix](https://github.com/nocobase/nocobase/commit/4aecb60d151a9002004dcf984f63d62f17a6cb45)
- [GHSA-2rx5-2g7j-2659: Cosmos Constellation forward-auth header smuggling](https://github.com/azukaar/Cosmos-Server/security/advisories/GHSA-2rx5-2g7j-2659)
- [GHSA-5fqm-cc34-fcf5: Cosmos arbitrary bearer acceptance](https://github.com/azukaar/Cosmos-Server/security/advisories/GHSA-5fqm-cc34-fcf5)
- [Cosmos 0.22.19 release commit](https://github.com/azukaar/Cosmos-Server/commit/59c561d686c8f9843b3e092b50f6346c481d8bbf)

The reviewed package ranges are `@nocobase/plugin-collection-sql <2.0.62`, alpha builds before `2.1.0-alpha.46`, beta builds before `2.1.0-beta.45`, Cosmos Server `<=0.22.18` for the tunnel path, and Cosmos Server `0.22.18` for the public-device route. Confirm the exact package, enabled feature, database privileges, route configuration, caller position, and fixed-build behavior before reporting.

!!! warning "Authorized validation only"
    Use disposable NocoBase databases, synthetic tables and rows, lab-only Cosmos users/devices, fake bearer values, a canary upstream, and an isolated Constellation network. Never query password hashes, live user tables, PostgreSQL session text, customer device metadata, production internal addresses, or real administrator routes; never retain or replay real tokens.

## Boundary matrix

| Surface | Intended authority | Untrusted input | Safe proof |
| --- | --- | --- | --- |
| NocoBase SQL Collection | selected collection or approved schema | authenticated administrator's SQL text | one synthetic row in a lab-only out-of-scope table |
| Cosmos tunnel shortcut | trusted manager-generated identity | device request plus `x-cosmos-*` headers | fake principal reflected by a canary upstream |
| Cosmos public-device route | validated and authorized token | arbitrary non-empty bearer value | one synthetic device record in a temporary database |

The finding is the broken binding, not merely accepted syntax or an HTTP 200. Capture the input representation, authorization decision, canonical identity or database object, and harmless sink separately.

## NocoBase: test SQL object scope, not only verb filtering

The affected `sqlCollection:execute` path accepts administrator-supplied `SELECT` or `WITH ... SELECT` text and rejects a list of dangerous substrings. The advisory demonstrates that the list omitted sensitive PostgreSQL catalogs and application tables. The durable pattern is broader: **a read-only verb check does not prove that the query remains inside the collection or schema the feature is meant to expose**.

### Synthetic namespace fixture

1. Deploy an affected NocoBase build with PostgreSQL in a disposable network. Enable the SQL Collection plugin and create only lab users.
2. Create `allowed_collection` with marker `ALLOW-<random>` and a separate lab-only table such as `audit_canary` with marker `OUTSIDE-<random>`. Neither marker should resemble a credential or customer record.
3. Give the application database role only the minimum privileges needed for the fixture. Record the role, active schema, `search_path`, and grants.
4. Through the normal administrator UI or `POST /api/sqlCollection:execute`, run a baseline query against `allowed_collection` and capture the selected collection configuration plus returned marker.
5. Submit a single `SELECT` that addresses `audit_canary`. Record the raw query, parser/filter verdict, resolved relation, response field names, and marker hash. Stop after one row.
6. Add controls for schema-qualified names, a CTE, a nested subquery, quoted identifiers, comments between tokens, and a nonexistent relation. Keep every object synthetic.
7. Repeat on the relevant fixed line. Confirm the known metadata names are rejected, but do not assume the patch creates a general collection allowlist: the linked fix extends the blacklist with `pg_catalog`, selected `pg_*` names, and `information_schema`.

A bounded positive result is **application administrator selects the SQL Collection surface -> accepted read-only SQL resolves outside the intended collection namespace -> one synthetic out-of-scope marker is returned**. Do not query `pg_shadow`, `pg_authid`, `pg_stat_activity`, the application's real `users` table, or any credential-bearing field. A filter bypass is valuable without collecting sensitive data.

Report database privilege separately from application validation. If the application role cannot read the canary, a database denial is a negative control; it does not prove the SQL filter correctly binds object scope.

## Cosmos: test who is allowed to assert forward-auth identity

The affected Constellation branch checks tunnel source and a device key, but on auth-enabled routes it can return to the upstream before removing caller-supplied `x-cosmos-user`, `x-cosmos-role`, `x-cosmos-user-role`, and `x-cosmos-mfa` headers or applying the administrator-only gate. This requires Constellation, an enrolled device key, tunnel reachability, an auth-enabled proxy route, and an upstream that trusts Cosmos identity headers.

### Canary upstream matrix

1. Build Cosmos Server `0.22.18` in an isolated lab, enable Constellation, and enroll two synthetic devices: one manager and one ordinary member.
2. Configure an auth-enabled, administrator-only proxy route to a canary upstream. The upstream must only return a JSON object containing the identity headers it received and increment an in-memory counter; it must expose no real privileged action.
3. Establish the baseline with a valid lab administrator session. Record source device, route flags, Cosmos authentication path, upstream headers, and counter state.
4. From the ordinary enrolled device, send its valid lab device credential with a unique fake identity such as `canary-admin`. Do not use a real username.
5. Vary one factor at a time: no identity header, identity header without a device key, invalid key, non-Constellation source, ordinary member device, manager device, `AuthEnabled=false`, and `AdminOnly=false`.
6. Repeat on `0.22.19`. The release changes the shortcut so only a manager device may use it; verify this exact deployed trust model rather than claiming all forwarded identity is cryptographically bound.

The bounded positive result is **ordinary enrolled device + valid device key + caller-supplied identity header -> auth-enabled/admin-only route forwards the fake identity to the canary upstream without a Cosmos user session**. Preserve every precondition. This is not an Internet-unauthenticated path and does not establish impact where the upstream ignores these headers.

## Cosmos: distinguish bearer presence from token validation

The affected `GET /cosmos/api/constellation/public-devices` handler checks for an `Authorization` header, removes a `Bearer ` prefix, but does not validate or use the resulting value when selecting visible devices. Constellation is disabled by default, so prove that it is enabled and populated before testing.

1. Seed a temporary Cosmos database with one visible synthetic device and one invisible control. Use fake names, RFC 5737 documentation addresses, and an owned hostname.
2. Exercise the real route through the deployed middleware, not the handler in isolation.
3. Build a decision table for no header, empty bearer, malformed scheme, random bearer, invalid Cosmos-prefixed token, valid underprivileged lab token, and valid authorized lab token.
4. Capture only status, response shape, synthetic row count, and hashes of seeded names. Do not preserve addresses or metadata from any non-lab device.
5. Repeat on `0.22.19`; the linked release calls the normal permission check before serving the route.

A valid result is **arbitrary non-empty bearer value -> middleware and handler accept it -> synthetic visible-device row is returned**, while the missing-header control is rejected. Do not describe the endpoint as universally exposed: the Constellation feature and visible device data are required.

## Reporting checklist

Include:

- exact NocoBase/Cosmos versions, package or image digest, database engine, and enabled plugins/features;
- caller role, Constellation device role, network position, route `AuthEnabled`/`AdminOnly` flags, and upstream header trust;
- raw query/header class, filter or middleware branch, resolved relation/principal, and marker-only sink evidence;
- database role, schema, `search_path`, grants, and proof that all rows/devices/principals were synthetic;
- baseline, one-variable negative controls, and affected/fixed comparisons;
- a bounded claim separating SQL object-scope escape, tunnel identity injection, and arbitrary-token metadata access.

Do not include tokens, cookies, database hashes, production table names, real usernames, device inventories, internal addresses, upstream application data, or copied advisory proof-of-concept secrets.

## August 20 NocoBase follow-up: storage-root redirection and backup-restore shell interpolation

Two records published 2026-08-19/20 extend the NocoBase low-code platform boundary with a reusable pattern: an admin-configurable storage property or a backup metadata field crosses into a filesystem root or a shell command string without binding the value to the object it is supposed to describe.

- [GHSA-ghvf-qf6h-g8x5: NocoBase arbitrary file write chained with local file inclusion](https://github.com/advisories/GHSA-ghvf-qf6h-g8x5): `storages:update` accepts an unsanitized `documentRoot`, letting any authenticated admin redirect the upload storage root to an arbitrary path (including the application directory), while the plugin-manager `pm:enable` endpoint triggers Node.js `require()` on a user-supplied absolute path with no validation. Chained, the two flaws reach authenticated remote code execution.
- [GHSA-p853-83gj-wjj3 / CVE-2026-55410: NocoBase backup restore schema-name command injection](https://github.com/advisories/GHSA-p853-83gj-wjj3): `@nocobase/plugin-backups` 2.0.57 restores PostgreSQL backups by interpolating the backup metadata schema name into shell command strings executed via `child_process.exec()`. A backup-management user who can restore an uploaded PostgreSQL backup with forced schema restore can place shell metacharacters in `_metadata.json` under `database.schema`.

### Storage-root redirection to module load

Replayable validation:

- Preconditions: a disposable NocoBase install, a synthetic admin account, a lab-only storage directory with one marker file, a denied `require()` recorder patched into the plugin-manager load path, and no production plugins or application files.
- Baseline: confirm `storages:update` on the default `public` storage root returns the configured `documentRoot`, and that `pm:enable` for a benign in-app plugin succeeds.
- Send a `storages:update` request setting `documentRoot` to the lab-only directory, then confirm a subsequent upload lands there. Record the raw request, the persisted storage record, and the resolved filesystem root.
- Drive `pm:enable` with a path pointing only at the lab marker module (a no-op ESM file) and capture the denied `require()` recorder: the requested path, the resolution result, and whether module code was entered.
- A bounded positive is **admin `documentRoot` value -> storage root rebind -> upload writes outside the default root**, and **plugin-manager path -> `require()` entry for an absolute path outside the plugin directory**, on the affected build only.

Do not write outside the lab root, do not load executable application files, and do not use this chain on a production instance. The report is the two-step boundary (storage root rebind plus unrestricted module path), not a claim that default installations expose both.

### Backup metadata schema name into a shell command

Replayable validation:

- Preconditions: a disposable NocoBase install with `@nocobase/plugin-backups` and PostgreSQL, a synthetic backup-management user (no other privileges), and a patched `child_process.exec` recorder that captures the composed command string and rejects before execution.
- Upload a synthetic PostgreSQL backup fixture whose `_metadata.json` `database.schema` contains a shell metacharacter marker (for example a quoted marker that would break out of the argument position).
- Trigger the restore with forced schema restore. Capture: the raw `_metadata.json` field, the composed command line, the exec branch, and the denied-sink result.
- Controls: a benign schema name, a schema name with only allowed characters, a restore without forced schema restore, and the fixed build where the schema name is bound as a single argument or passed through a parameterized path.

A bounded positive is **backup-management user's `database.schema` value -> interpolated shell command string -> exec argument boundary broken for the marker**, on the affected build only. Never execute the composed command, never restore into a real database, and keep every fixture synthetic.

## pglogical publisher-to-subscriber command boundary

[GHSA-cg29-63x4-27px / CVE-2026-50736](https://github.com/advisories/GHSA-cg29-63x4-27px) adds a database control-plane variant: pglogical queue messages can carry out-of-band commands such as replicated DDL, and affected subscribers execute the payload with the apply worker's PostgreSQL-superuser-equivalent authority. The record's key precondition is the ability to direct a subscription at an attacker-controlled publisher; default PostgreSQL installations normally reserve that action for superusers, so the useful target is a managed or shared service that delegates subscription creation to lower-privilege tenants.

Use two disposable PostgreSQL clusters, a delegated non-superuser test role, a dedicated subscriber database, and one benign canary schema/function. First prove whether the role can create or retarget a pglogical subscription to the owned publisher. Then send only a queue message that creates or invokes an inert marker object in the disposable subscriber. Record the role initiating the subscription, publisher identity, message class, apply-worker role, SQL audit event, and marker owner. Compare a fixed build and a control where subscription creation remains superuser-only.

Report **delegated subscription authority -> attacker-controlled publisher queue message -> subscriber apply-worker superuser context**. Do not read catalogs containing credentials, create login roles, alter extensions, access other databases, or execute operating-system commands. If the caller already has PostgreSQL superuser or equivalent subscription authority, state that the privilege boundary is absent rather than claiming escalation.

## ClickHouse client escaping differential

[GHSA-6wcc-39rp-hh9p / CVE-2026-54658](https://github.com/hypequery/hypequery/security/advisories/GHSA-6wcc-39rp-hh9p) reports that `@hypequery/clickhouse` before 2.0.2 escaped single quotes before backslashes during parameter substitution. A caller-controlled value ending in a backslash could change where the generated string literal closes and alter the surrounding SQL.

Use a disposable ClickHouse database with one allowed table and one synthetic out-of-scope table. Instrument or mock the query transport first to capture the template, parameter value, final SQL text, and server-parsed result without executing multi-statement or destructive queries. Compare empty, quote, backslash, trailing backslash, quote-plus-backslash, Unicode, and fixed-version cases one variable at a time. If server validation is required, limit the effect to selecting one canary constant or row from the synthetic table.

The proof is **parameter API value -> incorrect backslash/quote escaping -> server parser observes SQL structure outside the intended string literal**. Do not query system catalogs, credentials, user datasets, or run file/table/function mutations. Record ClickHouse settings that affect backslash and multiquery parsing, because a malformed client string without a reachable parser effect is not arbitrary SQL execution.

## October 19 follow-up: `sqlCollection:setFields` is a second write path around `checkSQL()` — the validator exists, the alternate action doesn't call it ([GHSA-j67h-xf8r-r323](https://github.com/advisories/GHSA-j67h-xf8r-r323) / CVE-2026-112306, high, `@nocobase/plugin-collection-sql` through 2.2.28)

The July leg above covered `sqlCollection:execute` accepting `SELECT`/`WITH ... SELECT` text with a dangerous-substring deny-list. This new advisory adds a sharper axis: attackers holding the `collection-sql` snippet bypassed `checkSQL()` **entirely** by storing unvalidated SQL through the `sqlCollection:setFields` action — a schema-definition verb that persists the collection's query text, which is then executed **on reload**. Impact legs named in the advisory: reading `pg_shadow` password hashes and calling `pg_read_file`.

Operator rules:

1. **Enumerate every write path that reaches the same sink, then diff which ones call the validator.** `execute` checked, `setFields` didn't — the validation function existed in the same plugin and was simply not wired into the schema-definition verb. For any "guarded SQL/config/expression field" feature, list all actions that can assign that field (`:execute`, `:update`, `:setFields`, `:import`, bulk ops, REST PATCH on the resource record) and prove the guard fires on each. A `201` from an unvalidated sibling of a validated endpoint is the whole finding.
2. **Store-time vs run-time validation drift.** A deny-list applied at submit time on one path means nothing if a stored value is executed later by a different code path (here: on collection reload). Test: set a benign-looking query through the alternate verb, trigger the reload path, observe what the worker actually runs.
3. **This is the same product's third SQL-boundary wave** (July scope-check leg, August storage-root leg, now the setFields leg). Same-product re-sweep rule validated again — keep NocoBase on the standing low-code re-sweep list.

Validation boundary: disposable NocoBase with a delegated non-superuser PostgreSQL role; prove reachability of `pg_shadow`/`pg_read_file` only in your own scratch cluster with synthetic rows, redact any captured hash material, never run the query on a shared database.
