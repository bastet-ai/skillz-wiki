# ArcadeDB, Nuclio, and Pheditor control-boundary checks

Sources: hourly offensive-security scan, 2026-07-16 GitHub Security Advisory updates. Primary entries: [GHSA-x9f9-r4m8-9xc2](https://github.com/advisories/GHSA-x9f9-r4m8-9xc2), [GHSA-48qw-824m-86pr](https://github.com/advisories/GHSA-48qw-824m-86pr), [GHSA-vwjc-v7x7-cm6g](https://github.com/advisories/GHSA-vwjc-v7x7-cm6g), [GHSA-x8mg-6r4p-87pf](https://github.com/advisories/GHSA-x8mg-6r4p-87pf), [GHSA-vg6x-6pg9-6qwg](https://github.com/advisories/GHSA-vg6x-6pg9-6qwg), [GHSA-8w86-m9h8-hvqg](https://github.com/advisories/GHSA-8w86-m9h8-hvqg), [GHSA-3v79-m2cg-89ww](https://github.com/advisories/GHSA-3v79-m2cg-89ww), [GHSA-wpcj-rmv4-86qg](https://github.com/advisories/GHSA-wpcj-rmv4-86qg), [GHSA-p4h7-p9rj-2pq2](https://github.com/advisories/GHSA-p4h7-p9rj-2pq2), [GHSA-9643-6xjp-vx57](https://github.com/advisories/GHSA-9643-6xjp-vx57), and [GHSA-wg4w-wr5q-6vjc](https://github.com/advisories/GHSA-wg4w-wr5q-6vjc).

This batch is durable for operators because it exposes reusable boundaries across database scripting/import surfaces, serverless build control planes, and web-based file editors: low-privilege roles reaching host-aware interpreters, import sources crossing into SSRF or local files, unauthenticated function-build APIs writing outside their workspace, template-rendered build configuration becoming executable code, and prefix-based terminal allowlists reaching a shell.

!!! warning "Authorized validation only"
    Keep proofs to disposable ArcadeDB databases, Nuclio lab dashboards, Pheditor test installs, owned callbacks, fake credentials, synthetic files, and inert marker commands. Do not read real host secrets, query metadata services, write outside disposable temp paths, modify production schemas, run web shells, alter live functions, or publish weaponized payload strings.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-x9f9-r4m8-9xc2](https://github.com/advisories/GHSA-x9f9-r4m8-9xc2) | ArcadeDB engine before `26.7.2` | Trigger scripting allowed broad Java host interop for users with schema-update rights | Validate whether database-admin-but-not-security-admin roles can cross from trigger definitions into host command execution in a lab. |
| [GHSA-48qw-824m-86pr](https://github.com/advisories/GHSA-48qw-824m-86pr) | ArcadeDB server before `26.7.1` | Read-only database users could reach JavaScript command execution and host file reads | Test script-language command paths as role-boundary checks, proving only with synthetic canary files. |
| [GHSA-vwjc-v7x7-cm6g](https://github.com/advisories/GHSA-vwjc-v7x7-cm6g) | ArcadeDB engine before `26.7.2` | SQL `DEFINE FUNCTION ... LANGUAGE js` bypassed the polyglot scripting permission gate | Test whether SQL function-library paths still let read-only or low-privilege users reach JavaScript execution after direct polyglot routes are blocked. |
| [GHSA-x8mg-6r4p-87pf](https://github.com/advisories/GHSA-x8mg-6r4p-87pf) | ArcadeDB server before `26.7.2` | Time-series, batch, Prometheus, and Grafana handlers resolved `{database}` without the normal per-database access check | Add cross-database IDOR probes where one authorized database token attempts read/write through alternate handler families against a second database. |
| [GHSA-vg6x-6pg9-6qwg](https://github.com/advisories/GHSA-vg6x-6pg9-6qwg) | ArcadeDB engine before `26.6.1` | Read-only users could mutate schema through unchecked DDL methods | Add schema-integrity probes to low-privilege database tokens without touching production data models. |
| [GHSA-8w86-m9h8-hvqg](https://github.com/advisories/GHSA-8w86-m9h8-hvqg) | ArcadeDB engine before `26.6.1` | `IMPORT DATABASE` accepted HTTP(S) and local-file sources without sufficient admin gating | Reuse SSRF and local-file canary workflows through database import endpoints, not through generic web inputs. |
| [GHSA-3v79-m2cg-89ww](https://github.com/advisories/GHSA-3v79-m2cg-89ww) | Nuclio before `1.16.5` | Dashboard function build attributes were rendered into `build.gradle` without code-context safety | Validate serverless build pipelines where user-supplied repository metadata becomes executable build configuration. |
| [GHSA-wpcj-rmv4-86qg](https://github.com/advisories/GHSA-wpcj-rmv4-86qg) | Nuclio before `1.16.5` | `spec.handler` module names could escape the temporary source directory during function build | Test unauthenticated or weakly authenticated dashboard APIs for build-time file-write boundaries with marker files only. |
| [GHSA-p4h7-p9rj-2pq2](https://github.com/advisories/GHSA-p4h7-p9rj-2pq2) | Pheditor `2.0.1` through `2.0.5` | Hardcoded default password can expose file editing, upload, and terminal features | Include default-credential checks only where credential testing is in scope, then stop at harmless file/terminal canaries. |
| [GHSA-9643-6xjp-vx57](https://github.com/advisories/GHSA-9643-6xjp-vx57), [GHSA-wg4w-wr5q-6vjc](https://github.com/advisories/GHSA-wg4w-wr5q-6vjc) | Pheditor terminal feature | Prefix allowlist and incomplete shell metacharacter filtering allowed command execution past intended terminal restrictions | Audit web terminal wrappers for first-token checks followed by raw shell execution. |

## Replayable validation boundaries

### ArcadeDB script, schema, and import probes

1. Build a disposable ArcadeDB instance with a synthetic database, a low-privilege `reader` user, and a separate schema-update user. Use fake data only.
2. Enumerate which HTTP command/query or MCP-adjacent database analysis paths are exposed in the target deployment. Record whether each path requires authentication and which database role is bound to the token.
3. For script-language checks, avoid host secret reads and process-control payloads. Use a synthetic file placed by the tester under a temp directory and prove only that the vulnerable role can or cannot read that canary. Include both direct polyglot command routes and SQL function-library routes such as user-defined JavaScript functions, because fixes may gate only one interpreter entry point.
4. For trigger checks, use an inert command marker such as writing a nonce to a disposable temp path in a lab. Do not place payloads in production triggers or fire triggers against customer records.
5. For schema mutation checks, create a throwaway type/property and attempt harmless rename or property-flag changes with the low-privilege token. Immediately drop the disposable object in the lab.
6. For `IMPORT DATABASE`, use an owned callback endpoint and a synthetic local file under an allowlisted temp directory. Do not target cloud metadata, loopback admin panels, configuration directories, keys, or unrelated filesystem paths.
7. For cross-database handler checks, create two disposable databases (`a` and `b`), authorize the test user only for `a`, and compare the expected `403` from canonical command/query routes with alternate time-series, batch, Prometheus, or Grafana routes that name `b`. Positive evidence should be limited to marker rows, marker series, or route-status differences.
8. Repeat every probe against a patched version and an admin-only positive control so the report shows role drift rather than generic database reachability.

Report ArcadeDB findings as **database role -> script/import/schema feature -> host, network, or schema side effect outside documented permission boundary**, or **database-scoped token -> alternate handler family -> second database read/write without authorization**. Evidence should include role names, endpoint family, version, canary-only outputs, and negative controls.

### Nuclio dashboard build-control checks

1. Use a lab Nuclio dashboard or an explicitly approved target where function creation and builds are in scope. Confirm whether the dashboard is in NOP/no-auth mode or behind an identity layer.
2. Create a disposable function whose source returns a static marker and has no access to live secrets, queues, model artifacts, or production clusters.
3. For build-configuration injection, place only inert marker statements in Java runtime repository metadata and capture whether the generated build configuration executes during Gradle configuration.
4. For handler path traversal, attempt only writes to a disposable temp path inside the dashboard container or a mounted scratch directory approved for the test. Never write cron files, shell startup files, binaries, Kubernetes credentials, or application configuration.
5. Capture the API route, auth posture, function spec fields, build logs with markers, file path decision table, container user context, and cleanup.
6. Run patched `1.16.5` or later as a negative control.

Report Nuclio findings as **dashboard function API -> build metadata or handler module path -> build-container code execution or file write**. Keep payload syntax out of public reports unless the program explicitly permits full reproduction details.

### Pheditor default-credential and terminal-wrapper checks

1. Confirm that password testing and web-terminal validation are in scope. If credential testing is not allowed, stop at version/configuration evidence.
2. Test only the documented default credential condition against a disposable install or an approved target. Do not brute-force or reuse credentials across systems.
3. If authenticated, verify the terminal permission state and configured command allowlist before sending any command.
4. Use a marker-only command in a lab, such as printing a nonce or writing under a disposable temp directory. Avoid network egress, shell profiles, persistence, interpreter downloaders, or web-root writes.
5. Separately test file upload/edit exposure with harmless text markers, not executable extensions or web shells.
6. Add controls for changed passwords, disabled terminal permission, patched versions, and allowlist entries that are validated after shell parsing rather than before it.

Report Pheditor findings as **default or authorized login -> web editor terminal/upload feature -> shell or filesystem side effect beyond intended allowlist**.

### July 24 Pheditor forced-change and argv follow-up

Two later advisories sharpen this fixture:

- [GHSA-f25v-x6vr-962g](https://github.com/advisories/GHSA-f25v-x6vr-962g): when the stored password was still the default, the forced-change branch checked that stored state but did not verify the submitted current password. Any non-empty value could reach the change form and establish an administrator session. Use a disposable install, a synthetic password, and a second browser profile; prove only the login-state transition. Version `2.0.8` is the fixed control.
- [GHSA-g3hq-hphg-8fhh](https://github.com/advisories/GHSA-g3hq-hphg-8fhh): after metacharacter fixes, the terminal still prefix-matched an allowlisted program and passed the whole string to a shell. Program-native execution options therefore crossed the allowlist without shell separators. Test only with an argv recorder or a command that writes one nonce beneath a disposable temp root. Version `2.0.7` is the fixed control.

Run the password case separately from terminal capability. The first boundary is **unauthenticated request -> unverified forced-change branch -> admin session**; the second is **terminal-enabled account -> first-token allowlist -> executable program option -> inert marker**. Do not use the newly established session to execute a terminal proof on any non-disposable target, and do not publish reusable command payloads.

## Operator checklist

- [ ] Which identity or role crosses the boundary: read-only database user, single-database user, schema admin, unauthenticated dashboard caller, default web-editor user, or terminal-enabled account?
- [ ] Is the proof reduced to a canary file, owned callback, marker command, synthetic schema object, or build log nonce?
- [ ] Does a patched negative control block the same request shape?
- [ ] Are dangerous locations explicitly avoided: service-account tokens, cloud metadata, production config, web roots, cron paths, customer records, and live function artifacts?
- [ ] Can the report distinguish source facts from lab observations without publishing weaponized strings?

## August 2 ArcadeDB MCP principal and server-authority follow-up

Three advisories for ArcadeDB before `26.7.3` extend the database-role fixture into its MCP transport and trigger runtime:

| Advisory | Failed binding | Bounded operator proof |
| --- | --- | --- |
| [GHSA-hq22-48ph-vqch](https://github.com/advisories/GHSA-hq22-48ph-vqch) / CVE-2026-68578 | the authenticated MCP user is not bound into engine permission checks, so non-root MCP users can reach writes, DDL, schema changes, and JavaScript query behavior | non-root lab user, synthetic database, read/write/DDL decision matrix, and recorder-only script marker |
| [GHSA-7qj8-rw8h-hhxv](https://github.com/advisories/GHSA-7qj8-rw8h-hhxv) / CVE-2026-67357 | `get_server_settings` returns the HA cluster token; cluster forwarding headers then treat that bearer value as authority to select a forwarded user | fake cluster token, mocked forwarding handler, and root-versus-non-root identity decision table |
| [GHSA-p28w-g8xf-vm54](https://github.com/advisories/GHSA-p28w-g8xf-vm54) / CVE-2026-67356 | schema-admin trigger JavaScript receives the real `LocalDatabase` with unrestricted host access, exposing security-user creation outside schema authority | schema-admin lab role, recorder-wrapped security API, and inert create-user call marker without creating an account |

### MCP and trigger role matrix

1. Create a disposable database with root, read-only, read/write, and schema-admin users. Give each only the MCP access and database permissions needed for its row in the test matrix.
2. Through MCP, compare a harmless read, one marker-row write, creation of a throwaway type, and a recorder-only JavaScript query. Capture the authenticated transport principal and the principal observed by the engine separately.
3. Call `get_server_settings` only against a lab configured with a fake cluster-token sentinel. Record whether the complete sentinel is returned, but redact it from screenshots and reports.
4. Prove the forwarding half independently: replace cluster-token verification with a local recorder or use the fake lab sentinel, supply a synthetic forwarded username, and record the identity selected by the handler. Do not replay any token from a real deployment.
5. As schema admin, install a trigger whose host call is intercepted by a fake `Security.createUser` recorder. Positive evidence is the attempted method, arguments, and caller role; do not create an administrator, execute host commands, or leave the trigger installed.
6. Repeat all rows on `26.7.3`. The patched negative control should preserve legitimate root behavior while denying lower-role operations at the engine, settings, forwarding, and trigger boundaries.

Keep the three claims separate: **MCP-authenticated role -> missing engine principal -> unauthorized database operation**, **settings tool -> cluster bearer disclosure -> forwarded-user authority**, and **schema trigger -> unrestricted database host object -> server-security API call**. A settings response alone does not prove root impersonation, and schema-update permission alone does not prove that a real administrator was created.

## Reporting notes

- Lead with the trust boundary and precondition, not exploit spectacle: database role, dashboard auth mode, web-editor credential state, or shell-wrapper design.
- Preserve route names, versions, role matrices, and marker evidence. Redact hostnames, tokens, session cookies, tenant names, and filesystem layouts that reveal sensitive deployments.
- For multi-advisory clusters, group findings by reusable invariant: host-aware interpreter exposure, import source validation, build metadata execution, path confinement, or shell allowlist bypass.

## October 21 ArcadeDB second follow-up: multi-protocol authz drift — Bolt tenant enumeration, schema-flag writes without UPDATE_SCHEMA, and reader-role Groovy RCE (fixed 26.10.1)

Fourth ArcadeDB wave (published 2026-10-21T03:32Z, CVE-2026-114056–114058/114059). Same product keeps yielding the same invariant family — **authorization checks live in the HTTP layer while Bolt/gRPC/WS handlers re-implement access independently**:

| Advisory | Failed binding | Operator probe |
| --- | --- | --- |
| [GHSA-vp2h-6426-v5wh](https://github.com/advisories/GHSA-vp2h-6426-v5wh) | `SHOW DATABASES` over the **Bolt port** for a single-database user reveals all database names | credentials to one tenant DB ⇒ enumerate other tenant/project identifiers; run the enum battery per-protocol, not just HTTP |
| [GHSA-7762-mmrx-x9p5](https://github.com/advisories/GHSA-7762-mmrx-x9p5) | read-only user alters edge-type `lightweight`/`unique` schema flags via bare `ALTER TYPE ... WITH` with no `UPDATE_SCHEMA` check — over HTTP, gRPC, **or Bolt** | schema mutation persistence without schema permission; compare per-protocol decisions on the same statement |
| [GHSA-2mgh-5pqv-xpqq](https://github.com/advisories/GHSA-2mgh-5pqv-xpqq) | `GremlinQueryEngine.command()` lacks scripting authorization: **reader-role** users execute Groovy (`POST /api/v1/command/{database}` when the Groovy engine is enabled) ⇒ OS commands as the server user | the script-engine route family is the escalation pivot; fingerprint enabled engines (Gremlin/Groovy/JS) then run the reader-role command battery |

Rules reinforced: multi-protocol databases need per-protocol authz decision tables (this page's Aug 2 MCP-principal leg was the same defect on a third transport); *read-only* role names do not imply no script-engine access — enumerate query engines exposed through the command API and test lowest-tier roles on each. Lab-only: fake multi-database fixture, reader-role canary user, inert Groovy marker (`touch` in temp), never OS-level payloads.
