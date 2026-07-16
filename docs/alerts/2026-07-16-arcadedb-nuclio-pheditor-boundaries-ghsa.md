# ArcadeDB, Nuclio, and Pheditor control-boundary checks

Sources: hourly offensive-security scan, 2026-07-16 GitHub Security Advisory updates. Primary entries: [GHSA-x9f9-r4m8-9xc2](https://github.com/advisories/GHSA-x9f9-r4m8-9xc2), [GHSA-48qw-824m-86pr](https://github.com/advisories/GHSA-48qw-824m-86pr), [GHSA-vg6x-6pg9-6qwg](https://github.com/advisories/GHSA-vg6x-6pg9-6qwg), [GHSA-8w86-m9h8-hvqg](https://github.com/advisories/GHSA-8w86-m9h8-hvqg), [GHSA-3v79-m2cg-89ww](https://github.com/advisories/GHSA-3v79-m2cg-89ww), [GHSA-wpcj-rmv4-86qg](https://github.com/advisories/GHSA-wpcj-rmv4-86qg), [GHSA-p4h7-p9rj-2pq2](https://github.com/advisories/GHSA-p4h7-p9rj-2pq2), [GHSA-9643-6xjp-vx57](https://github.com/advisories/GHSA-9643-6xjp-vx57), and [GHSA-wg4w-wr5q-6vjc](https://github.com/advisories/GHSA-wg4w-wr5q-6vjc).

This batch is durable for operators because it exposes reusable boundaries across database scripting/import surfaces, serverless build control planes, and web-based file editors: low-privilege roles reaching host-aware interpreters, import sources crossing into SSRF or local files, unauthenticated function-build APIs writing outside their workspace, template-rendered build configuration becoming executable code, and prefix-based terminal allowlists reaching a shell.

!!! warning "Authorized validation only"
    Keep proofs to disposable ArcadeDB databases, Nuclio lab dashboards, Pheditor test installs, owned callbacks, fake credentials, synthetic files, and inert marker commands. Do not read real host secrets, query metadata services, write outside disposable temp paths, modify production schemas, run web shells, alter live functions, or publish weaponized payload strings.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-x9f9-r4m8-9xc2](https://github.com/advisories/GHSA-x9f9-r4m8-9xc2) | ArcadeDB engine before `26.7.2` | Trigger scripting allowed broad Java host interop for users with schema-update rights | Validate whether database-admin-but-not-security-admin roles can cross from trigger definitions into host command execution in a lab. |
| [GHSA-48qw-824m-86pr](https://github.com/advisories/GHSA-48qw-824m-86pr) | ArcadeDB server before `26.7.1` | Read-only database users could reach JavaScript command execution and host file reads | Test script-language command paths as role-boundary checks, proving only with synthetic canary files. |
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
3. For script-language checks, avoid host secret reads and process-control payloads. Use a synthetic file placed by the tester under a temp directory and prove only that the vulnerable role can or cannot read that canary.
4. For trigger checks, use an inert command marker such as writing a nonce to a disposable temp path in a lab. Do not place payloads in production triggers or fire triggers against customer records.
5. For schema mutation checks, create a throwaway type/property and attempt harmless rename or property-flag changes with the low-privilege token. Immediately drop the disposable object in the lab.
6. For `IMPORT DATABASE`, use an owned callback endpoint and a synthetic local file under an allowlisted temp directory. Do not target cloud metadata, loopback admin panels, configuration directories, keys, or unrelated filesystem paths.
7. Repeat every probe against a patched version and an admin-only positive control so the report shows role drift rather than generic database reachability.

Report ArcadeDB findings as **database role -> script/import/schema feature -> host, network, or schema side effect outside documented permission boundary**. Evidence should include role names, endpoint family, version, canary-only outputs, and negative controls.

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

## Operator checklist

- [ ] Which identity or role crosses the boundary: read-only database user, schema admin, unauthenticated dashboard caller, default web-editor user, or terminal-enabled account?
- [ ] Is the proof reduced to a canary file, owned callback, marker command, synthetic schema object, or build log nonce?
- [ ] Does a patched negative control block the same request shape?
- [ ] Are dangerous locations explicitly avoided: service-account tokens, cloud metadata, production config, web roots, cron paths, customer records, and live function artifacts?
- [ ] Can the report distinguish source facts from lab observations without publishing weaponized strings?

## Reporting notes

- Lead with the trust boundary and precondition, not exploit spectacle: database role, dashboard auth mode, web-editor credential state, or shell-wrapper design.
- Preserve route names, versions, role matrices, and marker evidence. Redact hostnames, tokens, session cookies, tenant names, and filesystem layouts that reveal sensitive deployments.
- For multi-advisory clusters, group findings by reusable invariant: host-aware interpreter exposure, import source validation, build metadata execution, path confinement, or shell allowlist bypass.
