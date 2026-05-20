# Tomcat, Rclone, Mako, and ML runtime-boundary batch

Source: GitHub Security Advisories, updated 2026-05-20:
[GHSA-24j9-x2wg-9qv6](https://github.com/advisories/GHSA-24j9-x2wg-9qv6),
[GHSA-x5gf-qvw8-r2rm](https://github.com/advisories/GHSA-x5gf-qvw8-r2rm),
[GHSA-jfwf-28xr-xw6q](https://github.com/advisories/GHSA-jfwf-28xr-xw6q),
[GHSA-v92g-xgxw-vvmm](https://github.com/advisories/GHSA-v92g-xgxw-vvmm), and
[GHSA-rvhj-8chj-8v3c](https://github.com/advisories/GHSA-rvhj-8chj-8v3c).

This batch is durable because it clusters around boundary assumptions that operators often delegate to framework defaults: mutual-TLS failure semantics, unauthenticated control APIs, template path normalization, shell command construction around model serving, and regex complexity in process-manager config parsing.

## What changed

- **CLIENT_CERT soft-fail semantics can become an auth gap:** Apache Tomcat FFM-backed CLIENT_CERT authentication did not fail as expected in some scenarios when soft fail was disabled. Affected `org.apache.tomcat:tomcat-coyote-ffm` trains are `9.0.92` through `9.0.116`, `10.1.22` through `10.1.53`, and `11.0.0-M14` through `11.0.20`; fixed versions are `9.0.117+`, `10.1.54+`, and `11.0.21+`.
- **Rclone RC can instantiate attacker-controlled backends:** `operations/fsinfo` lacked `AuthRequired: true` while accepting attacker-controlled `fs` input. In reachable unauthenticated RC deployments, inline WebDAV backend definitions can trigger `bearer_token_command` during initialization, producing single-request local command execution. Upgrade `github.com/rclone/rclone` to `1.73.5+` and remove unauthenticated RC exposure.
- **Template path canonicalization must match every caller:** Mako `TemplateLookup.get_template()` stripped all leading slashes while `Template.__init__` stripped only one. A URI like `//../../../secret.txt` could bypass traversal checks and read process-readable files when untrusted input reached `get_template()` directly. Upgrade `Mako` to `1.3.11+`.
- **Model-serving helpers are command boundaries:** MLflow serving with `enable_mlserver=True` embedded `model_uri` into a `bash -c` command without proper sanitization. Shell metacharacters in model paths can execute commands, especially where a privileged service serves models from a lower-privileged writable location. Upgrade `mlflow` to `3.9.0+`.
- **Config parsers still need resource limits:** `pm2` before `7.0.0` contains an inefficient regular-expression path in `lib/tools/Config.js`. Even low-severity ReDoS in process-control tooling can matter when config parsing is exposed through deployment, dashboard, or automation surfaces.

## Operator triage

1. **Patch exposed auth and control planes first.** Prioritize Tomcat services relying on client certificates and any `rclone rc` or `rclone rcd` endpoint that is reachable beyond localhost.
2. **Find unauthenticated Rclone RC deployments.** Inventory `--rc`, `rclone rcd`, `--rc-addr`, and missing `--rc-user` / `--rc-pass` / `--rc-htpasswd` controls. Treat internet- or LAN-reachable unauthenticated RC as compromised until logs and process history say otherwise.
3. **Review template lookup call sites.** Search for direct `TemplateLookup.get_template(user_input)` or URI routing that bypasses HTTP servers known to normalize double-slash prefixes. Patch Mako and add app-level allowlists for template names.
4. **Separate model authors from model servers.** If lower-privileged users can write model directories or registry entries consumed by a higher-privileged MLflow service, rotate credentials and inspect model-serving logs for shell metacharacters, unexpected child processes, or modified startup scripts.
5. **Constrain automation/config ingestion.** Upgrade `pm2` to `7.0.0+`, then rate-limit and size-limit any path that parses user-controlled process config.

## Replayable validation boundaries

- **Tomcat CLIENT_CERT negative test:** present no certificate, an invalid certificate, and a revoked/untrusted certificate through the exact production connector stack; expected result is failure before application code or session creation.
- **Rclone RC auth test:** call `operations/fsinfo` without global RC credentials from every reachable network zone; expected result is authentication failure, not backend initialization.
- **Rclone command canary:** in a disposable lab only, verify patched RC rejects inline backend options that would execute `bearer_token_command`; production detection should rely on logs/process telemetry, not exploit replay.
- **Mako traversal corpus:** feed `//../`, mixed-slash, URL-decoded, and normalized path variants into every template lookup wrapper; expected result is canonical rejection or lookup inside an allowlisted template root.
- **MLflow shell-metacharacter test:** serve a benign model path containing `$()`, backticks, semicolons, and spaces in a non-production environment; expected result is literal argument handling or rejection with no shell execution.
- **pm2 parser resource test:** parse oversized and regex-worst-case config values under CPU/time limits; expected result is bounded failure and no process-manager stall.

## Durable controls

- Treat mTLS and CLIENT_CERT behavior as a testable security contract; negative certificate cases belong in release and proxy-chain smoke tests.
- Never expose control APIs without global authentication, even if individual handlers are supposed to mark `AuthRequired` correctly.
- Normalize paths once, at the boundary, then pass structured template identifiers instead of raw URIs to render APIs.
- Build shell-free model-serving paths: pass arguments as arrays, avoid `bash -c`, and isolate model-writable locations from serving identities.
- Put CPU, input-size, and timeout limits around config parsing and orchestration surfaces, not just public HTTP handlers.
