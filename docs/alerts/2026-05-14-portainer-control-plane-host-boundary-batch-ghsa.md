# Portainer control-plane and host-boundary batch (GHSA)

Source: GitHub Security Advisories updated 2026-05-14.

Portainer sits between regular users and Docker/Kubernetes hosts, so every proxy route is a control-plane boundary. This batch is durable because it shows the same mistakes across auth middleware, Docker proxy handlers, stack Git imports, archive restore, and token transport: one missing `return`, unchecked alternate request fields, or symlink-following file read can turn delegated environment access into cluster, host, or secret compromise.

## Advisories covered

- **Docker plugin endpoint authorization bypass to host RCE**, [GHSA-rrmm-9v76-h3p4](https://github.com/advisories/GHSA-rrmm-9v76-h3p4), CVE-2026-44848: Docker `/plugins/*` proxy routes lacked Portainer RBAC handlers, allowing endpoint users to install/enable root-running Docker plugins. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Swarm service endpoint-security bypass**, [GHSA-5fxq-qcf3-244w](https://github.com/advisories/GHSA-5fxq-qcf3-244w), CVE-2026-44849: Swarm service create/update paths did not apply endpoint restrictions for capabilities, sysctls, security options, and related privileged settings. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Kubernetes middleware authorization fall-through**, [GHSA-mgq6-4x29-88r3](https://github.com/advisories/GHSA-mgq6-4x29-88r3), CVE-2026-44882: token validation wrote `403` but continued into the handler, forwarding Kubernetes requests that should have stopped. Fixed in `2.33.8`.
- **Bind-mount restriction bypass via `HostConfig.Mounts`**, [GHSA-7fw3-x4r2-g7wc](https://github.com/advisories/GHSA-7fw3-x4r2-g7wc), CVE-2026-44850: non-admin container creation blocked legacy `HostConfig.Binds` but not equivalent `HostConfig.Mounts`. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Git symlink arbitrary file read in stack auto-update**, [GHSA-rpgq-m5fp-32wr](https://github.com/advisories/GHSA-rpgq-m5fp-32wr), CVE-2026-44881: Git-backed stacks could make the compose file a symlink to host files read by Portainer. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Backup archive path traversal arbitrary file write**, [GHSA-m8fg-67j7-cx4v](https://github.com/advisories/GHSA-m8fg-67j7-cx4v), CVE-2026-44885: tar extraction joined paths without a final containment check, letting crafted backups write outside the restore root. Fixed in `2.39.0` and later; `2.33.8` also carries the LTS fix.
- **JWT accepted in URL query leaks tokens**, [GHSA-jvp4-q659-95mj](https://github.com/advisories/GHSA-jvp4-q659-95mj), CVE-2026-44883: `?token=<JWT>` worked on authenticated API routes and could leak through logs, browser history, and `Referer`. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Custom-template file missing authorization**, [GHSA-cqpq-2fgr-8mvc](https://github.com/advisories/GHSA-cqpq-2fgr-8mvc), CVE-2026-44884: authenticated users could enumerate custom-template file IDs and read template contents. Fixed in `2.33.8` and `2.39.1`; `2.40.0+` is not affected.
- **Docker proxy path-normalization authorization bypass**, [GHSA-588v-59vc-3xh9](https://github.com/advisories/GHSA-588v-59vc-3xh9), CVE-2026-72533: an August 11 unreviewed record reports that non-canonical proxy paths can be authorized under one route identity and forwarded to Docker under another through CE 2.44.0. Confirm affected/fixed builds before reporting.

## Operator triage

1. Patch Portainer CE/BE/EE to the fixed line that matches your deployment. Treat Docker and Kubernetes endpoints managed by vulnerable Portainer instances as exposed to any user with endpoint access.
2. Rotate Portainer JWTs and review reverse-proxy, application, audit, and browser-support logs for `?token=` URLs before retention overwrites them.
3. Hunt Portainer audit/API logs for `/plugins/`, `/services/create`, `/services/*/update`, `/containers/create`, `/api/stacks/*/file`, backup restore, and Kubernetes proxy requests by non-admin users.
4. Inspect recent Git-backed stacks for symlinked compose files or unexpected auto-update repository changes. Preserve the cloned repo and Portainer data directory if host file reads are suspected.
5. Review Docker hosts for unexpected plugins, privileged Swarm services, bind mounts to sensitive host paths, and backup restore artifacts outside the Portainer data directory.
6. Assume custom templates may have leaked embedded secrets; rotate registry credentials, connection strings, API keys, and tokens found in templates.

## Durable controls

- Register explicit authorization handlers for every proxied daemon API route; unknown routes should fail closed, not pass through.
- Validate all semantically equivalent Docker fields (`Binds`, `Mounts`, Swarm task mounts, capabilities, sysctls, seccomp/AppArmor) through one normalized policy model.
- After writing an error response in middleware, terminate control flow and test that denied requests cannot reach downstream handlers.
- Treat Git repositories and backup archives as hostile filesystems: reject symlink entrypoints, canonicalize after checkout/extraction, and require final realpath containment before reading or writing.
- Never accept bearer tokens in URLs. Use headers or short-lived, purpose-scoped WebSocket/session tokens that are not logged by default.

## August 11 proxy canonicalization follow-up

Run Portainer and a fake Docker API in an isolated lab. Give a low-privilege user access only to harmless status routes, then replace Docker dispatch with a recorder that returns no daemon data. Generate raw path pairs covering dot segments, repeated and encoded separators, percent-decoding order, mixed slash forms where the stack accepts them, path parameters, and double decoding. Preserve the raw request target, each middleware's route identity, normalized upstream path, matched RBAC rule, and denied backend operation.

A bounded positive is **low-privilege request -> authorization evaluates benign route A -> proxy normalization forwards privileged route B to the denied fake-Docker sink**. A changed status code or parser discrepancy alone is insufficient. Never create a container, mount the host, access the Docker socket outside the fake backend, or claim host root without the exact privileged operation and endpoint binding.

## August 30 follow-up: unauthenticated `/api/restore` admin takeover on the initialization window

- **Unauthenticated restore endpoint → admin takeover**, [GHSA-x626-fcwx-f5pc / CVE-2026-55761](https://github.com/advisories/GHSA-x626-fcwx-f5pc), high, 5.9. Portainer's `POST /api/restore` is *intentionally* unauthenticated so the instance can be restored before the first admin account exists, and it stays reachable for the **five-minute initialization window that opens on every startup**. An unauthenticated attacker with network access to a not-yet-initialised instance can POST a crafted backup archive containing attacker-controlled credentials and replace the Portainer database, gaining full administrative access. The same unauthenticated window also exposes the admin-account-creation endpoint (`/api/users/admin/...`). Fixed in `2.39.4` and `2.43.0` (affected `>= 2.39.0, < 2.39.4` and `>= 2.40.0, < 2.43.0`).

Durable heuristic: this is the **init-window / pre-bootstrap endpoint** class, a route that is unauthenticated *by design* during first-run and then gated afterward. The operator check is to confirm whether the instance has completed initialization and whether the bootstrap/restore/admin-create routes are actually closed afterward. On a target, the question is timing: is the instance inside the init window, and does the restore endpoint authenticate once an admin exists? This pairs with the existing backup-archive path-traversal write finding above: the same archive-restore surface that can write files outside the root can also wholesale replace the credential store when unauthenticated.

Replayable validation (lab only): a lab Portainer in the affected range, deliberately left uninitialised.

1. Baseline: with no admin created, confirm `POST /api/restore` is reachable unauthenticated (negative control is the same route returning 401 after an admin exists).
2. Craft a minimal backup archive that seeds a canary admin credential; POST it to `/api/restore`.
3. Positive: the canary credential is accepted at login, proving the unauthenticated restore replaced the database. Stop there, do not exfiltrate a real database, do not create a real admin on a managed host, and do not target production.
4. Negative control on `2.39.4` / `2.43.0`: the endpoint requires authentication or the init window is closed.

