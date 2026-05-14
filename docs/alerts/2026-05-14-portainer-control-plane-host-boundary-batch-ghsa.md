# Portainer control-plane and host-boundary batch (GHSA)

Source: GitHub Security Advisories updated 2026-05-14.

Portainer sits between regular users and Docker/Kubernetes hosts, so every proxy route is a control-plane boundary. This batch is durable because it shows the same mistakes across auth middleware, Docker proxy handlers, stack Git imports, archive restore, and token transport: one missing `return`, unchecked alternate request fields, or symlink-following file read can turn delegated environment access into cluster, host, or secret compromise.

## Advisories covered

- **Docker plugin endpoint authorization bypass to host RCE** — [GHSA-rrmm-9v76-h3p4](https://github.com/advisories/GHSA-rrmm-9v76-h3p4), CVE-2026-44848: Docker `/plugins/*` proxy routes lacked Portainer RBAC handlers, allowing endpoint users to install/enable root-running Docker plugins. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Swarm service endpoint-security bypass** — [GHSA-5fxq-qcf3-244w](https://github.com/advisories/GHSA-5fxq-qcf3-244w), CVE-2026-44849: Swarm service create/update paths did not apply endpoint restrictions for capabilities, sysctls, security options, and related privileged settings. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Kubernetes middleware authorization fall-through** — [GHSA-mgq6-4x29-88r3](https://github.com/advisories/GHSA-mgq6-4x29-88r3), CVE-2026-44882: token validation wrote `403` but continued into the handler, forwarding Kubernetes requests that should have stopped. Fixed in `2.33.8`.
- **Bind-mount restriction bypass via `HostConfig.Mounts`** — [GHSA-7fw3-x4r2-g7wc](https://github.com/advisories/GHSA-7fw3-x4r2-g7wc), CVE-2026-44850: non-admin container creation blocked legacy `HostConfig.Binds` but not equivalent `HostConfig.Mounts`. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Git symlink arbitrary file read in stack auto-update** — [GHSA-rpgq-m5fp-32wr](https://github.com/advisories/GHSA-rpgq-m5fp-32wr), CVE-2026-44881: Git-backed stacks could make the compose file a symlink to host files read by Portainer. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Backup archive path traversal arbitrary file write** — [GHSA-m8fg-67j7-cx4v](https://github.com/advisories/GHSA-m8fg-67j7-cx4v), CVE-2026-44885: tar extraction joined paths without a final containment check, letting crafted backups write outside the restore root. Fixed in `2.39.0` and later; `2.33.8` also carries the LTS fix.
- **JWT accepted in URL query leaks tokens** — [GHSA-jvp4-q659-95mj](https://github.com/advisories/GHSA-jvp4-q659-95mj), CVE-2026-44883: `?token=<JWT>` worked on authenticated API routes and could leak through logs, browser history, and `Referer`. Fixed in `2.33.8`, `2.39.2`, and `2.41.0`.
- **Custom-template file missing authorization** — [GHSA-cqpq-2fgr-8mvc](https://github.com/advisories/GHSA-cqpq-2fgr-8mvc), CVE-2026-44884: authenticated users could enumerate custom-template file IDs and read template contents. Fixed in `2.33.8` and `2.39.1`; `2.40.0+` is not affected.

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
