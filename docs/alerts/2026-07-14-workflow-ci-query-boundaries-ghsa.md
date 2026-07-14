# n8n-MCP backup, Woodpecker agent/Kubernetes identity, and Anyquery server-mode file-write checks

Source: hourly offensive-security scan, 2026-07-14 GitHub advisory wave. Primary entries: [GHSA-j6r7-6fhx-77wx](https://github.com/advisories/GHSA-j6r7-6fhx-77wx), [GHSA-2cf7-hpwf-47h9](https://github.com/advisories/GHSA-2cf7-hpwf-47h9) / CVE-2026-55608, [GHSA-g7mm-9vx7-jm7h](https://github.com/advisories/GHSA-g7mm-9vx7-jm7h), [GHSA-qf34-295c-26v8](https://github.com/advisories/GHSA-qf34-295c-26v8) / CVE-2026-61549, and [GHSA-xrcf-6jh3-ggvx](https://github.com/advisories/GHSA-xrcf-6jh3-ggvx).

This batch is durable because each advisory exposes a reusable operator boundary: multi-tenant workflow backup storage that is not scoped to the tenant or default/single-tenant migration scope, CI agent identity derived from client-supplied gRPC metadata after JWT verification, repository-controlled Kubernetes backend options crossing into pod service-account identity, and a SQL-compatible server path where unauthenticated SQL can invoke SQLite disk features that write outside the intended query surface.

!!! warning "Authorized validation only"
    Keep proofs to disposable multi-tenant workflow labs, throwaway CI agents, local gRPC harnesses, disposable Kubernetes namespaces, and temporary Anyquery server instances. Use synthetic workflow nodes, fake credential references, inert agent IDs, marker-only pipeline jobs, low-privilege test service accounts, disposable SQLite files, and temporary directories. Do not read production workflow snapshots, credential bodies, authorization headers, CI secrets, build logs, source repositories, deployment keys, Kubernetes Secrets, service-account tokens, user workflows, real databases, cron paths, shell startup files, web roots, or service configuration files.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-j6r7-6fhx-77wx](https://github.com/advisories/GHSA-j6r7-6fhx-77wx) | `n8n-mcp` multi-tenant HTTP mode | Workflow version-history backups are stored/read without tenant isolation | Add backup/version-history object-scope tests to MCP and workflow-automation assessments. |
| [GHSA-2cf7-hpwf-47h9](https://github.com/advisories/GHSA-2cf7-hpwf-47h9) / CVE-2026-55608 | `n8n-mcp` multi-tenant HTTP mode | Tenant-scoped requests can reach local default-scope workflow-version backups left from single-tenant or migration state | Extend backup tests to default-scope leftovers, not only another active tenant. |
| [GHSA-g7mm-9vx7-jm7h](https://github.com/advisories/GHSA-g7mm-9vx7-jm7h) | Woodpecker CI gRPC agent layer | Server verifies an agent JWT, then trusts caller-controlled `agent_id` metadata | Test verified-identity vs client-metadata confusion in CI/CD and agent control planes. |
| [GHSA-qf34-295c-26v8](https://github.com/advisories/GHSA-qf34-295c-26v8) / CVE-2026-61549 | Woodpecker CI Kubernetes backend | Pipeline `backend_options.kubernetes.serviceAccountName` is copied into the pod spec without admin gating | Add repository-to-pod-identity checks for CI runners on Kubernetes. |
| [GHSA-xrcf-6jh3-ggvx](https://github.com/advisories/GHSA-xrcf-6jh3-ggvx) | Anyquery `server` mode | MySQL-compatible listener forwards SQLite `ATTACH DATABASE` disk-write primitives | Add unauthenticated SQL-to-filesystem boundary checks to exposed data-query services. |

## Replayable validation boundaries

### n8n-MCP workflow backup tenant-scope proof

1. Stand up `n8n-mcp` in HTTP mode with multi-tenancy enabled and only two disposable tenants: Tenant A and Tenant B.
2. Under Tenant B, create or update a workflow that produces an automatic version-history snapshot containing only canary node names such as `N8N-MCP-TENANT-B-BACKUP-CANARY` and fake credential references like `cred-ref-canary`, not real tokens.
3. Authenticate as Tenant A and enumerate only the documented or observed version-history/backup routes needed to locate snapshots.
4. Record whether Tenant A can list, read, delete, or destroy Tenant B's backup snapshot, and separately whether either tenant can reach default-scope snapshots left from a previous single-tenant run or migration.
5. Add controls for normal Tenant B access, unauthenticated access, a nonexistent tenant ID, an empty default-scope backup directory, a patched build, and non-version-history workflow routes.

Report this as **tenant-controlled backup selector -> missing tenant scope on workflow version history -> cross-tenant workflow snapshot read/delete**. Strong evidence is a route/status/object-owner table plus the synthetic canary node name; do not include workflow bodies that contain secrets or real authorization headers.

### Woodpecker CI gRPC agent metadata impersonation

1. Build a lab Woodpecker server with two disposable agents: `agent-a` and `agent-b`. Give each only marker metadata and jobs that print inert strings such as `WOODPECKER-AGENT-CANARY`.
2. Authenticate as `agent-a` with its normal JWT or lab token and capture the baseline gRPC metadata the agent sends.
3. Replay a minimal gRPC call that preserves `agent-a`'s verified token but supplies `agent-b` in the client-controlled `agent_id` metadata field.
4. Observe whether the server attributes the request, polling state, logs, or job execution to `agent-b` despite the token belonging to `agent-a`.
5. Add controls for invalid JWTs, omitted `agent_id`, mismatched nonexistent agent IDs, patched server behavior, and an admin/API path that independently resolves the verified agent identity.

Report this as **verified agent token -> client-supplied gRPC metadata overrides identity -> cross-agent impersonation**. Keep captures to metadata key names, agent IDs from a lab, status codes, and marker job IDs; never route production jobs or collect CI secrets.

### Woodpecker CI Kubernetes `serviceAccountName` escalation

1. Run Woodpecker with the Kubernetes backend in a disposable namespace containing only two service accounts: a default low-privilege account and a canary account with permission to read a synthetic ConfigMap, not Secrets.
2. Give a test repository user only the normal push permission needed to run pipelines.
3. Commit a pipeline that sets `backend_options.kubernetes.serviceAccountName` to the canary service account and runs a marker job that checks only for the synthetic ConfigMap permission.
4. Record whether the resulting pod spec uses the requested service account and whether the marker permission is available inside the job.
5. Add controls for omitted `serviceAccountName`, a nonexistent service account, a patched Woodpecker build, admission policies that deny unexpected service accounts, and a namespace with no privileged service accounts.

Report this as **repository pipeline config -> Kubernetes backend option -> pod service-account identity / RBAC boundary**. Do not mount or read real service-account tokens, Kubernetes Secrets, cluster-admin roles, production namespaces, or deployment keys.

### Anyquery server-mode SQLite disk-write proof

1. Start Anyquery in `server` mode on a local lab host or approved test network with an empty profile and a service account that can write only to a temporary directory.
2. Create a target canary path under a disposable directory, for example `/tmp/anyquery-server-mode-canary/attached.db`. Confirm it does not exist before the test.
3. Connect to the MySQL-compatible listener from an unauthenticated client if the lab reproduces the vulnerable exposure.
4. Submit a bounded `ATTACH DATABASE` proof that asks SQLite to create a database at the canary path, then immediately detach it. Do not write to startup paths, web roots, cron directories, home directories, application data, or existing databases.
5. Verify only that the marker SQLite file was created by the Anyquery process and record the listener exposure, process user, and filesystem permissions.
6. Add controls for localhost-only binding, authenticated wrappers, patched server behavior, read-only filesystems, and denied paths outside the disposable temp directory.

Report this as **network SQL listener -> native SQLite disk primitive exposed -> arbitrary file creation within process write permissions**. Avoid claiming RCE unless a separate, authorized lab proves a safe marker-only execution chain; the durable finding is the server-mode SQL-to-filesystem boundary.

## Reporting notes

- Lead with preconditions: multi-tenant `n8n-mcp` HTTP mode, who can authenticate as a tenant, whether workflow version history is enabled, whether default-scope backups exist from prior operation, Woodpecker agent registration/trust model, agent token provenance, Kubernetes backend namespace/RBAC layout, Anyquery listener bind address, and the Anyquery process write scope.
- Prefer decision tables over payload dumps: actor, tenant/agent identity, supplied object or metadata ID, verified identity, requested service account, expected owner/RBAC check, observed owner/effect, marker object, and patched control.
- Redact workflow JSON bodies, credential references from real tenants, authorization headers, gRPC tokens, CI logs with secrets, repository names from customer environments, SQL payload details beyond grammar shape, filesystem paths outside disposable labs, and any file content not created solely as a canary.
- The same scan included CISA KEV entries for Microsoft ADFS and SharePoint plus low-signal updates for weak hashes and Concrete CMS deserialization. They were not promoted here because the available summaries did not add a safe, replayable offensive workflow beyond existing authorization and deserialization testing patterns.
