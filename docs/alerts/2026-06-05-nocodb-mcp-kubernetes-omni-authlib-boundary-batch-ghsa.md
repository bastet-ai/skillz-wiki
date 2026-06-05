# NocoDB, MCP Kubernetes, Omni, Authlib, and runtime boundary batch

Source: GitHub Security Advisories REST API, published/updated 2026-06-05.

This batch is durable because the advisories map to reusable offensive testing patterns: **public low-code shared views exposing hidden data**, **formula builders crossing into SQL syntax**, **MCP log/tool prompt injection crossing into privileged Kubernetes client flags**, **control-plane readers crossing into cluster CA material**, **same-host API path traversal**, **OAuth cached-state CSRF**, and **WASI sandbox permission mismatches**. Use these workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **NocoDB public shared-view hidden-column exposure** — [GHSA-4w6r-5c2j-qf5f](https://github.com/advisories/GHSA-4w6r-5c2j-qf5f) / CVE-2026-47378 and [GHSA-9wgh-m22w-9xj8](https://github.com/advisories/GHSA-9wgh-m22w-9xj8) / CVE-2026-47279: NocoDB public shared-view endpoints accepted caller-controlled grouping, filtering, sorting, relation, and LTAR column IDs without consistently restricting them to visible view columns. A holder of a shared-view UUID could directly enumerate hidden values, infer hidden values through row counts, or read hidden relation links.
- **NocoDB cross-workspace integration connection test** — [GHSA-96fh-m4r8-6v9v](https://github.com/advisories/GHSA-96fh-m4r8-6v9v) / CVE-2026-47381: the `testConnection` path fetched integrations in a bypass scope and accepted a caller who had owner/creator role on any base in any workspace, letting one workspace drive another workspace's integration/database credentials through connection testing.
- **NocoDB Postgres formula SQL injection** — [GHSA-cxv7-gmmp-228p](https://github.com/advisories/GHSA-cxv7-gmmp-228p) / CVE-2026-47375: an authenticated user with `columnAdd` permission on a Postgres-backed base could supply an unrestricted `ARRAYSORT(..., direction)` value that became a raw `ORDER BY` fragment during formula column creation and later reads.
- **NocoDB shared-view timing oracle** — [GHSA-qhxg-623c-cfjm](https://github.com/advisories/GHSA-qhxg-623c-cfjm) / CVE-2026-47379: legacy plaintext shared-view passwords used strict equality comparison, leaking length and prefix through response timing. Treat this as a lab-only timing validation pattern unless the engagement explicitly permits timing-oracle testing.
- **MCP Server Kubernetes `kubectl_generic` flag injection** — [GHSA-6mx4-4h42-r8vh](https://github.com/advisories/GHSA-6mx4-4h42-r8vh) / CVE-2026-47250: `mcp-server-kubernetes` accepted arbitrary `kubectl` flags/args in the generic tool. A low-privileged actor who can plant instructions into pod logs can cause an AI/operator workflow to run `kubectl` with attacker-controlled `--server` and `--insecure-skip-tls-verify`, making privileged kubeconfig bearer tokens leave the intended API-server boundary.
- **Omni imported-cluster CA secret read** — [GHSA-wv8c-6mx2-xf4j](https://github.com/advisories/GHSA-wv8c-6mx2-xf4j) / CVE-2026-45726: Reader-level Omni users could retrieve `ImportedClusterSecrets` for imported Talos clusters whose secrets were not rotated, exposing Kubernetes, Talos, etcd, and service-account CA material.
- **Omni image-factory same-host path traversal** — [GHSA-c66c-vq6w-fvh5](https://github.com/advisories/GHSA-c66c-vq6w-fvh5) / CVE-2026-45723: `CreateSchematic` embedded caller-controlled `talos_version` into an image-factory path, allowing authenticated Operators to traverse to unintended paths on the configured image-factory host and receive reflected error-body content.
- **Authlib cached OAuth state CSRF** — [GHSA-jj8c-mmj3-mmgv](https://github.com/advisories/GHSA-jj8c-mmj3-mmgv) / CVE-2026-41425: integrations using the `cache` parameter stored OAuth state without tying the callback to the same browser/session that initiated the flow, enabling account-linking CSRF where the victim completes an attacker-started OAuth redirect.
- **changedetection.io decorator-order authentication bypass** — [GHSA-jmrh-xmgh-x9j4](https://github.com/advisories/GHSA-jmrh-xmgh-x9j4) / CVE-2026-35490: multiple Flask routes placed `@login_optionally_required` outside `@blueprint.route()`, so Flask registered the undecorated function. Backup routes could be reached without a session when the rest of the application required login.
- **wasmtime-wasi `path_open(TRUNCATE)` permission mismatch** — [GHSA-2r75-cxrj-cmph](https://github.com/advisories/GHSA-2r75-cxrj-cmph) / CVE-2026-47261: embeddings that preopen directories with mutate permission but `FilePerms::READ` could allow guest WASI code to truncate files using `OpenFlags::TRUNCATE` without the write permission check firing.

## Operator triage

1. Search for NocoDB assets with public shared views, password-protected shared views, multi-workspace tenancy, Postgres bases, formula-column creation by non-admin creators, and integration connection-test features.
2. Prioritize NocoDB shared views where the shared UUID is exposed in tickets, docs, browser history, analytics, or public pages; the advisory impact starts from possession of the UUID, not full application authentication.
3. Search Kubernetes automation stacks for `mcp-server-kubernetes` and any agent/tooling that exposes a generic `kubectl` wrapper to LLM instructions, chatops, runbook agents, or log-summarization flows.
4. Search Omni deployments for imported Talos clusters, Reader accounts, and private image-factory integrations. Prioritize environments where Kubernetes/Talos APIs are reachable from the tester's network segment.
5. Search Python OAuth clients using Authlib integrations with cache-backed state storage. Prioritize account-linking, SSO connect, and “connect provider” flows where a victim can be induced to visit a callback URL.
6. Search changedetection.io targets for backup management routes and decorator-order mistakes in custom Flask blueprints.
7. Search Rust/Wasm platforms for `wasmtime-wasi` embeddings that intentionally expose read-only file content while still granting directory mutate permissions.

## Replayable validation boundaries

### NocoDB public shared-view hidden data proof

Use only a lab base or an approved non-production shared view with marker-only data.

1. Create a NocoDB table with visible columns and a hidden marker column or hidden LTAR relation containing a unique value such as `skillz-hidden-marker-<date>`.
2. Publish a shared view that hides the marker column/relation and capture the shared-view UUID from the normal URL.
3. Call the public shared-view row, group, filter, sort, and relation endpoints with the hidden column name or column ID. For LTAR, test the documented relation paths: many-to-many, has-many, link/one-to-many, and nested picker routes.
4. Vulnerable result: hidden marker values appear directly, relation records are returned, or row-count changes disclose the hidden marker through a boolean filter.
5. Capture the shared-view configuration, route, column visibility state, request, version, and marker-only response. Do not enumerate real customer data.

### NocoDB cross-workspace integration proof

1. In a lab with two workspaces, create a low-privileged creator/owner account in workspace A and a non-private integration in workspace B.
2. From workspace A, submit the connection-test request while supplying the workspace B integration ID.
3. Use an inert test database or a canary integration endpoint that logs only a benign connection attempt.
4. Vulnerable result: the connection test reaches or drives workspace B's integration instead of rejecting the workspace mismatch.
5. Capture workspace IDs, caller role, integration ID provenance, request path, and canary connection evidence.

### NocoDB Postgres `ARRAYSORT` formula proof

Keep the proof non-destructive and bounded to a fixture table.

1. Confirm the base uses Postgres and the tester has `columnAdd` permission.
2. Create a formula column using `ARRAYSORT()` where the optional direction argument contains a harmless SQL-shape canary, such as a benign constant subselect or query-comment marker, rather than data extraction or destructive SQL.
3. Read the formula column while logging generated SQL or measuring only a controlled fixture behavior.
4. Vulnerable result: the direction argument is embedded as SQL syntax in the generated `ORDER BY` fragment.
5. Capture the formula expression, generated SQL excerpt, affected NocoDB version, database backend, and controlled fixture result.

### MCP Kubernetes flag-injection canary

Never exfiltrate a real kubeconfig token. Use a disposable kubeconfig with a fake bearer token and a local HTTPS listener.

1. Configure a lab `mcp-server-kubernetes` instance with a kubeconfig whose bearer token is an inert marker.
2. Start a controlled HTTPS listener with a self-signed certificate.
3. Invoke the generic kubectl tool with flags equivalent to `--server=https://127.0.0.1:<port>` and `--insecure-skip-tls-verify=true`.
4. Vulnerable result: the listener receives a Kubernetes API request carrying the inert `Authorization: Bearer <marker>` header.
5. For indirect-prompt testing, plant only an inert JSON/log instruction in a lab pod log and verify whether the agent proposes or executes the dangerous flag combination. Stop before real cluster credentials are in play.

### Omni imported-cluster CA read proof

1. Use a lab Omni deployment with an imported Talos cluster and deliberately generated disposable CA material.
2. Authenticate as a Reader-level user.
3. Request the `ImportedClusterSecrets` resource through the ResourceService path used by the deployment.
4. Vulnerable result: the Reader receives CA private-key material or enough bundle data to mint cluster credentials.
5. Capture resource type, caller role, imported-cluster state, version, and redacted marker-only CA fingerprint. Do not store or publish real private keys.

### Omni image-factory path traversal proof

1. Configure a lab Omni instance against a controlled image-factory host that returns distinct marker error bodies for safe paths.
2. Authenticate as an Operator.
3. Call `CreateSchematic` with `talos_version` values containing traversal prefixes that should resolve outside `/version/<talos>/overlays/official` but remain on the same host.
4. Vulnerable result: Omni requests the unintended path and reflects the controlled marker error body.
5. Capture the supplied `talos_version`, resulting image-factory path, response body marker, and version.

### Authlib cached-state CSRF proof

1. In a lab integration using Authlib with cache-backed OAuth state, start an attacker-controlled OAuth authorization flow and pause before following the callback URL.
2. Deliver only the generated callback URL to a separate victim browser/session that is logged into the target application.
3. Complete the callback in the victim session.
4. Vulnerable result: the victim's local account is linked to, or authenticated through, the attacker's upstream OAuth identity because the cached state was not bound to the initiating browser/session.
5. Capture state storage mode, integration framework, callback request IDs, and account-linking result. Do not target real user accounts.

### changedetection.io route decorator-order proof

1. In a lab instance with password/login enabled, verify protected routes redirect to `/login` without a session.
2. Request backup-management routes without cookies, including backup request, backup listing, and backup download paths.
3. Vulnerable result: a backup route returns 200/302 to the backup workflow rather than redirecting to login, or permits marker backup download without a session.
4. Capture route, status code, redirect target, affected version, and marker-only backup filename. Do not download production backups.

### wasmtime-wasi truncate-permission proof

1. Build a tiny lab embedding that preopens a directory with `DirPerms::READ | DirPerms::MUTATE` and `FilePerms::READ`, then creates a marker file inside it.
2. Run a guest module that opens the marker with `OpenFlags::TRUNCATE`/`OFLAGS_TRUNC` and read-only descriptor rights.
3. Vulnerable result: the marker file length changes even though write file permission was not granted.
4. Capture the embedding permission tuple, guest call, file length before/after, and `wasmtime-wasi` version.

## Reporting heuristics

- Frame NocoDB findings around **low-code view/integration/formula trust boundaries**. The strongest evidence is a hidden marker crossing a public shared-view boundary, a workspace-B integration driven from workspace A, or user-controlled formula syntax reaching Postgres SQL.
- Frame MCP Kubernetes findings as **agent tool argument allowlist failure plus credential-boundary impact**. Do not include real tokens; inert bearer-marker capture is sufficient.
- Frame Omni findings as **control-plane role/resource boundary** or **same-host server-side path traversal**. Separate Reader CA-material impact from Operator image-factory path probing.
- Frame Authlib findings as **OAuth state not bound to the initiating client when cached**. Evidence should show account linking or login confusion in a lab, not phishing copy.
- Frame changedetection.io findings as **Flask route registration bypassing auth decorators**. Show a protected baseline route and a vulnerable route side by side.
- Frame wasmtime-wasi findings as **sandbox policy mismatch** for embeddings, not a generic Wasmtime CLI issue. Record whether the host actually uses the affected preopen permission combination.

## Sources

- GitHub Advisory Database: [GHSA-4w6r-5c2j-qf5f / CVE-2026-47378](https://github.com/advisories/GHSA-4w6r-5c2j-qf5f)
- GitHub Advisory Database: [GHSA-9wgh-m22w-9xj8 / CVE-2026-47279](https://github.com/advisories/GHSA-9wgh-m22w-9xj8)
- GitHub Advisory Database: [GHSA-96fh-m4r8-6v9v / CVE-2026-47381](https://github.com/advisories/GHSA-96fh-m4r8-6v9v)
- GitHub Advisory Database: [GHSA-cxv7-gmmp-228p / CVE-2026-47375](https://github.com/advisories/GHSA-cxv7-gmmp-228p)
- GitHub Advisory Database: [GHSA-qhxg-623c-cfjm / CVE-2026-47379](https://github.com/advisories/GHSA-qhxg-623c-cfjm)
- GitHub Advisory Database: [GHSA-6mx4-4h42-r8vh / CVE-2026-47250](https://github.com/advisories/GHSA-6mx4-4h42-r8vh)
- GitHub Advisory Database: [GHSA-wv8c-6mx2-xf4j / CVE-2026-45726](https://github.com/advisories/GHSA-wv8c-6mx2-xf4j)
- GitHub Advisory Database: [GHSA-c66c-vq6w-fvh5 / CVE-2026-45723](https://github.com/advisories/GHSA-c66c-vq6w-fvh5)
- GitHub Advisory Database: [GHSA-jj8c-mmj3-mmgv / CVE-2026-41425](https://github.com/advisories/GHSA-jj8c-mmj3-mmgv)
- GitHub Advisory Database: [GHSA-jmrh-xmgh-x9j4 / CVE-2026-35490](https://github.com/advisories/GHSA-jmrh-xmgh-x9j4)
- GitHub Advisory Database: [GHSA-2r75-cxrj-cmph / CVE-2026-47261](https://github.com/advisories/GHSA-2r75-cxrj-cmph)
- NocoDB advisories/source: <https://github.com/nocodb/nocodb/security/advisories> and <https://github.com/nocodb/nocodb>
- MCP Server Kubernetes advisory/source: <https://github.com/Flux159/mcp-server-kubernetes/security/advisories> and <https://github.com/Flux159/mcp-server-kubernetes>
- Omni advisories/source: <https://github.com/siderolabs/omni/security/advisories> and <https://github.com/siderolabs/omni>
- Authlib advisories/source: <https://github.com/lepture/authlib/security/advisories> and <https://github.com/lepture/authlib>
- changedetection.io advisories/source: <https://github.com/dgtlmoon/changedetection.io/security/advisories> and <https://github.com/dgtlmoon/changedetection.io>
- Wasmtime advisories/source: <https://github.com/bytecodealliance/wasmtime/security/advisories> and <https://github.com/bytecodealliance/wasmtime>
