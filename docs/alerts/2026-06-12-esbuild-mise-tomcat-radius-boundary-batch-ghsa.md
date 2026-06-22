# esbuild, mise, Tomcat, Radius, and late TYPO3 boundary checks

Source: hourly offensive-security scan, 2026-06-12, updated 2026-06-22 for the `.tool-versions` mise follow-up. Primary entries: GitHub advisories [GHSA-gv7w-rqvm-qjhr](https://github.com/advisories/GHSA-gv7w-rqvm-qjhr), [GHSA-g7r4-m6w7-qqqr](https://github.com/advisories/GHSA-g7r4-m6w7-qqqr), [GHSA-fjj5-v948-whjj](https://github.com/advisories/GHSA-fjj5-v948-whjj) / CVE-2026-33646, [GHSA-436v-8fw5-4mj8](https://github.com/advisories/GHSA-436v-8fw5-4mj8) / CVE-2026-35533, [GHSA-fpj8-gq4v-p354](https://github.com/advisories/GHSA-fpj8-gq4v-p354) / CVE-2025-66614, [GHSA-fp5j-4fj2-4jvq](https://github.com/advisories/GHSA-fp5j-4fj2-4jvq) / CVE-2026-53999, and late TYPO3 advisories [GHSA-pjpj-v387-x4vq](https://github.com/advisories/GHSA-pjpj-v387-x4vq) / CVE-2026-11607, [GHSA-jh32-v29g-68pq](https://github.com/advisories/GHSA-jh32-v29g-68pq) / CVE-2026-49741, [GHSA-hwvq-2w67-rvxp](https://github.com/advisories/GHSA-hwvq-2w67-rvxp) / CVE-2026-47346, [GHSA-3v8v-4wg6-r7qh](https://github.com/advisories/GHSA-3v8v-4wg6-r7qh) / CVE-2026-47343, [GHSA-f34x-rx2w-7pm3](https://github.com/advisories/GHSA-f34x-rx2w-7pm3) / CVE-2026-47349, [GHSA-qcmw-6rm2-5x78](https://github.com/advisories/GHSA-qcmw-6rm2-5x78) / CVE-2026-47350, and [GHSA-3p42-w5ch-gg42](https://github.com/advisories/GHSA-3p42-w5ch-gg42) / CVE-2026-47347.

This batch is durable because each item exposes a reusable operator boundary: build tooling that converts registry environment variables into executable native binaries, developer servers that normalize paths differently from their host OS, repository-local tool config that can approve its own trust state, TLS SNI/HTTP `Host` split-brain authentication, Kubernetes controller confused-deputy deletes across tenants, and TYPO3 backend permissions crossing into SQL-capable form definitions or unauthorized record/file operations.

## What changed

- **esbuild Deno binary integrity boundary** — the Deno module fetched native binaries from `NPM_CONFIG_REGISTRY` and wrote executable files without the SHA-256 integrity checks used by the Node installer path. This is a CI, shared dev-host, and private-registry trust boundary, not a generic browser issue.
- **esbuild Windows dev-server file boundary** — the development server used POSIX-style `path.Clean()` on request paths while Windows treats backslashes as path separators, enabling traversal out of `servedir` on affected Windows hosts.
- **mise project-local trust boundary** — local `.mise.toml` settings could be loaded before trust checks, allowing repository-controlled settings such as `trusted_config_paths = ["/"]` to make that same untrusted project config appear trusted and reach hooks, tasks, templates, or `[env] _.source`. A June 22 follow-up adds a separate `.tool-versions` parser boundary where Tera template rendering, including `exec()`, ran without a trust prompt in non-paranoid mode.
- **Tomcat connector mTLS virtual-host boundary** — when client certificate authentication was enforced only at the connector, Tomcat virtual hosts with different TLS requirements could be confused by sending one host in TLS SNI and another in the HTTP `Host` header.
- **Radius controller confused-deputy boundary** — in multi-tenant installs, a tampered `radapp.io/status` Deployment annotation could cause the controller to delete a container resource referenced under another tenant/resource group using controller privileges.
- **TYPO3 form, file-mount, and record-control follow-up wave** — late TYPO3 advisories add Form Framework extension/case bypasses that can reach SQL-capable form definitions, direct `DataHandler` writes to `form_definition`, unauthorized record moves/restores, destructive operations on file-mount roots, and a core utility open-redirect boundary.

## Operator triage

1. **Lead with preconditions.** esbuild requires Deno module execution plus registry/environment influence; the file-read variant is Windows dev-server only; mise requires a repo or working tree the tester can place files in and a shell/editor/CI path that invokes mise hooks or parsing; Tomcat requires connector-level client cert auth and multiple virtual hosts with different requirements; Radius is strongest in multi-tenant controller topologies; TYPO3 requires backend roles, file-write, module, or table-write access.
2. **Separate proof of boundary from destructive impact.** A downloaded inert binary canary, file-read marker, hook marker, mTLS route differential, synthetic Radius container ID, or disposable TYPO3 form definition is enough. Do not execute production payloads, read secrets, delete real tenant resources, or create real admin accounts.
3. **Favor environment and parser-differential evidence.** Capture the exact environment variable, path separator, trust setting, SNI/Host pair, Kubernetes annotation field, or TYPO3 module/table/extension check that made the boundary fail.

## Replayable validation boundaries

### esbuild registry-to-executable validation

- Scope only CI runners, build images, or developer hosts where running the esbuild Deno module is authorized.
- Set `NPM_CONFIG_REGISTRY` to a tester-controlled local registry or HTTP callback that serves an inert tarball matching the expected package path and platform name.
- Positive proof is that the Deno installer downloads from the canary registry and writes/attempts to execute a tester-owned marker binary without an integrity mismatch.
- Keep the binary inert: print a marker, write a disposable file under a temp directory, or exit with a unique code. Do not run shell download cradles or credential access commands.
- Evidence: esbuild version, Deno invocation, redacted environment, requested registry URL, marker result, and patched `v0.28.1+` negative control.

### esbuild Windows `servedir` traversal validation

- Validate only against a local or lab Windows dev-server instance; do not expose production dev servers to the internet for testing.
- Create a harmless marker file outside `servedir`, then request a URL path containing Windows backslash traversal segments toward that marker.
- Positive proof is retrieval of the marker file and a negative control showing normal forward-slash normalization stays confined.
- Evidence should include OS, esbuild version, `servedir`, sanitized request path, marker file contents, and patched negative behavior.

### mise repository-config trust validation

- Use a disposable repository and a canary `.mise.toml`; avoid testing against developer home directories or repositories with real hooks/secrets.
- Place a local config that sets a trust-expanding setting such as `trusted_config_paths` and an inert `[env] _.source`, hook, task, or template marker.
- Trigger only a safe command path such as `mise hook-env` in a sandboxed shell and confirm whether the marker executes before explicit user trust is granted.
- Evidence: mise version, repository path, `.mise.toml` trust stanza, command used, canary marker, and patched-version behavior.

### mise `.tool-versions` Tera execution validation

- Validate only in a disposable repository and sandbox shell. Do not run this in a real developer checkout, home directory, or environment carrying live cloud, package-registry, SSH-agent, or API credentials.
- Create a `.tool-versions` file with the smallest inert Tera marker that proves template evaluation. Prefer a temp-file marker over network callbacks:

  ```text
  node 20 {{ exec(command="printf skillz-mise-canary > /tmp/skillz-mise-canary") }}
  ```

- Trigger a safe mise parse path such as `mise hook-env` or the same shell activation path the target workflow uses. Avoid package installs, build scripts, or commands that execute project code for unrelated reasons.
- Positive proof is the marker appearing before any explicit trust approval for the repository and without a `.mise.toml` trust prompt. Pair it with a patched-version negative control where possible.
- Evidence: mise version, shell integration path, `.tool-versions` contents, command used, marker file metadata, and confirmation that the repo was untrusted/non-paranoid. Redact environment output; do not demonstrate token access even if the advisory notes inherited environment exposure.

### Tomcat SNI/Host mTLS bypass validation

- Confirm a lab or customer-approved Tomcat deployment has at least two virtual hosts on the same connector: one requiring client certificates and one not, with client certificate auth enforced at the connector rather than inside the web application.
- Send one TLS SNI value for the non-client-cert host and an HTTP `Host` header for the client-cert-protected host. Use an owned route that returns a marker page, not a sensitive application endpoint.
- Positive proof is access to the protected virtual host without presenting a client certificate, paired with controls where matching SNI/Host values behave as expected.
- Evidence: Tomcat version, connector/vhost layout, SNI, `Host`, client-cert presence/absence, marker route status, and patched version negative behavior.

### Radius controller annotation confused-deputy validation

- Validate only in a lab or explicitly approved multi-tenant Radius/Kubernetes environment with disposable tenants, resource groups, Deployments, and container resources.
- Create two synthetic tenants/resources and tamper only the attacker-controlled Deployment's `radapp.io/status` annotation to reference a victim canary container resource.
- Trigger the reconcile/delete flow and verify whether the controller attempts to delete the referenced canary resource.
- Stop at canary deletion/attempt evidence. Do not target production containers, shared namespaces, service accounts, or non-test resource groups.
- Evidence: Radius version, controller scope/RBAC, tenant/resource IDs, sanitized annotation JSON, controller log/API delete attempt, and recovery/cleanup.

### TYPO3 late-wave validation

- For Form Framework extension and `DataHandler` issues, use a disposable backend user and a synthetic form definition that executes only a harmless SQL canary such as creating or updating a marker row in a lab table. Do not create administrative users on production systems.
- For file-mount root operations, prove attempted rename/move/delete only against a disposable mount root in a lab; prefer observing authorization acceptance/rejection rather than performing destructive operations.
- For Recycler and record-move checks, use synthetic pages/tables and marker records where source/target permissions are intentionally split.
- For `sanitizeLocalUrl`, demonstrate only a redirect to a tester-owned URL and never use phishing pages or user-targeted links.
- Evidence should include TYPO3 version, backend role, module/table/file permission, canary object, route/API used, and patched-version negative behavior.

## Reporting heuristics

- Name the crossed trust boundary in the title: `NPM_CONFIG_REGISTRY to native binary execution`, `Windows dev-server backslash traversal`, `repo config self-trust`, `.tool-versions Tera template to shell execution`, `SNI/Host mTLS mismatch`, `Deployment annotation to cross-tenant delete`, or `backend form/file permission to SQL/admin-capable action`.
- Keep impact scoped to the proven precondition. These are strong findings when the report preserves topology and role requirements instead of claiming blanket RCE, auth bypass, or tenant takeover.
- Redact environment values, client cert material, Kubernetes tokens, registry credentials, and application secrets. Canary evidence should be enough.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. PyO3 memory-safety advisories, pypdf resource-consumption items, Tomcat cleanup/input-validation updates unrelated to the SNI/Host client-certificate boundary, and duplicate/adjacent TYPO3 sanitizer XSS entries were tracked but not promoted because they do not add a higher-signal replayable operator workflow than the trust, parser, controller, and backend authorization boundaries above. No new PortSwigger, Trail of Bits, ProjectDiscovery, Disclosed, or CISA KEV item in this hour added additional durable guidance.
