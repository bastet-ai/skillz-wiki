# Flowise RCE, secret, and tenant-boundary batch

Source: GitHub Security Advisories updated 2026-05-14.

This Flowise batch is durable because it shows the same failure pattern across agent platforms: authenticated users, API keys, tools, and workspace-scoped objects were treated as already-trusted after login. For workflow builders, every custom-code endpoint, MCP command field, credential API, and update body is still a security boundary.

## Advisories covered

- **Credential encrypted-data leak** — [GHSA-7g73-99r4-m4mj](https://github.com/advisories/GHSA-7g73-99r4-m4mj): filtered credential lookup responses could include `encryptedData`. Affects npm `flowise <= 3.1.1`; fixed in **3.1.2**.
- **Authenticated custom-function host RCE** — [GHSA-9rvc-vf7m-pgm2](https://github.com/advisories/GHSA-9rvc-vf7m-pgm2): `POST /api/v1/node-custom-function` lacked route-level authorization and could execute attacker JavaScript; common deployments without E2B fell back to escapable `NodeVM`, reaching host command execution. Affects `flowise <= 3.1.1`; fixed in **3.1.2**.
- **MCP command security bypass to RCE** — [GHSA-m99r-2hxc-cp3q](https://github.com/advisories/GHSA-m99r-2hxc-cp3q): Custom MCP Server command validation could be bypassed, including `docker build` style execution paths. Affects `flowise` and `flowise-components <= 3.1.1`; fixed in **3.1.2**.
- **Basic-auth credential exposure/bruteforce surface** — [GHSA-php6-83fg-gw3g](https://github.com/advisories/GHSA-php6-83fg-gw3g): API handling around basic-auth checks exposed a weak plaintext credential comparison surface without adequate throttling. Affects `flowise <= 3.1.1`; fixed in **3.1.2**.
- **Workspace mass assignment** — [GHSA-5wxp-qjgq-fx6m](https://github.com/advisories/GHSA-5wxp-qjgq-fx6m), [GHSA-hp26-q66v-q2w7](https://github.com/advisories/GHSA-hp26-q66v-q2w7), [GHSA-x5v6-pj28-cwwm](https://github.com/advisories/GHSA-x5v6-pj28-cwwm), [GHSA-6fw7-3q8r-m5vj](https://github.com/advisories/GHSA-6fw7-3q8r-m5vj): chatflow, assistant, tool, and variable update endpoints accepted server-controlled fields such as `workspaceId`, `createdDate`, `updatedDate`, deployment state, or visibility, enabling cross-workspace reassignment or tenant-boundary breakage. Affects `flowise <= 3.1.1`; fixed in **3.1.2**.

## Operator triage

1. Upgrade Flowise and `flowise-components` to **3.1.2+** before exposing instances to shared users or API keys.
2. Treat any Flowise instance with untrusted authenticated users as potentially host-compromised if custom functions or MCP servers were enabled. Review process, container, Docker, and outbound network telemetry.
3. Rotate Flowise credentials, workspace secrets, model/provider keys, MCP tokens, and any secrets stored in Flowise credential records if filtered credential APIs were reachable.
4. Review audit logs and database history for changed `workspaceId`, `isPublic`, `deployed`, `createdDate`, or `updatedDate` fields on chatflows, assistants, tools, and variables.
5. Restrict Flowise egress and Docker/socket access. A workflow builder should not be able to reach the Docker daemon, metadata services, internal admin panels, or arbitrary outbound hosts by default.

## Durable controls

- Route-level authorization must be explicit on every execution-capable endpoint; authentication alone is not authorization.
- Do not expose raw custom JavaScript execution to shared tenants unless it runs in a separately isolated worker with no host, Docker, filesystem, or secret-store authority.
- MCP command allowlists should be positive allowlists over exact binaries and argument schemas. Blocklists miss subcommands like build, plugin, helper, or remote-fetch execution paths.
- Response serializers should deny secret fields by default, including filtered/search/list variants. Add tests proving `encryptedData`, API keys, hashes, and tokens never leave the trusted service boundary.
- Update endpoints should map request bodies onto explicit DTOs. Server-controlled fields such as tenant/workspace IDs, ownership, visibility, timestamps, deployment flags, and credential references must be derived server-side and re-authorized per object.
- Multi-workspace products need object-level authorization on both the object ID and the target workspace ID. A valid object update is not valid if the tenant relationship changes.
