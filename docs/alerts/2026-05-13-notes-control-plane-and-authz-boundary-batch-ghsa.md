# Notes, control-plane, and authorization-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because collaboration and control-plane systems often expose “reader,” “template,” “webhook,” or “backend” features that are assumed to be low-risk. The advisories show those paths can mutate persistent configuration, reach internal services, or bypass object-level authorization.

## Advisories covered

- **SiYuan Bazaar stored XSS to Electron code execution** — [GHSA-27qc-m5gf-jv5r](https://github.com/advisories/GHSA-27qc-m5gf-jv5r): marketplace package `name`/`version` metadata rendered unescaped and could reach Electron execution.
- **SiYuan publish-mode Conf/SQL mutation** — [GHSA-gmmv-4cc5-wr9r](https://github.com/advisories/GHSA-gmmv-4cc5-wr9r): Reader access could mutate configuration and SQL index state through ungated APIs before the fixed kernel build.
- **SiYuan publish-mode search API authorization gaps** — [GHSA-fmh9-gpqh-g53g](https://github.com/advisories/GHSA-fmh9-gpqh-g53g): Reader access could call search endpoints intended for more privileged contexts.
- **SiYuan tag-sort mutation** — [GHSA-6r88-8v7q-q4p2](https://github.com/advisories/GHSA-6r88-8v7q-q4p2): `/api/tag/getTag` could mutate and persist `Conf.Tag.Sort` despite Reader role.
- **SiYuan attribute-view stored XSS to Electron RCE** — [GHSA-2h64-c999-c9r6](https://github.com/advisories/GHSA-2h64-c999-c9r6): attribute-view names could become stored XSS in Electron renderer contexts.
- **Obot MCP connector authorization bypass** — [GHSA-vw82-7fv8-r6gp](https://github.com/advisories/GHSA-vw82-7fv8-r6gp): any authenticated user could use any registered MCP server via `/mcp-connect/{id}` in affected releases.
- **Nautobot writable Git repository head** — [GHSA-p3hx-pwf3-j8wr](https://github.com/advisories/GHSA-p3hx-pwf3-j8wr): `GitRepository.current_head` was writable through REST API.
- **Nautobot webhook SSRF** — [GHSA-c35q-vxrp-ph26](https://github.com/advisories/GHSA-c35q-vxrp-ph26): webhook definitions could reach server-side network destinations.
- **Nautobot bulk-rename ReDoS** — [GHSA-qrpw-gjvh-x5gm](https://github.com/advisories/GHSA-qrpw-gjvh-x5gm): crafted regexes in UI bulk actions could deny service.
- **Nautobot GenericForeignKey reference bypass** — [GHSA-wpxj-44w3-2j6x](https://github.com/advisories/GHSA-wpxj-44w3-2j6x): REST API could create references to objects the user should not be able to reference.
- **Traefik internal REST exposure through Gateway API** — [GHSA-96qj-4jj5-wcjc](https://github.com/advisories/GHSA-96qj-4jj5-wcjc): `TraefikService` backends could expose `rest@internal` despite `providers.rest.insecure=false`.
- **Argo Workflows template authorization** — [GHSA-56px-hm34-xqj5](https://github.com/advisories/GHSA-56px-hm34-xqj5): unauthorized users could access workflow templates before `v3.7.11` / `v4.0.2`.

## Operator triage

1. Patch SiYuan, Obot, Nautobot, Traefik, and Argo if exposed to shared users, publish-mode readers, or cluster tenants.
2. Review audit logs for Reader-role calls to mutation endpoints, unexpected MCP connector IDs, webhook URLs to RFC1918/cloud metadata ranges, and Gateway API references to `*@internal` backends.
3. Re-check object-level authorization on generic foreign keys, templates, webhooks, Git repo sync metadata, and MCP server registration/use.
4. Temporarily disable user-defined webhooks, MCP connectors, and Gateway internal-service references if patching cannot happen immediately.

## Durable controls

- Every control-plane API needs verb-level authorization: “read” endpoints must not mutate persisted sort, search, index, or configuration state.
- Renderer boundaries in desktop/Electron apps need the same stored-XSS discipline as browsers, plus explicit isolation from local code execution primitives.
- Webhook and backend-reference features need egress allowlists, metadata blocking, DNS rebinding defenses, and audit trails.
- Object references should be authorized both when created and when dereferenced; generic relation fields are not exempt from object-scope checks.
