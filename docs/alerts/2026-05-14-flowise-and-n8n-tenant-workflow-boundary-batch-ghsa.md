# Flowise and n8n tenant/workflow boundary batch (GHSA)

Source: GitHub Security Advisories updated 2026-05-14.

Flowise and n8n both expose low-code workflow surfaces where authenticated users can create objects, connect credentials, run nodes, and interact with external systems. This batch is durable because it repeats a hard lesson for automation platforms: authenticated workflow authors are still untrusted tenants, and request bodies, node parameters, OAuth reconnects, source-control pulls, and prototype-bearing JSON/XML all need explicit policy gates.

## Advisories covered

### FlowiseAI tenant isolation

All Flowise items affect `flowise <= 3.1.1` and are fixed in `3.1.2`.

- **Vector-store permission checks missing** — [GHSA-hmg2-jjjx-jcp2](https://github.com/advisories/GHSA-hmg2-jjjx-jcp2): authenticated users could create, update, delete, or modify OpenAI Assistants vector stores without the intended permission checks.
- **Assistant mass assignment** — [GHSA-78pr-c5x5-jggc](https://github.com/advisories/GHSA-78pr-c5x5-jggc): client-controlled fields such as `workspaceId`/`id` could cross workspace boundaries.
- **CustomTemplate mass assignment** — [GHSA-728h-4mwj-f2p4](https://github.com/advisories/GHSA-728h-4mwj-f2p4): marketplace template create/update accepted tenant identity fields from request bodies.
- **Dataset mass assignment** — [GHSA-5h9v-837x-m97r](https://github.com/advisories/GHSA-5h9v-837x-m97r): datasets could be assigned across workspaces.
- **DatasetRow mass assignment** — [GHSA-7j65-65cr-6644](https://github.com/advisories/GHSA-7j65-65cr-6644): row create/update accepted attacker-controlled identity/ownership fields.
- **Evaluation mass assignment** — [GHSA-mq53-pc65-wjc4](https://github.com/advisories/GHSA-mq53-pc65-wjc4): evaluation entities could be taken over cross-workspace.
- **Evaluator mass assignment** — [GHSA-wxrr-jp8m-qq7f](https://github.com/advisories/GHSA-wxrr-jp8m-qq7f): evaluator entities accepted fields that should have been server-owned.

### n8n workflow and credential authority

Affected n8n lines are fixed in `1.123.43`, `2.20.7`, and either `2.21.1` or `2.22.1` depending on the advisory.

- **HTTP Request pagination prototype pollution to RCE** — [GHSA-c8xv-5998-g76h](https://github.com/advisories/GHSA-c8xv-5998-g76h), CVE-2026-44789: workflow editors could pollute prototypes through HTTP Request node pagination parameters, with RCE impact when chained.
- **Git node arbitrary file read** — [GHSA-57g9-58c2-xjg3](https://github.com/advisories/GHSA-57g9-58c2-xjg3), CVE-2026-44790: Git node push parameters could inject CLI flags and read server files. Short-term mitigation: exclude `n8n-nodes-base.git`.
- **XML node prototype-pollution patch bypass** — [GHSA-wrwr-h859-xh2r](https://github.com/advisories/GHSA-wrwr-h859-xh2r), CVE-2026-44791: authenticated workflow authors could bypass an earlier XML-node patch and reach RCE chains. Short-term mitigation: exclude `n8n-nodes-base.xml`.
- **Source Control Pull SQL injection** — [GHSA-mhrx-qhrj-673w](https://github.com/advisories/GHSA-mhrx-qhrj-673w), CVE-2026-44792: malicious Data Table JSON in a connected repository could inject SQL when an administrator pulled source-control changes on PostgreSQL-backed instances.
- **Dynamic credential OAuth reconnect authorization bypass** — [GHSA-6h4j-wcr9-2vg7](https://github.com/advisories/GHSA-6h4j-wcr9-2vg7), CVE-2026-45732: read-only access to a shared credential was enough to start OAuth reconnect and replace stored token material.

## Operator triage

1. Patch Flowise to `3.1.2+` and n8n to a fixed release line immediately for any multi-user or internet-facing deployment.
2. For Flowise, audit assistants, custom templates, datasets, dataset rows, evaluations, evaluators, and vector stores whose `workspaceId`, `id`, `createdDate`, or `updatedDate` changed unexpectedly or points across tenant boundaries.
3. For n8n, restrict workflow creation/editing to trusted users until patched; temporarily exclude the Git, XML, and HTTP Request nodes if those paths are exposed to semi-trusted authors.
4. Rotate OAuth credentials that are shared across users/projects and inspect credential histories for unexpected reconnects or token owner changes.
5. Review source-control repository write access and admin pull events. Treat connected repositories as production change authority, not just configuration.
6. Search logs for `__proto__`, `constructor`, suspicious pagination objects, Git CLI flag injection, XML prototype pollution payloads, and failed or unusual source-control imports.

## Durable controls

- Never use broad `Object.assign(entity, body)` into persisted ORM objects. Allowlist mutable fields and bind tenant/owner identifiers from server-side context after validation.
- Every workflow node parameter that reaches a shell, parser, HTTP client, database, or prototype-bearing object needs schema validation and dangerous-key rejection before execution.
- Credential reconnect/update must require write-level permission and strong audit events; read access to a credential is not consent to replace its token material.
- Source-control imports should parse into an inert model first, validate names and identifiers as data, and only then write to production databases.
- Workflow-builder permissions should separate view, edit, credential-use, credential-update, node-execution, and source-control actions.
