# n8n XML prototype-pollution RCE, Python sandbox escape, credential replay, and chat/MCP exposure batch (GHSA-q5f4-99jv-pgg5 / GHSA-hqr4-h3xv-9m3r / GHSA-44v6-jhgm-p3m4 / GHSA-r4v6-9fqc-w5jr / GHSA-537j-gqpc-p7fq / GHSA-49m9-pgww-9vq6 / GHSA-756q-gq9h-fp22 / GHSA-f77h-j2v7-g6mw)

**Signal:** GitHub Security Advisories published **2026-04-29**. n8n fixed a second late-April batch affecting workflow execution, XML parsing, MCP OAuth, dynamic credential resolution, public API variables, and Hosted Chat WebSockets.

## What it is
The highest-risk issues are execution and credential-boundary failures:

- `GHSA-q5f4-99jv-pgg5` / `CVE-2026-42231`: XML webhook body parsing can trigger prototype pollution and chain to RCE through Git node SSH operations.
- `GHSA-hqr4-h3xv-9m3r` / `CVE-2026-42232`: the XML node can trigger global prototype pollution and RCE when chained with other nodes.
- `GHSA-44v6-jhgm-p3m4` / `CVE-2026-42234`: Python Code node task-runner sandbox escape, where Python Task Runner is enabled.
- `GHSA-r4v6-9fqc-w5jr` / `CVE-2026-42226`: `dynamic-node-parameters` can use a foreign credential ID and replay another user's API key to attacker-controlled infrastructure.
- `GHSA-537j-gqpc-p7fq` / `CVE-2026-42235`: MCP OAuth client name XSS can execute script in an authenticated user's browser session.
- `GHSA-49m9-pgww-9vq6` / `CVE-2026-42236`: unauthenticated MCP client registration can exhaust memory, even when MCP access is disabled.
- `GHSA-756q-gq9h-fp22` / `CVE-2026-42227`: public API variables IDOR can disclose variables across projects.
- `GHSA-f77h-j2v7-g6mw` / `CVE-2026-42228`: unauthenticated Hosted Chat WebSocket clients can hijack waiting chat executions if execution IDs are known.

Affected package: npm `n8n`. Fixed versions vary by line, but the recurring fixed set is `1.123.32`, `2.17.4`, and `2.18.1`; the dynamic credential replay issue is fixed in `1.123.33` and `2.17.5`/`2.18.0+`.

References:

- <https://github.com/advisories/GHSA-q5f4-99jv-pgg5>
- <https://github.com/advisories/GHSA-hqr4-h3xv-9m3r>
- <https://github.com/advisories/GHSA-44v6-jhgm-p3m4>
- <https://github.com/advisories/GHSA-r4v6-9fqc-w5jr>
- <https://github.com/advisories/GHSA-537j-gqpc-p7fq>
- <https://github.com/advisories/GHSA-49m9-pgww-9vq6>
- <https://github.com/advisories/GHSA-756q-gq9h-fp22>
- <https://github.com/advisories/GHSA-f77h-j2v7-g6mw>

## Triage
1. Inventory internet-exposed n8n and record release line, workflow authors, Python Task Runner status, MCP status, Hosted Chat workflows, and public API usage.
2. Treat workflow authorship as privileged code execution until patched; identify users who can create, import, or edit workflows.
3. Search workflows for XML Webhook/XML nodes, Git nodes, Python Code nodes, dynamic credential lookups, MCP OAuth, variables, and Chat Trigger nodes with authentication set to `None`.
4. Review whether variables contain secrets; if they do, assume cross-project read exposure for vulnerable enterprise/team deployments.
5. Identify shared or high-privilege credentials that may have been reachable through dynamic node parameter helpers.

## Mitigation
- Upgrade to a fixed version for the deployed release line; prefer the latest patched n8n release.
- Until upgraded, limit workflow create/edit/import rights to fully trusted users only.
- Disable XML and Python Code nodes where not required (`NODES_EXCLUDE`), or disable Python Task Runner entirely.
- Restrict network access to n8n, especially MCP OAuth registration and public Hosted Chat endpoints.
- Disable MCP server functionality if unused, and reduce `N8N_PAYLOAD_SIZE_LIMIT` to bound registration payload abuse.
- Require authentication on Chat Trigger nodes; do not expose unauthenticated waiting executions.
- Rotate any credentials or variables that could have been exposed or replayed.

## Detection ideas
- Hunt for workflows created or edited shortly before unexpected Git/SSH operations, Python task-runner activity, or outbound requests to unfamiliar hosts.
- Review request logs for XML payloads containing prototype-pollution keys such as `__proto__`, `constructor`, or `prototype`.
- Look for `dynamic-node-parameters` requests where a user supplied credential IDs outside their expected workflow/project ownership.
- Check MCP registration volume, unusually large OAuth client metadata, and stored `client_name` values with script-like content.
- Review Hosted Chat WebSocket connections for multiple clients attached to the same waiting execution.

## Durable lesson
Automation platforms combine user-controlled configuration, credentials, network egress, and code-like nodes. Patch quickly, but also design the deployment so workflow authorship, connector credentials, and unauthenticated triggers each have narrow blast radius.
