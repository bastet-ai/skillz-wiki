# n8n database node SQL injection and MCP OAuth redirect batch (GHSA-mp4j-h6gh-f6mp / GHSA-r6jc-mpqw-m755 / GHSA-hp3c-vfpm-q4f7 / GHSA-f6x8-65q6-j9m9)

**Signal:** GitHub Security Advisories published **2026-04-29**. n8n released fixes for multiple workflow-node SQL injection issues and an MCP OAuth consent-flow open redirect.

## What it is
The advisories cover medium-severity but operationally important n8n surfaces:

- `GHSA-mp4j-h6gh-f6mp` / `CVE-2026-42229`: SQL injection in the SeaTable node.
- `GHSA-r6jc-mpqw-m755` / `CVE-2026-42233`: SQL injection in the Oracle Database node via the limit field.
- `GHSA-hp3c-vfpm-q4f7` / `CVE-2026-42237`: SQL injection in Snowflake and legacy MySQL v1 nodes when user-controlled expressions reach identifier fields such as table name, column name, or update key.
- `GHSA-f6x8-65q6-j9m9` / `CVE-2026-42230`: open redirect in the MCP OAuth consent flow.

Affected package: npm `n8n`. Fixed versions include `1.123.32`, `2.17.4`, and `2.18.1` depending on release line.

References:

- <https://github.com/advisories/GHSA-mp4j-h6gh-f6mp>
- <https://github.com/advisories/GHSA-r6jc-mpqw-m755>
- <https://github.com/advisories/GHSA-hp3c-vfpm-q4f7>
- <https://github.com/advisories/GHSA-f6x8-65q6-j9m9>

## Triage
1. Inventory n8n instances and note whether users can create or import workflows.
2. Search workflows for SeaTable, Oracle Database, Snowflake, and MySQL nodes, especially where node parameters are populated from webhook, chat, form, or external trigger data.
3. For `GHSA-hp3c-vfpm-q4f7`, specifically check Snowflake and legacy MySQL v1 nodes for expressions in identifier-like fields: table name, column name, and update key. Treat those fields as SQL structure, not values.
4. Identify database credentials with broad read/write privileges or access to production data.
5. Check whether MCP OAuth is enabled and whether redirect targets are logged.

## Mitigation
- Upgrade to a fixed n8n version for your release line. For the Snowflake/MySQL follow-up advisory, patched versions are `1.123.32`, `2.17.4`, and `2.18.1`.
- Restrict workflow authoring/import to trusted users and require review for workflows that execute SQL or handle OAuth redirects.
- Migrate legacy MySQL v1 workflows to MySQL v2 where possible; v2 implements identifier escaping for this path.
- If you cannot patch immediately, consider excluding the Snowflake node with `NODES_EXCLUDE=n8n-nodes-base.snowflake` until affected workflows are remediated.
- Use least-privilege database users per workflow; avoid shared admin credentials.
- Validate and bound query parameters before they enter database-node fields such as limits, filters, table names, column names, update keys, and raw expressions.
- Enforce redirect allowlists for OAuth consent and callback flows.

## Detection ideas
- Hunt workflow execution history for SQL metacharacters, stacked queries, comments, unusually large limits, or unexpected table/schema access.
- Review OAuth consent logs for redirects to unapproved domains, punycode lookalikes, or attacker-controlled callback URLs.
- Alert on n8n database credentials querying system catalogs, credential tables, or data outside normal workflow scope.

## Durable lesson
Low-code workflow tools turn configuration fields into execution surfaces. Identifier fields are still SQL inputs, even when they are not value placeholders. Treat workflow authorship like code deployment, and give every connector credential the smallest blast radius possible.
