# 2026-02-05 — Payload CMS Drizzle adapter: SQL injection in JSON/RichText queries (GHSA-xx6w-jxg9-2wh8)

GitHub published an advisory for **`@payloadcms/drizzle`** (Payload CMS Drizzle-based DB adapters) describing a **critical SQL injection** issue when querying **JSON** or **RichText** fields.

- Advisory: <https://github.com/advisories/GHSA-xx6w-jxg9-2wh8>

## Why this matters (durable guidance)

This is a common, high-impact class of bug in “query builder” layers:

- user input (filters/search/sort) is accepted via an API
- the backend translates those filters into SQL
- special field types (JSON, rich text, full-text search, “contains”, etc.) get *custom SQL fragments*
- one missing parameterization/escaping step becomes **SQL injection**

Even when you believe “only authenticated users can query”, check for:

- public/unauth endpoints that expose read access (including “preview”, “search”, “list”, and GraphQL)
- overly permissive `access.read` policies
- multi-tenant / multi-role deployments (one compromised low-priv account can become a full data breach)

## Impact (per advisory)

- Blind SQL injection → **data extraction** (e.g., emails, password reset tokens)
- **Account takeover** without password cracking (via reset-token theft)

## Affected conditions (per advisory)

You’re affected if all of the following are true:

1. Payload version **< 3.73.0**
2. Using the Drizzle-based adapter (`@payloadcms/drizzle`) and one of:
   - `@payloadcms/db-postgres`
   - `@payloadcms/db-vercel-postgres`
   - `@payloadcms/db-sqlite`
   - `@payloadcms/db-d1-sqlite`
3. You have at least one accessible collection with a `json` or `richText` field where `access.read` is not `false`

Not affected (per advisory): Mongo adapter (`@payloadcms/db-mongodb`).

## Mitigation

- **Upgrade Payload to v3.73.0+** (fix).

### Temporary mitigation (if you cannot upgrade immediately)

- Set `access: { read: () => false }` on all **JSON** and **RichText** fields.

### Defense-in-depth checks (recommended)

- Confirm your DB user permissions are least-privilege (no superuser / no write perms for read-only APIs).
- Add monitoring for suspicious query patterns at the app layer (unexpected operators, repeated time-based probes).
- Rate-limit and/or require auth for high-cardinality query endpoints (search/list APIs are common abuse paths).

## References

- <https://github.com/advisories/GHSA-xx6w-jxg9-2wh8>
- <https://github.com/payloadcms/payload/security/advisories/GHSA-xx6w-jxg9-2wh8>
