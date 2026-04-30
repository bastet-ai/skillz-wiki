# CKAN DataStore SQL search unauthenticated SQL injection and authorization bypass (GHSA-h7j7-3rx6-xvcg / CVE-2026-42031)

**Signal:** GitHub Security Advisories published **2026-04-29** and **2026-04-30**. CKAN fixed unauthenticated `datastore_search_sql` injection and authorization-bypass paths that can expose private resources and PostgreSQL system information when SQL search is enabled.

## What it is
`datastore_search_sql` accepted attacker-controlled SQL in a path that could bypass intended resource authorization. The vulnerable feature is disabled by default, but many CKAN deployments enable it for DataStore-backed querying.

Affected package: pip `ckan`. Fixed versions: `2.10.10` and `2.11.5`. The later authorization-bypass advisory is tracked as `GHSA-cg4x-64p3-x59h` / CVE-2026-42032 and shares the same emergency control: disable DataStore SQL search if not patched.

References: <https://github.com/advisories/GHSA-h7j7-3rx6-xvcg>, <https://github.com/advisories/GHSA-cg4x-64p3-x59h>

## Triage
1. Inventory CKAN portals and confirm whether `ckan.datastore.sqlsearch.enabled` is true.
2. Identify internet-exposed instances with DataStore enabled and private datasets/resources.
3. Review access logs for unauthenticated or low-privilege calls to `datastore_search_sql`, especially queries touching PostgreSQL catalogs or private resource IDs.

## Mitigation
- Upgrade CKAN to `2.10.10`, `2.11.5`, or later.
- Until patched, set `ckan.datastore.sqlsearch.enabled = false`.
- Treat private dataset metadata and DataStore contents as potentially exposed if SQL search was enabled on a public instance.

## Detection ideas
- Search web/proxy logs for `datastore_search_sql` requests containing `pg_catalog`, `information_schema`, `UNION`, comments, or resource IDs outside the caller's expected access.
- Compare suspicious query timestamps with downloads or API reads against private resources.

## Durable lesson
Optional query features are still attack surface. If a product documents a feature as “not designed to prevent all abuse,” expose it only behind authentication, least-privilege resource checks, and query-shaping controls.
