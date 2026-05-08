# Query and data-pipeline SQL-boundary batch

**Signal:** The **2026-05-08 22:15 UTC** advisory scan added SQL construction failures in application search/aggregate APIs and data-pipeline I/O managers.

## Advisory cluster

- **Daptin aggregate raw SQL injection** — [GHSA-rw2c-8rfq-gwfv](https://github.com/advisories/GHSA-rw2c-8rfq-gwfv): `github.com/daptin/daptin <0.11.4` accepted `column` and `group` query parameters on `/aggregate/:typename` and passed them into `goqu.L()` raw SQL expressions. Any authenticated session could inject arbitrary expressions under the application's database privileges.
- **Dagster dynamic partition SQL injection** — [GHSA-mjw2-v2hm-wj34](https://github.com/advisories/GHSA-mjw2-v2hm-wj34): `dagster <=1.13.0` and related DuckDB, Snowflake, BigQuery, and DeltaLake I/O manager packages `<=0.29.0` interpolated dynamic partition key values into SQL `WHERE` clauses without escaping.

## Why this matters

Column names, group keys, and partition labels are not data once they are spliced into SQL grammar. They become query structure. Parameter binding does not save code paths that intentionally drop user strings into raw identifier/expression positions.

## Triage

1. Patch Daptin to a fixed release beyond the affected `0.11.x` range and patch Dagster / I/O manager packages once upstream fixed versions are available.
2. Search for Daptin aggregate and fuzzy-search exposure to low-privilege or self-registered users.
3. In Dagster, inventory jobs using dynamic partitions with DuckDB, Snowflake, BigQuery, or DeltaLake I/O managers; restrict `Add Dynamic Partitions` to trusted operators.
4. Hunt database logs for injected expressions in Daptin `column` / `group` parameters and suspicious partition keys containing quotes, comments, parentheses, semicolons, or SQL keywords.
5. Rotate database credentials if low-privilege app users could reach query APIs backed by broad database roles.

## Durable controls

- Use allowlisted identifier maps for columns, grouping fields, table names, and partition-derived query fragments.
- Keep raw-SQL literal helpers (`goqu.L`, string-formatted `WHERE`, manual SQL fragments) behind security review gates.
- Give app and pipeline database credentials least-privilege views, not whole-database read/write authority.
- Treat metadata written by users or operators as untrusted until it has passed grammar-specific validation.
