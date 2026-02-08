# Rails / Active Storage: UUID primary keys must not be stored as bigint

If your Rails app uses **UUID primary keys**, ensure Active Storage (and any other association tables) store foreign keys as **UUID**, not `bigint`.

## Why this matters
Active Storage stores attachments in `active_storage_attachments`. The `record_id` column is the foreign key to the attached record.

If `record_id` is the wrong type (e.g., `bigint`) while your application uses UUIDs, you can get:
- **Runtime coercion** (UUID-like strings becoming integers)
- **Collisions** (different UUIDs mapping to the same integer prefix)
- **Wrong attachment served to the wrong user** (data leak)

This failure mode showed up in the wild (Decidim private exports leak: **CVE-2025-65017**).

## What to check
1. Confirm your app PK type:
   - Are your tables created with `id: :uuid`?

2. Check Active Storage schema:
   - `active_storage_attachments.record_id` should be `uuid`.

Postgres quick check:

```sql
\d active_storage_attachments
```

## How to fix (conceptual)
- Migrate `active_storage_attachments.record_id` to `uuid`.
- Recreate foreign keys / indexes accordingly.
- Validate there is no code path that calls `to_i` (or similar) on record identifiers.

Because schema migrations are app-specific (and may require data backfills), treat this as a planned change:
- snapshot DB
- run migrations in staging
- verify attachments still resolve correctly

## Defense-in-depth
Even with correct types:
- **Authorize before serving** any blob/bytes (don’t rely on obscurity of IDs).
- Add regression tests that assert attachments cannot cross tenant/user boundaries.

## References
- Decidim advisory (CVE-2025-65017): https://github.com/decidim/decidim/security/advisories/GHSA-3cx6-j9j4-54mp
