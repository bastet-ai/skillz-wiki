# 2026-02-07 — Decidim private data export leak via UUID→integer coercion (GHSA-3cx6-j9j4-54mp / CVE-2025-65017)

**Advisory:** GHSA-3cx6-j9j4-54mp  
**CVE:** CVE-2025-65017  
**Product:** Decidim (Ruby on Rails)  
**Impact:** Exposure of private “download your data” exports to the wrong user (data leak)  
**Severity:** High (per advisory)

## What happened
Decidim’s “Download your data” feature can leak a private export to a different user in some cases.

The root cause described in the advisory is a **type mismatch / coercion bug**: a UUID-like identifier for a `PrivateExport` record ends up being coerced into an integer (e.g., via `to_i`), which can create collisions (multiple UUIDs mapping to the same integer prefix). When that happens, an attachment can be associated with the wrong export record.

This is particularly dangerous in Rails apps when **UUID primary keys** are used but an associated table stores a foreign key as **`bigint`** (or otherwise coerces IDs).

## Who is affected
- Decidim **>= 0.30.0 and < 0.30.4** (per advisory)

## Fix
- **Upgrade Decidim to 0.30.4 or newer**.

## Additional hardening / checks (Rails)
Even outside Decidim, this class of bug is worth hunting for:

1. **Audit ID types across tables**
   - If your model primary keys are `uuid`, ensure join / attachment / foreign key columns are also `uuid`.
   - Watch for places where string IDs are coerced to integers (e.g., `to_i`) or stored in `bigint` columns.

2. **If you use Active Storage with UUID primary keys**
   - Ensure `active_storage_attachments.record_id` matches your application’s PK type.
   - See: [Rails / Active Storage: UUID primary keys must not be stored as bigint](../best-practices/rails-activestorage-uuid-record-id.md)

3. **Add tests for "wrong user got my export" invariants**
   - Any private export/download flow should validate: `current_user.id == export.user_id` **before** serving bytes.

## References
- Advisory: https://github.com/decidim/decidim/security/advisories/GHSA-3cx6-j9j4-54mp
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-65017
