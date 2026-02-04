# 2026-02-04 — Alist path traversal in file-operation handlers (GHSA-x4q4-7phh-42j9)

**Product:** Alist (go module: `github.com/alist-org/alist/v3`)

## Summary
A GitHub Security Advisory reports that **Alist** had **path traversal** issues across multiple file-operation handlers (remove/copy/rename/batch operations).

- Advisory: <https://github.com/advisories/GHSA-x4q4-7phh-42j9>
- CVE: CVE-2026-25161
- CWE: CWE-22 (Path Traversal)

## Why this matters
Even when you validate the *directory* a user is allowed to operate within, you can still lose isolation if you accept attacker-controlled **file name components** and then do:

- `Join(validatedDir, userSuppliedName)`

…without a final **canonical-path** check.

In multi-tenant / multi-user storage mounts, that becomes cross-user data access or destruction.

## Durable guidance
1. **Validate after join, not before**
   - Build the full path, canonicalize it (`Clean` + resolve symlinks if relevant), then enforce `pathHasPrefix(allowedRoot, candidate)`.

2. **Treat “name” fields as hostile paths**
   - Reject any segment containing `..`, path separators, or percent-encoded separators.
   - Prefer server-side identifiers over client-supplied paths.

3. **Beware of symlinks**
   - If the storage backend can contain symlinks, simple string prefix checks can be bypassed unless you `realpath()`.

## Related Wisdom
- [Archive Extraction: Symlink + Path Traversal](../best-practices/archive-extraction-symlink-traversal.md)

## References
- GitHub Advisory: <https://github.com/advisories/GHSA-x4q4-7phh-42j9>
