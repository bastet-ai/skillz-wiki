# Note Mark identity, export, and deletion-boundary batch

**Sources:** GHSA-pxf8-6wqm-r6hh / CVE-2026-41571, GHSA-q6mh-rqwh-g786 / CVE-2026-44523, GHSA-g49p-4qxj-88v3 / CVE-2026-44522, GHSA-3gr9-485j-v4xf / CVE-2026-41572

## Why this matters

This Note Mark batch is a compact reminder that auth state, file names, and soft-delete state are all security boundaries. The durable pattern is not unique to Note Mark:

- OIDC-only users must never inherit a password-auth fallback value such as `bcrypt("null")`.
- HMAC JWT secrets must fail startup when decoded key material is shorter than the algorithm requires; HS256 needs at least 32 bytes.
- User-controlled asset names remain dangerous even if exploitation is delayed until an administrator runs an export job.
- Soft-deleted public containers must be excluded in every note/content/asset read path, including raw joins that bypass ORM soft-delete scopes.

## Affected surface

- `github.com/enchant97/note-mark/backend` before patched pseudo-versions around the April/May 2026 fixes.
- Internal password login endpoints for OIDC-created users.
- Deployments using weak or human-chosen `JWT_SECRET` values.
- Asset upload flows that persist the `X-Name` header and later export assets to disk.
- Public books that were soft-deleted while their note IDs, slug paths, or asset URLs remained known.

## Operator triage

1. Upgrade Note Mark to a release containing the four fixes, or consume the patched Go pseudo-versions listed in the advisories.
2. Treat any OIDC user account as exposed if the password endpoint was reachable before patching; revoke sessions and review login telemetry for `password: "null"` attempts.
3. Rotate `JWT_SECRET` from a trusted system and invalidate all existing JWTs if the current secret is shorter than 32 bytes after base64 decoding or was ever logged/shared.
4. Search stored asset names for `/`, `\\`, `%2f`, `%5c`, `..`, absolute paths, shell profile names, cron/systemd paths, and overwritten binary names.
5. If exports ran while malicious asset names existed, inspect the export host for unexpected writes outside the export directory and rebuild from clean media if system paths were touched.
6. Re-check soft-deleted public books by direct note ID, content endpoint, slug URL, and asset URL; all should return a hard deny/404.

## Hunt prompts

- Password logins for users with OIDC identity records and empty password hashes.
- JWT verification failures immediately followed by successful requests for a different user ID.
- Asset upload headers containing traversal sequences or executable/script-like suffixes.
- Export jobs run as root or with host filesystem mounts.
- Reads of notes/assets whose parent book has non-null `deleted_at`.

## Durable controls

- Split account credential families: SSO-only users should have an explicit impossible password state, not a placeholder password.
- Validate cryptographic key length and entropy at config parse time; fail closed rather than warning at runtime.
- Normalize and validate file names at ingress, then re-normalize at each filesystem sink as defense in depth.
- Run export/migration jobs as a constrained user in a scratch directory with no host root write access.
- Add regression tests that assert parent soft-delete predicates are included in every raw SQL join and asset-serving query.
