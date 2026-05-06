# Archive and file-extraction boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced two **astral-tokio-tar** advisories updated on **2026-05-06**.

## Advisories covered

- **`unpack_in` symlink-following chmod outside archive root** — [GHSA-xx64-wwv2-hcqq](https://github.com/advisories/GHSA-xx64-wwv2-hcqq): Rust `astral-tokio-tar <= 0.6.0` could modify permissions of external directories by following symlinks while unpacking. Fixed in `0.6.1`.
- **PAX header desynchronization** — [GHSA-fp55-jw48-c537](https://github.com/advisories/GHSA-fp55-jw48-c537): manipulated PAX headers could make archive entries visible or invisible differently across implementations, enabling unexpected file smuggling. Fixed in `0.6.1`.

## Why this is durable

Archive extraction bugs recur because tar is both a filesystem format and a metadata language. Pathnames, symlinks, hardlinks, permissions, PAX headers, and implementation-specific visibility rules all influence what the extractor writes or mutates.

## Immediate triage

1. Upgrade `astral-tokio-tar` to `0.6.1+` wherever untrusted archives are extracted.
2. Inventory async Rust services that unpack uploads, dependency bundles, backup restores, CI artifacts, templates, or model/dataset packages.
3. Inspect extraction roots for symlinks pointing outside the intended tree before and after unpacking.
4. Compare suspicious archives with multiple tar implementations to detect PAX header desynchronization or hidden/smuggled paths.

## Durable controls

- Extract untrusted archives into empty, private, disposable directories on isolated filesystems.
- Resolve paths relative to an opened extraction root; never follow symlinks for metadata changes such as `chmod`, `chown`, or xattrs.
- Apply permissions after verifying the final inode is inside the extraction tree and is the expected file type.
- Normalize and audit PAX headers before extraction, and reject duplicate/conflicting metadata that can desynchronize tools.
- Treat archive restore/import features as privileged filesystem writes, even when the archive format is common.
