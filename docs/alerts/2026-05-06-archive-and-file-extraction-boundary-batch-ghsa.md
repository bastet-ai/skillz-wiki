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

## July 6 `decompress` symlink, hardlink, prefix, and mode follow-up

[GHSA-mp2f-45pm-3cg9](https://github.com/advisories/GHSA-mp2f-45pm-3cg9) / CVE-2026-53486 extends the same extraction-boundary workflow to the Node.js `decompress` package. The advisory covers archives whose entries can create symlinks or hardlinks outside the target directory, exploit string-prefix containment checks such as `/srv/out` vs `/srv/out-old`, or preserve special mode bits when extraction runs with elevated privileges.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-mp2f-45pm-3cg9](https://github.com/advisories/GHSA-mp2f-45pm-3cg9) | `decompress` tar/zip extraction | archive-controlled paths, symlinks, hardlinks, and modes can cross from an intended output directory into sibling/outside files or privileged file modes | CI, package-import, template, backup-restore, and installer reviews should treat archive extraction as a write/read/link/mode primitive, not a simple unzip step. |

### Safe `decompress` validation additions

- Preconditions: isolated Node.js harness, affected `decompress` version, temp extraction root, temp sibling directory with a similar prefix, outside-root marker files, and no production home directories or secrets mounted.
- Build or use a minimal archive containing one case at a time: a symlink followed by a file write, a hardlink to a synthetic outside marker, a path targeting a sibling prefix directory, or a mode-bit canary on a disposable file.
- Positive evidence should be limited to marker files, archive listings, resolved path tables, link target metadata, and fixed-version rejection. Do not target `/etc/passwd`, SSH keys, shell startup files, package-manager config, or real build artifacts.
- Negative controls: realpath containment checked after every link/path resolution, link targets rejected when outside the extraction root, exact path-segment containment instead of string prefixes, special bits stripped, extraction as an unprivileged user, and patched package behavior.
- Report this as **archive entry metadata to outside-root file/link/mode effect**. Include archive format, entry names, resolved paths, link target, process UID, marker result, and patched negative control.
