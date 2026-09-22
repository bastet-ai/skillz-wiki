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

## July 29 duplicate-entry and operator-download follow-up

Two reviewed advisories add ordering and trust-direction cases that a simple `../` fixture misses:

- [GHSA-h39j-r5qq-r9mm / CVE-2026-10732](https://github.com/advisories/GHSA-h39j-r5qq-r9mm) says all published `decompress <=4.2.1` releases can write through a duplicate-path ZIP sequence where the first entry becomes a symlink and the second regular-file write passes its link check before the first entry is resolved. No patched release is listed.
- [GHSA-f42x-p2mx-hm8r / CVE-2026-50558](https://github.com/advisories/GHSA-f42x-p2mx-hm8r) says Penelope's Unix Main Menu `download` path accepted a tar stream produced by the remote session and called Python `tarfile.extractall()` without safe filtering. A malicious or compromised session could write outside `~/.penelope/sessions/<session>/downloads`. The advisory text says fixed in 0.19.3, while GitHub's package metadata lists `penelope-shell-handler <0.20.0` with 0.20.0 first patched; preserve that discrepancy and test exact builds.

### Duplicate-path ordering fixture

Use a disposable output root and a sibling canary directory. Build a ZIP with two members sharing one in-root name: a symlink to the sibling canary followed by a regular file containing a fixed text marker. Record archive order, extraction scheduling, every pre-write `lstat`/`readlink` result, resolved final inode, and marker location. Repeat with reversed order, unique names, sequential extraction, concurrency disabled, and a fixed or replacement library. A valid finding is **duplicate entry scheduling -> link safety check observes stale state -> later write follows the resolved symlink into the sibling canary**. Never target startup files, package config, credentials, or executable paths.

### Penelope trust-direction fixture

Model the remote shell as adversarial even though the operator initiated the download. Use a local fake session that returns a minimal tar containing one benign in-root member and one marker aimed only at a temporary sibling directory. Trigger only the Unix Main Menu `download` path; compare the Python-agent path separately because the advisory says it does not depend on the remote `tar` command in the same way. Record remote command, received archive hash/listing, Python version, extraction filter, resolved destinations, and marker result. Do not overwrite `~/.penelope/peneloperc`, reload configuration, write SSH paths, or demonstrate code execution.

The bounded edge is **untrusted remote session -> operator-side archive stream -> outside-download-root marker write**. Confirm 0.19.3 and 0.20.0 independently rather than silently choosing one version claim.

## September 22 follow-up: stdlib `tarfile` data-filter verdict ignored on the link-fallback branch

[GHSA-rj44-3777-mh5x](https://github.com/advisories/GHSA-rj44-3777-mh5x) / CVE-2026-87910 (medium, surfaced in the 2026-09-22 updated feed): when Python `tarfile` extracts a link on a system that **doesn't support links**, it falls back to extracting the link's target member and runs the extraction filter **twice** — once for the member, once with the link location as name — and the **return value of one of those calls was ignored**. A filter (including the stdlib `data_filter`) that denies an entry by returning `None` is therefore bypassed on exactly that fallback path.

Operator rule: a security filter is only as strong as every call site honoring its verdict, and **fallback/error branches are where deny verdicts get dropped**. This is the mirror of the Penelope case above: there the filter was never called; here it runs and its answer is thrown away. Sweep any extractor wrapper that calls its own sanitizer more than once, or has a "operation unsupported -> retry differently" branch, for return-value handling on every leg.

Bounded proof: disposable extraction root, one symlink member aimed only at a temp sibling canary, a platform/config where link creation fails so the fallback fires, patched-Python negative control; never target real home directories, startup files, or credentials. Details and reporting language on the dedicated [Sept 22 Dancer2 guard-semantics page](2026-09-22-dancer2-guard-semantics-header-name-crlf-hook-refusal-dispatch-and-path-spelling-differentials-ghsa.md#adjacent-python-stdlib-tarfile-data-filter-verdict-ignored-on-the-link-fallback-path).
