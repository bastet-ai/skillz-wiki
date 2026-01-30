# Archive extraction: prevent path traversal + symlink escapes

Archive extraction is a common supply-chain and scanning surface (tar/zip/deb/rpm). A frequent failure mode is allowing paths or symlinks that escape the intended extraction directory.

## Threat model

An attacker provides an archive that, when extracted, causes:

- writes outside the target directory via `../` traversal or absolute paths
- writes outside the target directory via symlinks (create symlink inside dir → write through it)
- overwriting sensitive files (cron, SSH keys, config) when running as a privileged user

This matters even for “just scanning” workflows: if your scanner extracts untrusted archives, it’s part of your attack surface.

## Defensive extraction rules (portable)

### 1) Canonicalize and validate every member path

Reject entries when any of the following are true:

- path is absolute (`/etc/passwd`, `C:\\Windows\\...`)
- path contains `..` segments after normalization
- normalized path does not stay under the extraction root

### 2) Handle symlinks explicitly (don’t trust defaults)

- If you don’t need symlinks: **do not create them** (treat as suspicious and skip).
- If you allow symlinks:
  - validate the symlink *location* is within the root
  - validate the symlink *target* resolves within the root
  - on write operations, ensure you’re not writing through a symlink (use `O_NOFOLLOW` where available)

### 3) Prefer “openat-style” safe extraction

Where supported:

- open the root directory FD
- for each path segment, use `openat()` / `mkdirat()` with `O_NOFOLLOW`
- never follow symlinks while traversing

This avoids TOCTOU races and is far more robust than string checks.

### 4) Run extraction in a sandbox

Even with safe extraction, reduce blast radius:

- run as an unprivileged user
- extract into a temp directory on a dedicated filesystem
- consider container / namespace isolation (especially in CI)

## Quick regression tests

Include archives that attempt:

- `../../escape.txt`
- `/etc/cron.d/pwn`
- create `subdir/link -> ../../..` then write `subdir/link/escape`

Your extractor should either reject them or extract safely without writing outside root.

## References

- GitHub Advisory example: `malcontent` symlink path traversal due to argument confusion + missing symlink validation (CVE-2026-24846)
