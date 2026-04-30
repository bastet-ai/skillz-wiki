# uutils coreutils safety, symlink, and data-integrity batch (GHSA-v762-x3cf-5mfg et al.)

**Signal:** GitHub Security Advisories updated **2026-04-29** with a batch of uutils coreutils issues affecting destructive-operation guardrails, symlink handling, permission changes, exit-code reliability, and byte-preserving behavior.

## What it is
The batch includes several classes that matter when Rust `coreutils` replaces GNU coreutils in scripts, containers, or admin workflows:

- `rm` and `chmod` `--preserve-root` bypasses through symlinks or non-canonical path variants (`GHSA-v762-x3cf-5mfg`, `GHSA-9gqx-53gp-c8g3`).
- `mkfifo` changing permissions on an existing path after create failure (`GHSA-w8m4-4v35-v6x3`).
- `tail --follow=name` continuing to follow a replaced symlink and disclosing sensitive target files (`GHSA-xf75-659h-cgg5`).
- `chmod`, `chown`, and `chgrp` recursive operations reporting success based only on the last processed file (`GHSA-vp6q-mv9j-j428`, `GHSA-88ch-q68x-36v7`).
- `dd`, `comm`, `sort`, `cut`, and `mktemp` divergences that can hide write failures, corrupt non-UTF-8 bytes, drain FIFOs, crash pipelines, or create temp files in the current directory (`GHSA-wh8p-h9hw-x2mc`, `GHSA-rx8h-33gr-vhj9`, `GHSA-hwhf-8p2f-45wr`, `GHSA-f2jv-wjjc-2c94`, `GHSA-hj9r-8pfm-rmjj`, `GHSA-2cxp-xq3c-mjxx`).
- `mkdir -m` creating directories with default umask permissions before a later `chmod`, exposing a short private-directory TOCTOU window (`GHSA-vf87-345h-9qhx`, CVE-2026-35353).
- `cp -p` preserving setuid/setgid mode bits even when ownership preservation fails, unlike GNU `cp` guardrails (`GHSA-x2wv-9p67-mh9w`, CVE-2026-35350).
- Cross-filesystem `mv` fallback copy/delete behavior failing to preserve source ownership, breaking backup and migration assumptions (`GHSA-957r-r8gc-vv3h`, CVE-2026-35351).
- Additional late-added copy/install/move/fifo TOCTOU and metadata-safety issues:
  - `cp --no-dereference` checks a source path as a symlink, then opens it without `O_NOFOLLOW`, letting a local writer swap in a symlink and leak privileged-read file contents (`GHSA-hpfw-mqm3-33jh`).
  - Recursive `cp -R` copies character/block devices as byte streams instead of recreating device nodes, risking disk exhaustion, hangs, or broken `/dev`-style restores (`GHSA-67hp-f6hq-2h6g`).
  - `install -D` creates parent directories and later resolves the target path again without anchoring to a directory file descriptor, enabling symlink redirection of privileged writes (`GHSA-m26v-hjq3-x245`).
  - `cp` creates destination files with umask-derived permissions before tightening final mode, exposing a raceable readable file descriptor for private content (`GHSA-2m8x-mvfx-gwgj`).
  - Cross-device `mv` preserves extended attributes through repeated path-based lookups, allowing swapped files to receive inconsistent security xattrs such as SELinux labels or capabilities (`GHSA-x4mc-mqm7-gg39`).
  - `install` unlinks an existing destination and recreates it without `O_EXCL`, allowing symlink swaps to overwrite arbitrary files during privileged installs (`GHSA-v24v-f45g-w7jf`).
  - `mkfifo` creates a FIFO and then path-`chmod`s it, allowing a symlink swap to redirect the permission change to another file (`GHSA-9gh9-hwpr-rvqq`).

Affected package: Rust `coreutils` / uutils. Fixed versions vary; upgrade to the newest release and verify each utility used by privileged automation. Some late-added `cp`/`mv` ownership issues were still listed without a fixed version when checked.

References: <https://github.com/advisories/GHSA-v762-x3cf-5mfg>, <https://github.com/advisories/GHSA-w8m4-4v35-v6x3>, <https://github.com/advisories/GHSA-9gqx-53gp-c8g3>, <https://github.com/advisories/GHSA-vf87-345h-9qhx>, <https://github.com/advisories/GHSA-x2wv-9p67-mh9w>, <https://github.com/advisories/GHSA-957r-r8gc-vv3h>, <https://github.com/advisories/GHSA-hpfw-mqm3-33jh>, <https://github.com/advisories/GHSA-67hp-f6hq-2h6g>, <https://github.com/advisories/GHSA-m26v-hjq3-x245>, <https://github.com/advisories/GHSA-2m8x-mvfx-gwgj>, <https://github.com/advisories/GHSA-x4mc-mqm7-gg39>, <https://github.com/advisories/GHSA-v24v-f45g-w7jf>, <https://github.com/advisories/GHSA-9gh9-hwpr-rvqq>

## Triage
1. Identify hosts, containers, CI images, and embedded appliances using uutils coreutils instead of GNU coreutils.
2. Prioritize privileged scripts that call `rm -R`, `chmod -R`, `chown -R`, `chgrp -R`, `mkfifo`, `mkdir -m`, `cp -p`, `cp -R`, `cp --no-dereference`, `install`, `install -D`, cross-filesystem `mv`, `tail --follow=name`, `dd`, `sort --files0-from`, `comm`, or `mktemp`.
3. Check whether scripts rely on GNU-compatible raw-byte behavior, `--preserve-root`, recursive command exit codes, temporary private directories, or ownership/setuid/setgid preservation for safety decisions.

## Mitigation
- Upgrade uutils coreutils to versions that include the relevant fixes; prefer a current release rather than per-utility patch assumptions.
- In privileged automation, resolve paths with device/inode checks before destructive recursive actions.
- Do not run log-following commands as root in attacker-writable directories.
- Treat recursive ownership/permission command success as untrusted until stderr and target state are verified.
- Create sensitive directories and destination files with atomic/private defaults where possible, and validate final mode/owner before writing secrets.
- Avoid path-based privileged copy/install operations in attacker-writable directories; prefer directory-file-descriptor anchored operations, no-follow opens, exclusive creation, and temporary-file-then-atomic-rename patterns.
- After `cp -p`, recursive `cp`, `install`, `mkfifo`, or cross-device `mv` in privileged automation, assert owner, group, special mode bits, device-node semantics, xattrs, and final path inode match policy before executing or exposing the destination.

## Detection ideas
- Hunt for privileged `tail --follow=name` against directories writable by service users.
- Search automation logs for successful recursive `chmod`/`chown` followed by later permission-denied errors.
- Look for temp files unexpectedly created in working directories when `TMPDIR` is empty.
- Monitor privileged `cp`, `install`, `mv`, and `mkfifo` use in writable parent directories, especially when followed by unexpected reads, chmods, xattr changes, or writes outside the intended tree.

## Durable lesson
Compatibility utilities are security boundaries when scripts use them for guardrails. Replacement implementations need adversarial parity tests, especially for symlink races, path re-resolution, raw bytes, special files and device nodes, exit codes, special mode bits, ownership/xattr preservation, temporary-directory privacy, and destructive-operation protections.
