# uutils coreutils safety, symlink, and data-integrity batch (GHSA-v762-x3cf-5mfg et al.)

**Signal:** GitHub Security Advisories updated **2026-04-29** with a batch of uutils coreutils issues affecting destructive-operation guardrails, symlink handling, permission changes, exit-code reliability, and byte-preserving behavior.

## What it is
The batch includes several classes that matter when Rust `coreutils` replaces GNU coreutils in scripts, containers, or admin workflows:

- `rm` and `chmod` `--preserve-root` bypasses through symlinks or non-canonical path variants (`GHSA-v762-x3cf-5mfg`, `GHSA-9gqx-53gp-c8g3`).
- `mkfifo` changing permissions on an existing path after create failure (`GHSA-w8m4-4v35-v6x3`).
- `tail --follow=name` continuing to follow a replaced symlink and disclosing sensitive target files (`GHSA-xf75-659h-cgg5`).
- `chmod`, `chown`, and `chgrp` recursive operations reporting success based only on the last processed file (`GHSA-vp6q-mv9j-j428`, `GHSA-88ch-q68x-36v7`).
- `dd`, `comm`, `sort`, `cut`, and `mktemp` divergences that can hide write failures, corrupt non-UTF-8 bytes, drain FIFOs, crash pipelines, or create temp files in the current directory (`GHSA-wh8p-h9hw-x2mc`, `GHSA-rx8h-33gr-vhj9`, `GHSA-hwhf-8p2f-45wr`, `GHSA-f2jv-wjjc-2c94`, `GHSA-hj9r-8pfm-rmjj`, `GHSA-2cxp-xq3c-mjxx`).

Affected package: Rust `coreutils` / uutils. Fixed versions vary; upgrade to the newest release and verify each utility used by privileged automation.

References: <https://github.com/advisories/GHSA-v762-x3cf-5mfg>, <https://github.com/advisories/GHSA-w8m4-4v35-v6x3>, <https://github.com/advisories/GHSA-9gqx-53gp-c8g3>

## Triage
1. Identify hosts, containers, CI images, and embedded appliances using uutils coreutils instead of GNU coreutils.
2. Prioritize privileged scripts that call `rm -R`, `chmod -R`, `chown -R`, `chgrp -R`, `mkfifo`, `tail --follow=name`, `dd`, `sort --files0-from`, `comm`, or `mktemp`.
3. Check whether scripts rely on GNU-compatible raw-byte behavior, `--preserve-root`, or recursive command exit codes for safety decisions.

## Mitigation
- Upgrade uutils coreutils to versions that include the relevant fixes; prefer a current release rather than per-utility patch assumptions.
- In privileged automation, resolve paths with device/inode checks before destructive recursive actions.
- Do not run log-following commands as root in attacker-writable directories.
- Treat recursive ownership/permission command success as untrusted until stderr and target state are verified.

## Detection ideas
- Hunt for privileged `tail --follow=name` against directories writable by service users.
- Search automation logs for successful recursive `chmod`/`chown` followed by later permission-denied errors.
- Look for temp files unexpectedly created in working directories when `TMPDIR` is empty.

## Durable lesson
Compatibility utilities are security boundaries when scripts use them for guardrails. Replacement implementations need adversarial parity tests, especially for symlink races, raw bytes, special files, exit codes, and destructive-operation protections.
