# Project templates/scaffolding: prevent symlink-based file read/write escapes

Project scaffolding tools (template generators) can be a **supply-chain boundary**:

- cookiecutter / copier / yeoman-style generators
- “create-*” CLIs
- framework skeleton downloaders
- internal bootstrap scripts

If you run templates from untrusted sources (or templates are modifiable by attackers), you must treat them like **archives** and **code generation input**: they may try to read secrets or write outside the intended output directory.

## Threat model

Attackers aim to:

- **Read arbitrary files** from the developer/CI host (e.g., `~/.ssh`, cloud credentials, CI tokens)
- **Write arbitrary files** outside the project directory (e.g., overwrite dotfiles, inject config, drop hooks)
- Persist by writing into build directories that later execute (e.g., `.git/hooks`, CI scripts, package postinstall)

A common primitive is **symlink abuse**:

- A template contains a symlink that points outside the destination directory
- The generator either (a) follows the symlink while copying, or (b) preserves directory symlinks and then writes through them

## Defensive guidance

### 1) Treat templates as untrusted artifacts

- Prefer **pinned, reviewed templates** (internal registry, signed releases, or vetted repos).
- Avoid executing template “hooks” on untrusted input.

### 2) Apply “safe extraction” rules to template rendering

When copying files from a template into a destination directory, enforce the same rules you would for tar/zip extraction:

- Reject absolute paths and `..` traversal after normalization
- Ensure every output path stays under the destination root
- Handle symlinks explicitly (don’t rely on default filesystem behavior)

### 3) Symlink policy: default deny

Safest default:

- **Do not create symlinks** from templates.
- If a template contains symlinks, fail closed (or require an explicit allowlist).

If symlinks are required:

- Validate both:
  - the *symlink path* is within the destination root
  - the *symlink target* resolves within the destination root
- On write operations, prevent writing through symlinks (use `O_NOFOLLOW` / `openat` patterns where available).

### 4) Run scaffolding in a sandboxed environment

Especially in CI or when evaluating third-party templates:

- run as an unprivileged user
- use a clean working directory (no secrets mounted)
- restrict network egress where possible
- consider running in a container/VM with a throwaway filesystem

### 5) Operational rule: no secrets on the same host for untrusted templates

If you must run third-party templates locally:

- use a separate profile/container with **no SSH keys**, **no cloud credentials**, and **no repo tokens**

## Quick regression tests

Your generator should prevent both of these:

- A symlink like `output/subdir/escape -> ../../..` followed by a write to `output/subdir/escape/evil`
- A symlink like `output/secret -> ~/.ssh/id_rsa` followed by a read/copy step that dereferences it

## References

- GitHub Advisory (Copier): arbitrary filesystem read via symlinks when symlink preservation is disabled (GHSA-xjhm-gp88-8pfx)
- GitHub Advisory (Copier): arbitrary filesystem write via directory symlinks when symlink preservation is enabled (GHSA-4fqp-r85r-hxqh)
