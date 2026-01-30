# CWD auto-config poisoning (a.k.a. “run-from-/tmp” RCE)

Some developer tools **implicitly load configuration or scripts from the current working directory (CWD)**.
If an attacker can write to that directory (or influence where your process starts), they can plant a file that is **executed on startup**.

This is a classic “CWD poisoning” pattern:

- Victim launches a tool while their shell is in an attacker-writable directory (`/tmp`, shared repo, world-writable build dir, etc.).
- Tool auto-loads `./<config-or-startup-file>`.
- Attacker’s payload runs **as the victim user** (and becomes **local privilege escalation** if the victim is privileged).

## Where this shows up

This pattern appears in multiple ecosystems (shell profiles, editor/task runners, language REPLs, build tools). One recent example:

- **PsySH / Laravel Tinker** auto-loading `.psysh.php` from the CWD (CVE-2026-25129 / GHSA-4486-gxhx-5mg7).

## Defensive guidance

### 1) Treat CWD as untrusted unless you control it

- Do **not** run interactive tooling from:
  - `/tmp` or other world-writable locations
  - shared build/work directories
  - untrusted repos / third-party checkouts
- Prefer running from:
  - your home directory
  - a trusted, user-owned workspace with sane permissions

### 2) Lock down directories used by automation

In CI/CD and automation:

- Ensure `workdir` is **owned by the build user** and not group/world-writable.
- Avoid reusing shared workspaces across trust boundaries.
- Prefer ephemeral workspaces per job.

Quick checks:

```bash
# suspicious if group/world-writable (write bit set)
find . -maxdepth 1 -type d -perm -002 -o -perm -020

# show ownership and perms for the current directory
pwd
ls -ld .
```

### 3) Disable or constrain per-directory auto-loading where possible

If the tool supports it, prefer one of:

- **Disable per-directory config**
- Only load config from a **trusted, fixed path** (e.g., user config directory)
- Validate safety before loading:
  - directory is owned by the current user
  - directory is not group/world-writable
  - config file is owned by the current user

As an implementer, this is a strong default:

- refuse to auto-load from unsafe directories
- require an explicit `--config ./file` opt-in for CWD configs

### 4) Watch for “privileged + developer tool” footguns

- Don’t run REPLs / debuggers / tinker shells as root.
- If you must, ensure:
  - the CWD is trusted
  - environment is minimal
  - auto-loading features are disabled

## Incident response checklist (if you suspect abuse)

- Identify who ran the tool, from where:
  - shell history, CI logs, process audit logs
- Inspect the suspected directory for startup/config files:
  - e.g., `.psysh.php`
- Treat the run as arbitrary code execution:
  - check for persistence, exfil, new users/keys, cron changes

## References

- GitHub Advisory: https://github.com/advisories/GHSA-4486-gxhx-5mg7
