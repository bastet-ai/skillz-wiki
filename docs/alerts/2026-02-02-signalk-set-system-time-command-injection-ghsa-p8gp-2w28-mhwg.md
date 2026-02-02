# 2026-02-02 — Signal K set-system-time plugin command injection (GHSA-p8gp-2w28-mhwg)

## Summary

GitHub published an advisory describing **command injection → RCE** in the Signal K **set-system-time** plugin when enabled.

- Advisory: https://github.com/advisories/GHSA-p8gp-2w28-mhwg
- Trigger: attacker-controlled `navigation.datetime` values are interpolated into a shell command and executed via `sh -c` (per advisory).
- Impact: arbitrary command execution as the Signal K process user, and potentially **root** if `sudo` is configured permissively (per advisory).

## What to do (durable guidance)

### Immediate actions

1. **Disable the plugin** (`set-system-time`) until patched.
2. **Ensure Signal K security is enabled** (don’t run in unauthenticated mode).
3. **Audit permissions:**
   - Restrict who has **write** permissions (treat write as “can maybe RCE”).
4. **Fix `sudo` hardening:**
   - If you must allow time-setting, avoid blanket `sudo` and prefer narrowly-scoped mechanisms.

### Developer guidance (how to fix safely)

- Avoid shells for user-influenced values:
  - Prefer `execFile()`/`spawn()` with argv arrays (no `sh -c`).
- **Validate format** strictly (ISO-8601 datetime) and reject anything else.
- Consider moving system-time adjustments behind a privileged helper with a very small, audited interface.

## Related Wisdom

- [Agent Tools: Command Injection (shell=True)](../best-practices/agent-tool-command-injection.md)
