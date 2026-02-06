# 2026-02-06 — Claude Code sandbox escape via persistent config injection (GHSA-ff64-7w26-62rf)

**What happened:** Claude Code’s bubblewrap-based sandbox did not protect `~/.claude/settings.json` if the file **did not exist at startup**. Malicious code running *inside the sandbox* could create `settings.json` and inject persistent hooks (e.g., `SessionStart`) which would later execute **with host privileges** when Claude Code was restarted.

**Why it matters:** This is a classic “first-run / missing-file” pitfall: security policy is applied to *what exists*, not what *could be created*. For agent tools, persistence primitives (startup hooks, config files, plugins) are equivalent to a privileged autorun location.

## Durable guidance (defensive)

1. **Pre-create and lock down security-critical config files**
   - If your tool expects `settings.json`, create it on install/first-run and set restrictive permissions.
   - Prefer: create + chmod/chown before any untrusted code executes.

2. **Deny-by-default for writable mounts**
   - If a directory is writable inside a sandbox, assume an attacker can create *new* files there.
   - Apply protections at the directory boundary, not just at specific filenames.

3. **Treat “startup hooks” as privileged execution**
   - Require explicit user approval for any hook registration or change.
   - Make the default configuration contain **no executable hooks**.

4. **Make persistence auditable**
   - Record a cryptographic hash of trusted config at startup and warn on unexpected changes.
   - Consider storing config in an integrity-protected location (or signing it).

5. **Operational mitigation (users/operators)**
   - Update Claude Code to a fixed version (per advisory).
   - If you run agent tools in CI/dev environments: periodically delete/regenerate the tool’s config directory and run with least privilege.

## Status

Fixed upstream; update to the vendor’s patched release.

## References

- Upstream advisory: <https://github.com/anthropics/claude-code/security/advisories/GHSA-ff64-7w26-62rf>
- GitHub Advisory Database: <https://github.com/advisories/GHSA-ff64-7w26-62rf>
