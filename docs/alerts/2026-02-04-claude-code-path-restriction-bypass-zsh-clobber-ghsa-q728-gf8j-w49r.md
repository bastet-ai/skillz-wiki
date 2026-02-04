# 2026-02-04 — Claude Code path restriction bypass via ZSH clobber → arbitrary file write (GHSA-q728-gf8j-w49r)

**Product:** `@anthropic-ai/claude-code` (npm)

## Summary
A GitHub Security Advisory reports that **Claude Code** had a **path restriction bypass** when parsing shell commands that used **ZSH “clobber” redirection syntax**. Under the right conditions, this could allow **writing files outside the allowed directory**.

- Advisory: <https://github.com/advisories/GHSA-q728-gf8j-w49r>
- CVE: CVE-2026-24053
- CWEs: CWE-22 (Path Traversal), CWE-78 (OS Command Injection)

## Why this matters (durable lesson)
“Tool sandboxing” that relies on **string parsing shell syntax** is brittle.

If an agent/tool is allowed to run shell commands but is supposed to be constrained to a workspace, then:
- **Any parsing discrepancy** (bash vs zsh syntax, quoting edge cases, redirections, globbing) can become a **policy bypass**.
- A file-write primitive is often enough to escalate to RCE (e.g., modify startup files, config files, scripts executed by CI, etc.).

## Recommended actions
1. **Upgrade immediately**
   - Per advisory: fixed in **`@anthropic-ai/claude-code` 2.0.74**.

2. **Defense-in-depth (recommended even after patch)**
   - Prefer **non-shell execution APIs** (argv-based) over `sh -c` / shell parsing.
   - Enforce filesystem policy at the **OS layer**:
     - run in a container / sandbox
     - use a dedicated user
     - mount a single workspace directory
     - apply AppArmor/SELinux if available
   - Treat **redirection, globbing, and expansion** as high-risk features; disable/strip them where feasible.

3. **Hunt for impact**
   - Review agent/tool logs for suspicious outputs like `>` / `>>` / `|` and unexpected file writes.
   - Audit the workspace for newly created dotfiles or build scripts that shouldn’t exist.

## Related Wisdom
- [Agent + CI Hardening](../best-practices/agent-ci-hardening.md)
- [Agent Tools: Command Injection (shell=True)](../best-practices/agent-tool-command-injection.md)
- [Archive Extraction: Symlink + Path Traversal](../best-practices/archive-extraction-symlink-traversal.md)
