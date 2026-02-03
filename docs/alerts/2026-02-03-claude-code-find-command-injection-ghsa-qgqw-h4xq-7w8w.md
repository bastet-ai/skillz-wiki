# 2026-02-03 — Claude Code command injection (find) bypasses user approval (GHSA-qgqw-h4xq-7w8w)

**What happened:** Claude Code had a command-injection condition involving a `find` command, allowing execution that could bypass an intended **user approval** prompt.

**Why it matters:** “Approval gates” are only meaningful if there is no way to:
- smuggle extra arguments/flags
- inject shell metacharacters
- coerce tool invocation paths

In agent systems, this can turn a “read-only” or “ask first” tool into silent code execution.

## Durable guidance (defensive)

1. **Never build shell commands by string concatenation**
   - Use `execve`/spawn with an argv array.

2. **Avoid the shell entirely**
   - For filesystem search, prefer native APIs (walk directory trees) over invoking `find`.

3. **Make approval gates structural**
   - The gate should authorize a *specific action object* (tool + arguments), not a raw string.
   - Recompute/validate the action at execution time.

4. **Constrain tool capabilities by default**
   - Run agent tools in a sandbox with no ambient credentials.
   - Block outbound network unless explicitly required.

5. **Log and alert on “unexpected” execution**
   - Unexpected flags, paths outside workspace, or commands with metacharacters should trigger high-severity telemetry.

## Status

See the upstream advisory for affected versions and fix details.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-qgqw-h4xq-7w8w>
- Upstream advisory: <https://github.com/anthropics/claude-code/security/advisories/GHSA-qgqw-h4xq-7w8w>
