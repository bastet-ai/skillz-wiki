# 2026-02-03 — Claude Code path restriction bypass → arbitrary file write (GHSA-q728-gf8j-w49r)

**What happened:** A path restriction control in Claude Code could be bypassed via a ZSH “clobber”/redirection behavior, enabling **arbitrary file writes** outside the intended workspace.

**Why it matters:** Any coding agent that can write files is one step away from:
- **persistence** (dropping shell rc files, editor configs, cron jobs)
- **credential theft** (overwriting auth configs)
- **code execution** (writing scripts/binaries in PATH, altering build hooks)

## Durable guidance (defensive)

If you run/ship tools that can write files:

1. **Treat “path restrictions” as a security boundary**
   - Enforce in *every* write primitive (create, overwrite, rename, copy, archive extract).

2. **Canonicalize and validate paths server-side**
   - Resolve `realpath()` (or equivalent) and enforce:
     - ✅ `resolved == workspaceRoot` OR `resolved.startswith(workspaceRoot + "/")`
   - Reject writes to symlinks (or use `O_NOFOLLOW`/`openat` patterns).

3. **Defend against shell redirection tricks**
   - Avoid running file-write operations through a shell.
   - If a shell is unavoidable, use a restricted shell mode and disable/limit redirections.

4. **Sandbox the agent runtime**
   - Run as a dedicated low-privilege user.
   - Use filesystem isolation (container/VM) with a **read-only host**, and a single writable workspace mount.

5. **Add “tamper-evident” logging**
   - Log all writes with: absolute resolved path, uid/gid, hash(before/after), and request provenance.

## Status

See the upstream advisory for affected versions and fix details.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-q728-gf8j-w49r>
- Upstream advisory: <https://github.com/anthropics/claude-code/security/advisories/GHSA-q728-gf8j-w49r>
