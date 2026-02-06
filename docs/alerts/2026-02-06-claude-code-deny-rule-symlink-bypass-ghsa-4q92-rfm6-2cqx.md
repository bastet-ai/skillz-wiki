# 2026-02-06 — Claude Code deny-rule bypass via symlinks (GHSA-4q92-rfm6-2cqx)

**What happened:** Claude Code did not correctly enforce `settings.json` deny rules when file access went through **symbolic links**. If access to a sensitive file (e.g., `/etc/passwd`) was denied, but Claude Code could read a symlink pointing to it, the restricted file could be read via the symlink.

**Why it matters:** Any file access policy that doesn’t account for path indirection (symlinks, hardlinks, bind mounts, `..`, case-folding, UNC/NT paths, etc.) becomes a *policy bypass*. In agent tooling, file reads frequently become prompt/context leakage, credential exposure, or stepping stones to code execution.

## Durable guidance (defensive)

1. **Enforce policy on canonicalized paths**
   - Resolve to a real path (`realpath`) and then apply allow/deny rules.
   - Beware TOCTOU: re-check at the time of open/read.

2. **Prefer “safe open” primitives over string checks**
   - On Linux, consider `openat2(..., RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)` to prevent symlink traversal.
   - Walk path components using directory FDs (`openat`) to keep resolution under control.

3. **Deny by inode when appropriate**
   - For high-value targets, deny by inode/device after opening a handle (or maintain a protected allowlist by inode).

4. **Test the policy like an attacker**
   - Include unit tests for: symlinks, nested symlinks, symlink swaps, `..`, unusual Unicode, and race conditions.

5. **Operational mitigation (users/operators)**
   - Update Claude Code to a fixed version (per advisory).
   - Treat deny rules as *best effort* unless the tool documents hardened enforcement.

## Status

Fixed upstream; update to the vendor’s patched release.

## References

- Upstream advisory: <https://github.com/anthropics/claude-code/security/advisories/GHSA-4q92-rfm6-2cqx>
- GitHub Advisory Database: <https://github.com/advisories/GHSA-4q92-rfm6-2cqx>
