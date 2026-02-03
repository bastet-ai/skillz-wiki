# 2026-02-03 — Flowise arbitrary file exposure via ReadFileTool (GHSA-j44m-5v8f-gc9c)

**Summary:** Flowise’s `ReadFileTool` reads a user-supplied `file_path` without restricting it to an allowlisted directory. An authenticated attacker can read **arbitrary files** on the Flowise host/container, which can cascade into credential theft and potentially **RCE** (e.g., by stealing keys/tokens, DB files, SSH keys, etc.).

- **Component:** Flowise (`ReadFileTool` / file store)
- **Impact:** Arbitrary file read (information disclosure) → often becomes full compromise depending on what’s reachable
- **Access:** Authenticated

## Why this matters (durable lesson)
This is a canonical **“agent tool escape”** pattern:
- LLM/agent platforms commonly expose tools like `read_file`, `browse`, `run_command`, `sql_query`, etc.
- If the tool is wired directly to powerful primitives (filesystem, network, shell) without strong policy boundaries, **prompt injection becomes privilege escalation**.

## Defensive actions
1. **Constrain file access by design**
   - Implement an **allowlist** of readable paths (e.g., a single workspace directory).
   - Enforce **canonical-path checks**: resolve (`realpath`) then ensure the path is inside the allowed root.
   - Consider blocking **symlinks** or resolving them before access.

2. **Treat agent tools as untrusted input surfaces**
   - Log tool invocations (who/what requested them, arguments, result size).
   - Add rate limits and output-size limits to reduce bulk exfil.

3. **Reduce blast radius**
   - Run the service as a **non-root** user.
   - Containerize and apply mandatory access control where possible (AppArmor/SELinux).
   - Do not mount sensitive host paths into the container; keep secrets in a proper secret store.

See also: [Agent + CI Hardening](../best-practices/agent-ci-hardening.md) and [Archive Extraction: Symlink + Path Traversal](../best-practices/archive-extraction-symlink-traversal.md).

## References
- GitHub Advisory: https://github.com/advisories/GHSA-j44m-5v8f-gc9c
