# 2026-02-05 — `@coding-solo/godot-mcp` command injection via `projectPath` (GHSA-8jx2-rhfh-q928)

**Source:** https://github.com/advisories/GHSA-8jx2-rhfh-q928  
**Published:** 2026-02-04 (updated 2026-02-05)  
**Severity:** High  
**Fixed in:** `0.1.1`

## Summary
`@coding-solo/godot-mcp` (an NPM package) was reported as vulnerable to **OS command injection** due to an **unsanitized `projectPath`** parameter.

Even when the immediate fix is “upgrade to 0.1.1”, the durable lesson is about a common agent/tooling failure mode: **accepting a path/argument and feeding it into a shell command**.

## Durable guidance
If your code (or agent tooling) launches processes based on user-provided input:

- **Avoid shells entirely**
  - Use `spawn/execFile` with an argv array (Node) rather than `exec` / `shell=True` patterns.

- **Treat paths as hostile**
  - Normalize + validate paths (`realpath`) and enforce that they remain under an allowed directory.
  - Prefer **allowlists** and structured parameters over “free-form path strings”.

- **Defense in depth**
  - Run tooling in a **restricted sandbox** (no secrets, least-privilege FS access, limited network egress).
  - Log executed commands (with secrets redacted) to aid incident response.

## What to do
- If you use this package: **upgrade to `0.1.1`**.
- If you can’t upgrade immediately: audit any code path that composes commands from `projectPath` (or similar) and remove shell execution.

## References
- GitHub Advisory: https://github.com/advisories/GHSA-8jx2-rhfh-q928
- Related payloads: /payloads/command-injection.md
- Related best practice: /best-practices/agent-tool-command-injection.md
