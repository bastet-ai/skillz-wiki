# 2026-03-31 — @tinacms/graphql `FilesystemBridge` path validation bypass via symlinks or junctions (GHSA-g9c2-gf25-3x67)

**Product:** **@tinacms/graphql**

**Impact (per advisory):** String-based path containment checks can be bypassed with pre-existing symlinks or junctions, allowing file operations outside the intended content root.

## Why this matters
A path can look safe after `path.resolve()` and still point outside the sandbox once filesystem links are followed. Any tool that writes through template/content trees needs to validate the real target, not just the normalized string.

## Recommended actions
- **Patch/upgrade** @tinacms/graphql to the fixed release.
- Resolve and validate the **real filesystem target**, not only the string path.
- Default to **deny symlinks/junctions** in untrusted content trees.
- Prevent writes through symlinks with OS-level no-follow controls where available.
- Run template/content scaffolding in a sandbox with no secrets mounted.

## Detection / hunting ideas
- Look for content roots that already contain symlinks or junctions.
- Add regression tests for:
  - `../` traversal
  - symlink pivots
  - junction pivots on Windows
- Review adjacent file APIs for the same `resolve + startsWith` pattern.

## Related durable guidance
- [/best-practices/untrusted-templates-symlink-escapes](../best-practices/untrusted-templates-symlink-escapes.md)
- [/best-practices/archive-extraction-symlink-traversal](../best-practices/archive-extraction-symlink-traversal.md)

## References
- GitHub advisory: <https://github.com/advisories/GHSA-g9c2-gf25-3x67>
