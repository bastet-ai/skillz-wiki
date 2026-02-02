# 2026-02-02 — pip wheel extraction path traversal (GHSA-6vgw-5pg2-w6jp / CVE-2026-1703)

**Summary:** When installing and extracting a maliciously crafted **wheel**, pip may extract files **outside** the intended installation directory (path traversal).

- **Component:** `pip` wheel extraction / install
- **Impact:** Write outside target directory (with constraints described by upstream). Still a red flag for build/install environments.
- **Fixed:** **pip 26.0**
- **Severity:** Low (per advisory), but context-dependent.

## Why this matters
Even “limited” path traversal can be weaponized when:
- Builds run with elevated permissions (e.g., root inside CI images)
- Shared build hosts allow cross-project tampering
- Install directories sit under sensitive prefixes (e.g., writable locations that influence runtime)

This class of bug is also a reminder: **package installation is code execution**, and archive extraction needs strict controls.

## Defensive actions
1. **Upgrade pip** to **26.0+** wherever you build, package, or deploy.
2. **Harden build environments**:
   - Avoid running installs as root when possible.
   - Use isolated build containers/VMs; treat CI runners as disposable.
3. **If you write extractors/installers:**
   - Enforce canonical-path checks **before writing**.
   - Block symlinks/hardlinks unless explicitly required.

See also: [Archive Extraction: Symlink + Path Traversal](../best-practices/archive-extraction-symlink-traversal.md).

## References
- GitHub Advisory: https://github.com/advisories/GHSA-6vgw-5pg2-w6jp
- pip PR (fix): https://github.com/pypa/pip/pull/13777
- CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-1703
