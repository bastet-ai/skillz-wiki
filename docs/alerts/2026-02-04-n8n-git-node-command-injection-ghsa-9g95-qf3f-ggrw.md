# 2026-02-04 — n8n OS command injection in Git node (GHSA-9g95-qf3f-ggrw)

**Product:** **n8n** (npm package: `n8n`)

**Impact (per advisory):** An **authenticated** user with permission to create/modify workflows may be able to achieve **OS command execution** (and/or arbitrary file read) on the n8n host via the **Git** node.

## Recommended actions
- **Patch/upgrade:**
  - Upgrade to **n8n 2.5.0** (for 2.x)
  - or **n8n 1.123.10** (for 1.x)
- **Immediate mitigation (if patching is delayed):**
  - Restrict workflow authoring to fully trusted users.
  - **Disable or restrict the Git node** if not essential.
- **Hardening:** run n8n in a locked-down container/VM (no privileged mode), with minimal filesystem mounts and tight egress controls.

## Detection / hunting ideas
- Investigate unusual child processes spawned by n8n (shells, `curl/wget`, package managers, compilers).
- Review workflow diffs for Git node usage that looks suspicious (unexpected arguments/URLs).

## References
- Advisory: <https://github.com/n8n-io/n8n/security/advisories/GHSA-9g95-qf3f-ggrw>
- GitHub advisory entry: <https://github.com/advisories/GHSA-9g95-qf3f-ggrw>
- Blocking nodes docs: <https://docs.n8n.io/hosting/securing/blocking-nodes/>
