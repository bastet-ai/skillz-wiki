# 2026-02-04 — n8n improper file access controls allow arbitrary file read (GHSA-gfvg-qv54-r4pc)

**Product:** **n8n** (npm package: `n8n`)

**Impact (per advisory):** An **authenticated** user who can create/modify workflows may be able to **read sensitive files on the n8n host** (secrets/config/credentials), leading to **account takeover** and potentially broader compromise.

## Why this matters
Even “authenticated-only” file read is frequently exploitable in practice when workflow authoring is delegated (shared automation platforms, internal teams, contractors). If an attacker reads environment files, encryption keys, database creds, or API tokens, they can pivot quickly.

## Recommended actions
- **Patch/upgrade:** upgrade to **n8n 1.123.18 or 2.5.0** (or later).
- **Access control:** treat workflow creation/editing as **admin-equivalent**.
- **Reduce filesystem exposure:**
  - Run in a container/VM with **read-only rootfs** where possible.
  - Mount only required directories; avoid mounting host `/` or credential directories.
  - Use a dedicated service account with minimal permissions.
- **Temporary mitigation if you can’t patch immediately:**
  - Limit workflow authoring to a very small trusted group.
  - Restrict/disable nodes that interact with the filesystem (see n8n “blocking nodes” docs).

## Detection / hunting ideas
- Review audit logs for unusual workflow edits involving file reads.
- On the host/container, look for access to sensitive paths (e.g., `.env`, `/etc/*`, `/root/*`, app config directories) correlated with n8n process activity.

## References
- Advisory: <https://github.com/n8n-io/n8n/security/advisories/GHSA-gfvg-qv54-r4pc>
- GitHub advisory entry: <https://github.com/advisories/GHSA-gfvg-qv54-r4pc>
- n8n hardening / blocking nodes: <https://docs.n8n.io/hosting/securing/blocking-nodes/>
