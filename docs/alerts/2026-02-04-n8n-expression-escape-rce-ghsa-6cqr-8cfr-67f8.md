# 2026-02-04 — n8n Expression Escape vulnerability leading to RCE (GHSA-6cqr-8cfr-67f8)

**Signal:** GitHub Security Advisory published/updated 2026-02-04.

**Impact (per advisory):** An **authenticated** user who can create/modify workflows can abuse crafted expressions in workflow parameters to trigger **system command execution** on the host running n8n.

**Product:** **n8n** (npm package: `n8n`)

## Why this matters
n8n often runs with broad network access (internal APIs, SaaS tokens, secrets) and may be deployed on long-lived hosts. If an attacker can reach an account allowed to author workflows, they may be able to convert that access into **host-level RCE**.

## Who is exposed
- Instances where users (or compromised accounts) can **create or edit workflows**.
- Multi-tenant/shared n8n where workflow authoring is delegated beyond a small trusted admin set.

## Fix
Upgrade to a fixed version:
- **1.123.17** (1.x line)
- **2.5.2** (2.x line)

## Temporary mitigations (if you cannot upgrade immediately)
- Restrict workflow create/edit permissions to **fully trusted users only**.
- Run n8n in a **hardened environment**:
  - least-privilege OS user
  - container/VM isolation
  - restrict outbound network egress (only what workflows require)
  - restrict access to local metadata endpoints and cloud instance credentials

## Detection / hunt ideas
- Audit who has workflow create/edit permissions; review recent role changes.
- Review workflow history for newly-added expressions or unusual nodes.
- On the host: look for unexpected child processes spawned by n8n (shells, `curl/wget`, package managers).

## References
- Advisory:
  - <https://github.com/n8n-io/n8n/security/advisories/GHSA-6cqr-8cfr-67f8>
- GitHub advisory database mirror:
  - <https://github.com/advisories/GHSA-6cqr-8cfr-67f8>
