# 2026-02-05 — Qdrant: arbitrary file write via `/logger` endpoint (GHSA-f632-vm87-2m2f)

GitHub advisory: <https://github.com/advisories/GHSA-f632-vm87-2m2f>

## Summary

Qdrant’s HTTP API exposes a `/logger` endpoint that can be abused to **append to attacker-chosen files** (path control). In some deployments this can be chained into **configuration overwrite** and, after restart, **sensitive file read** / broader compromise.

The advisory notes exploitation may only require minimal privileges (e.g., read-only API access), depending on deployment.

## Who is at risk

Higher risk when:

- Qdrant is exposed to untrusted networks.
- An attacker can obtain *any* API credentials (even low-privilege).
- The configuration directory is writable by the Qdrant process (common in some container layouts).

## Triage

- Identify whether your Qdrant deployment exposes `/logger`.
- Verify what authn/authz is required for `/logger` in your version.
- Check filesystem permissions for the configuration directory (and whether `config/local.yaml` is used / can be created).

## Mitigation

- **Upgrade** to a fixed release per upstream guidance (preferred).
- If you cannot upgrade immediately:
  - **Restrict or disable** the `/logger` endpoint (reverse proxy ACLs, routing rules, or application-level configuration if available).
  - Enforce **strict path containment** for any logging configuration (logs directory only).
  - Reduce blast radius: run Qdrant with a dedicated OS user and least-privilege filesystem permissions.

## Detection / hunt

- Web/API logs: look for `POST /logger` requests, especially with unusual `log_file` values.
- File integrity monitoring: unexpected creation/modification of `config/local.yaml` or other config paths.
- Container/runtime telemetry: unexpected Qdrant restarts following suspicious logger activity.
