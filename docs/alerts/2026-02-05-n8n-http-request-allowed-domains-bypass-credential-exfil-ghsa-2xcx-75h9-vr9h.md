# 2026-02-05 — n8n HTTP Request “Allowed domains” validation bypass → credential exfiltration (GHSA-2xcx-75h9-vr9h)

**Product:** **n8n** (npm package: `n8n`)

## Impact (per advisory)
A weakness in the **HTTP Request** node’s **credential domain validation** could allow an **authenticated** attacker (someone who can create/modify workflows) to send HTTP requests **with attached credentials** to **unintended domains**, potentially enabling **credential exfiltration**.

The advisory notes this primarily affects deployments using **wildcard domain patterns** in the credential’s “Allowed domains” setting (e.g., `*.example.com`).

## Recommended actions
- **Patch/upgrade:** upgrade to **n8n 1.121.0+**.
- **Credential hardening (immediate mitigation if you can’t patch yet):**
  - Replace wildcard domain patterns (e.g., `*.example.com`) with **explicit allowlists** (e.g., `api.example.com`, `auth.example.com`).
  - Prefer **scoped/least-privilege** credentials for HTTP Request nodes; avoid high-value “god tokens”.
- **Access control:** treat workflow create/edit permissions as **admin-equivalent**.
  - Restrict who can author/modify workflows.
  - Review any shared-team or contractor access.
- **Audit & rotation (if you suspect abuse):**
  - Audit workflows using **HTTP Request** nodes with domain-restricted credentials.
  - Review execution history for unusual outbound destinations.
  - Rotate affected credentials/tokens (rotate from a known-clean admin machine if compromise is suspected).

## Detection / hunting ideas
- Search for workflows where HTTP Request nodes target unexpected hosts.
- Look for repeated HTTP Request failures/timeouts to external domains (failed exfil attempts still leave telemetry).
- If you have egress logging, flag requests from n8n infrastructure to **new/rare domains**.

## References
- GitHub advisory entry: <https://github.com/advisories/GHSA-2xcx-75h9-vr9h>
- Upstream advisory: <https://github.com/n8n-io/n8n/security/advisories/GHSA-2xcx-75h9-vr9h>

## Related Bastet Wisdom
- [2026-02-04 — n8n Expression Escape → RCE (GHSA-6cqr-8cfr-67f8)](2026-02-04-n8n-expression-escape-rce-ghsa-6cqr-8cfr-67f8.md)
- [2026-02-04 — n8n OS command injection in Git node (GHSA-9g95-qf3f-ggrw)](2026-02-04-n8n-git-node-command-injection-ghsa-9g95-qf3f-ggrw.md)
- [2026-02-04 — n8n arbitrary file read (GHSA-gfvg-qv54-r4pc)](2026-02-04-n8n-arbitrary-file-read-ghsa-gfvg-qv54-r4pc.md)
