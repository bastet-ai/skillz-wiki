# 2026-02-05 — n8n credential exfiltration via domain allowlist bypass (GHSA-2xcx-75h9-vr9h)

**Product:** **n8n** (npm package: `n8n`)

## Impact (per advisory)
A flaw in the **HTTP Request node** credential domain validation could allow an **authenticated attacker** to send requests **with stored credentials** to unintended domains, potentially enabling **credential exfiltration**.

**Fixed:** **n8n 1.121.0**

## Who is most at risk
Instances that:
- Use HTTP Request credentials with **wildcard allowlist patterns** (e.g., `*.example.com`)
- Allow untrusted users to create/modify workflows

## Recommended actions
- **Upgrade** to **n8n 1.121.0+**.
- Until upgraded:
  - Replace wildcard allowlist entries with **explicit hostnames**.
  - Restrict workflow authoring/modification to trusted users.
  - Audit existing workflows that use HTTP Request nodes with domain-restricted credentials.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-2xcx-75h9-vr9h>
