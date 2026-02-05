# 2026-02-05 — cert-manager controller DoS via crafted DNS response (GHSA-gx3x-vq4p-mhhv)

**Product:** `cert-manager` (controller)

## Impact (per advisory)
A specially crafted DNS response can trigger a **panic** in the cert-manager controller’s DNS cache handling during ACME DNS-01 operations, resulting in **Denial of Service**.

Attack preconditions (per advisory):
- Attacker can intercept/modify DNS traffic from the controller pod **or** controls the authoritative DNS server for the validated domain.

**Introduced:** cert-manager **1.18.0**

**Fixed:** cert-manager **1.18.5** and **1.19.3**

## Recommended actions
- **Upgrade** to a fixed version:
  - 1.18.x → **1.18.5+**
  - 1.19.x → **1.19.3+**
- Consider enabling **DNS-over-HTTPS** for outbound DNS lookups (reduces on-path tampering risk; does not help if authoritative DNS is malicious).

## References
- GitHub advisory: <https://github.com/advisories/GHSA-gx3x-vq4p-mhhv>
