# 2026-02-02 — cert-manager controller DoS via crafted DNS response (GHSA-gx3x-vq4p-mhhv)

**Summary:** A malicious/compromised DNS path (on-path attacker) or attacker-controlled authoritative DNS server can return a specially crafted DNS response that poisons cert-manager’s DNS cache and triggers a panic when accessed, causing **denial of service** of the cert-manager controller.

- **Component:** `cert-manager-controller` (ACME DNS-01 zone discovery / self-checks)
- **Impact:** Controller panic → availability loss / stalled certificate issuance/renewal
- **Introduced:** cert-manager **v1.18.0**
- **Fixed:** cert-manager **v1.18.5** and **v1.19.3** (supported minors at disclosure)
- **Severity:** Moderate (availability)

## Why this matters
Even “just DNS” dependencies can be attacker-controlled in real environments:
- Cloud/VPC DNS interception/misrouting
- Enterprise proxies/security appliances
- Malicious authoritative DNS (especially during ACME DNS-01 challenges)

If cert issuance/renewal is mission-critical, controller DoS becomes an operational incident.

## Defensive actions
1. **Upgrade cert-manager** to a fixed version (preferred).
2. **Harden DNS resolution paths** for in-cluster components:
   - Prefer trusted resolvers; reduce opportunities for on-path tampering.
   - Consider **DNS-over-HTTPS (DoH)** for the controller (mitigates on-path tampering, not malicious authoritative DNS).
3. **Operational guardrails**:
   - Alert on controller restarts / crash loops.
   - Consider PodDisruptionBudgets and adequate replicas, but note: a deterministic panic can take all replicas down if they share the same poisoned cache entry.

## References
- GitHub Advisory: https://github.com/cert-manager/cert-manager/security/advisories/GHSA-gx3x-vq4p-mhhv
