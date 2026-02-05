# 2026-02-05 — Devtron Attributes API leaks API token signing key (GHSA-8wpc-j9q9-j5m2)

**Product:** **Devtron** (Go)

## Impact (per advisory)
An authorization failure in Devtron’s Attributes API can allow a logged-in user to retrieve the global API token signing key (`apiTokenSecret`). With that key, an attacker can **forge JWTs** and potentially gain **full control** of Devtron and move laterally into the underlying Kubernetes cluster.

## Recommended actions
- Apply vendor fixes as available.
- Until patched:
  - Restrict network access to the orchestrator API (NetworkPolicy / ingress allowlists).
  - Treat `apiTokenSecret` as compromised: rotate it and invalidate existing tokens.
  - Review role assignments; minimize accounts that can access sensitive APIs.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-8wpc-j9q9-j5m2>
