# 2026-02-07 — Nebula fingerprint blocklist bypass via ECDSA signature malleability (GHSA-69x3-g4r3-p962)

GitHub advisory: <https://github.com/advisories/GHSA-69x3-g4r3-p962>

Upstream advisory: <https://github.com/slackhq/nebula/security/advisories/GHSA-69x3-g4r3-p962>

## Summary

Nebula supports blocklisting certificates by fingerprint.

When Nebula is configured to use **P-256 (ECDSA) certificates** (not the default), it is possible to produce a semantically equivalent certificate with a **different fingerprint** due to **ECDSA signature malleability**. This can allow **bypassing fingerprint-based blocklist entries**.

This is a general lesson: **fingerprints are only safe identifiers if the serialization is canonical**. If there are multiple valid encodings/signatures for “the same” object, “fingerprint == identity” can fail.

## Who is at risk

All of the following must be true (per advisory):

- You use **P-256** certificates (`CURVE_P256`).
- You use Nebula’s **blocklist**.
- The blocked certificates are signed by a trusted CA and not expired.
- An attacker has the **private key + certificate** for a blocked identity.

## Mitigation

1. **Upgrade Nebula**
   - Upgrade to **v1.10.3** (fixed).

2. **If you must stay on an affected version**
   - Prefer revoking/rotating the certificate/keypair rather than relying on fingerprint-only blocking.
   - If you have full copies of blocked certificates, compute and block **both “chirality” variants** (the advisory notes this as a workaround).
   - Consider rotating out CAs that have signed hosts now on the blocklist.

3. **Operational guidance**
   - Treat a blocklist as a *response tool*, not your only control:
     - enforce least privilege on what a node identity can access
     - monitor for unexpected joins/handshakes even for “known” identities

## Detection / hunt

- Review logs for connections from identities you believed were blocked.
- If you store historical fingerprints, look for “new fingerprint, same expected identity metadata”.
- Confirm your deployment is using `CURVE_P256` (if not, you’re likely not impacted).
