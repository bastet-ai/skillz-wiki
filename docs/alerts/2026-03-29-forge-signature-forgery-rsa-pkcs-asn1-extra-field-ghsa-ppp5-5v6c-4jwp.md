# 2026-03-29 — Forge signature forgery in RSA-PKCS due to ASN.1 extra field (GHSA-ppp5-5v6c-4jwp)

**Product:** **Forge**

**Impact (per advisory):** A malformed ASN.1 structure in RSA-PKCS signature handling could enable signature forgery.

## Why this matters
Signature verification is a trust boundary. If the parser accepts extra or unexpected ASN.1 fields, an attacker may be able to produce a blob that verifies even though it should fail.

## Recommended actions
- **Patch/upgrade** Forge to the fixed release.
- **Treat ASN.1 parsing as hostile input**:
  - reject non-canonical encodings
  - fail on extra unexpected fields
  - verify against strict DER expectations where applicable
- **Add regression tests** for malformed RSA-PKCS signature encodings.
- **Audit other cryptographic verification paths** for lax parser behavior.

## Detection / hunting ideas
- Add tests that replay malformed ASN.1 signatures and confirm verification fails.
- Review logs for signature-validation anomalies or unexpected accepted inputs.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-ppp5-5v6c-4jwp>
