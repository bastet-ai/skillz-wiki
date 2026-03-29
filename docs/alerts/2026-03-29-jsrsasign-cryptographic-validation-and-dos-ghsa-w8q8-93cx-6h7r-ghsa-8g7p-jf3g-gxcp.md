# 2026-03-29 — jsrsasign DSA signing validation failure and zero/negative input DoS

**Product:** **jsrsasign**

**Advisories:**
- **GHSA-w8q8-93cx-6h7r** — Missing cryptographic validation during DSA signing enables private key extraction
- **GHSA-8g7p-jf3g-gxcp** — Infinite loop / DoS when processing zero or negative inputs

## Why this matters
This is a classic split failure mode:
- cryptographic code must reject invalid parameters before it performs sensitive math
- parser/utility code must treat non-positive values as invalid input, not as a loop boundary

If either check is missing, an attacker can turn a helper library into a confidentiality or availability issue.

## Recommended actions
- **Patch/upgrade:** move to a fixed jsrsasign release as soon as one is available.
- **Validate inputs before crypto operations:** reject malformed curves, non-matching parameters, and impossible values up front.
- **Treat zero and negative values as invalid:** never let them flow into counters, lengths, loop bounds, or allocation math.
- **Add guardrails around library wrappers:** enforce explicit preconditions in your own code even if the upstream package is supposed to validate.
- **Fail closed:** return an error instead of attempting a fallback path when a cryptographic precondition is not met.

## Detection / hunting ideas
- Search for application code that forwards user-controlled numbers directly into jsrsasign helpers.
- Review any DSA/signature-related code paths for pre-validation of key material and parameters.
- Add fuzz cases for zero, negative, very large, and non-integer values around library entry points.
- Alert on hangs, worker saturation, or request latency spikes tied to signature/validation endpoints.

## References
- GitHub advisories:
  - <https://github.com/advisories/GHSA-w8q8-93cx-6h7r>
  - <https://github.com/advisories/GHSA-8g7p-jf3g-gxcp>
