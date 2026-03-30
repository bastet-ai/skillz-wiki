# 2026-03-29 — jsrsasign DSA validation failure and zero-input DoS

**Product:** **jsrsasign**

**Advisories:**
- **GHSA-w8q8-93cx-6h7r** — Missing cryptographic validation during DSA signing enables private key extraction
- **GHSA-8g7p-jf3g-gxcp** — Infinite loop / DoS when processing zero or negative inputs

## Why this matters
This is a split failure mode:
- crypto code must reject invalid parameters before it reaches sensitive math
- numeric helpers must reject zero/negative values before they become loop bounds or allocation inputs

## Recommended actions
- **Patch/upgrade** jsrsasign to the fixed release.
- **Validate cryptographic parameters before signing**; never accept malformed curve/key material.
- **Reject zero and negative values** at input boundaries.
- **Add fuzz tests** around signing and numeric helpers.

## Detection / hunting ideas
- Search for user-controlled numbers flowing directly into jsrsasign helpers.
- Add regression tests for malformed DSA parameters and zero/negative integer inputs.
- Alert on hangs or worker saturation in code paths that depend on jsrsasign.

## References
- GitHub advisories:
  - <https://github.com/advisories/GHSA-w8q8-93cx-6h7r>
  - <https://github.com/advisories/GHSA-8g7p-jf3g-gxcp>
