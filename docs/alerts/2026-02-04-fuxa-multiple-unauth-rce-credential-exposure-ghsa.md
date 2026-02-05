# 2026-02-04 — FUXA: multiple unauth issues (RCE paths + credential exposure) (multiple GHSAs)

**Product:** **FUXA** (advisories reference the `fuxa-server` package)

Multiple GitHub advisories were published describing **unauthenticated** weaknesses in FUXA that can enable:
- **remote code execution** (via hardcoded/default JWT secrets or token minting),
- **arbitrary file write / upload** leading to RCE,
- **credential exposure** (plaintext database creds), and
- **unauthenticated tag/device write** (integrity impact to connected systems).

## Affected advisories

- Unauthenticated tag write: GHSA-ggxw-g3cp-mgf8
- Unauthenticated RCE via arbitrary file write in upload API: GHSA-88qh-cphv-996c
- Unauthenticated RCE via hardcoded JWT secret in default config: GHSA-32cc-x95p-fxcg
- Unauthenticated exposure of plaintext DB credentials: GHSA-c5gq-4h56-4mmx
- Unauthenticated RCE via admin JWT minting: GHSA-vwcg-c828-9822

(Also see: unauth file upload leading to overwrite/RCE: GHSA-7g56-fwxj-cm23)

## Recommended actions (defender-focused)

1. **If internet-exposed: remove from the internet immediately**
   - Put behind an authenticated reverse proxy/VPN, or restrict to a management network.

2. **Upgrade + verify configuration**
   - Upgrade to a fixed version per each advisory.
   - Audit for **default/hardcoded secrets** and rotate all JWT/secret material.

3. **Treat as potential compromise** (if exposure existed)
   - Assume admin compromise is possible.
   - Rotate any credentials FUXA could access (DB creds, OT/SCADA integration creds, API tokens).

4. **Harden deployment**
   - Run as a non-root service user with minimal filesystem permissions.
   - Ensure upload paths cannot overwrite executable/config paths.
   - Add network ACLs to prevent direct access to management endpoints.

## References

- <https://github.com/advisories/GHSA-ggxw-g3cp-mgf8>
- <https://github.com/advisories/GHSA-88qh-cphv-996c>
- <https://github.com/advisories/GHSA-32cc-x95p-fxcg>
- <https://github.com/advisories/GHSA-c5gq-4h56-4mmx>
- <https://github.com/advisories/GHSA-vwcg-c828-9822>
- Related: <https://github.com/advisories/GHSA-7g56-fwxj-cm23>

## Related Bastet Wisdom

- [2026-02-04 — FUXA unauthenticated file upload leading to overwrite / RCE (GHSA-7g56-fwxj-cm23)](2026-02-04-fuxa-unauth-file-upload-ghsa-7g56-fwxj-cm23.md)
