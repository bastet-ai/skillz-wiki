# 2026-02-02 — jsPDF: PDF injection / metadata injection / DoS (fixed in 4.1.0)

## Summary

GitHub published multiple advisories for **jsPDF** (npm) affecting applications that generate PDFs from **user-influenced input**.

Key issues:

- **PDF object injection → arbitrary JavaScript actions** via AcroForm option handling
  - Advisory: https://github.com/advisories/GHSA-pqxr-3g65-p328
  - Affected APIs (per advisory): `AcroformChoiceField.addOption`, `AcroformChoiceField.setOptions`, and `appearanceState` on certain AcroForm field types.
- **Denial of service (OOM)** via unvalidated BMP dimensions when adding images
  - Advisory: https://github.com/advisories/GHSA-95fx-jjr5-f39c
  - Affected API (per advisory): `addImage` (and `html`).
- **Stored XMP metadata injection** (spoofing/integrity violation) via unescaped XML metadata
  - Advisory: https://github.com/advisories/GHSA-vm32-vv63-w422
  - Affected API (per advisory): `addMetadata`.

## What to do (durable guidance)

### Immediate actions

1. **Upgrade jsPDF to 4.1.0 or later**.
2. **Assume PDF generation is an injection surface**:
   - Treat any user-provided strings used to build PDF fields/metadata as *untrusted*.
3. If you cannot upgrade immediately:
   - **Do not pass user-controlled values** into the affected APIs.
   - Temporarily **disable or avoid AcroForm field generation** if any inputs are user-supplied.

### Engineering guidance (how to reduce risk long-term)

- **Never allow raw PDF object fragments** to be assembled from user strings.
  - Use strict allowlists for values like dropdown options, field names, metadata fields, etc.
- **Sanitize/escape correctly for the target context**:
  - PDF-string / name contexts are not HTML; use library-safe encoders or strict allowlists.
  - For metadata, **escape XML entities** (or better: build metadata with an XML library).
- **Resource limits for user-provided media**:
  - Enforce maximum width/height, file size, decoded pixel count, and total rendered surface area before calling `addImage`.
  - Consider server-side image transcoding to a safe, size-limited format.
- **Threat-model the viewer**:
  - PDF viewers can execute embedded JavaScript actions and are often deeply integrated into browsers/OSes.
  - If your workflow doesn’t require interactive PDFs, consider generating **non-interactive** documents only.

## Related Wisdom

- [Untrusted XML Parsing Hardening](../best-practices/untrusted-xml-parsing-hardening.md)
