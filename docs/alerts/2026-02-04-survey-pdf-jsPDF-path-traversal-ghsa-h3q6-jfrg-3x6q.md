# 2026-02-04 — survey-pdf: jsPDF path traversal / local file inclusion via dependency (GHSA-h3q6-jfrg-3x6q)

**Product:** `survey-pdf` (npm) via dependency on **jsPDF**

**Impact (per advisory):** jsPDF versions **<= 3.0.4** contain a **path traversal / local file inclusion** issue (referenced by SurveyJS). Projects depending on affected `survey-pdf` versions may be exposed.

## Recommended actions
- **Upgrade `survey-pdf`** to a fixed release:
  - `1.12.59+` (for the 1.x line) or
  - `2.5.5+` (for the 2.x line)

This bumps jsPDF to **>= 4.0.0**.

## Why this matters
This is a common “transitive vuln” failure mode: your app can be vulnerable even if you never directly imported the affected library. PDF generation stacks often touch the filesystem (templates, assets, fonts), so path traversal bugs can become secret exposure.

## Detection / hunting ideas
- Grep lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) for `survey-pdf` and `jspdf` versions.
- If you expose PDF generation endpoints, review logs for suspicious file path inputs.

## References
- GitHub advisory (survey-pdf): <https://github.com/advisories/GHSA-h3q6-jfrg-3x6q>
- Referenced jsPDF advisory: <https://github.com/parallax/jsPDF/security/advisories/GHSA-f8cm-6447-x5h2>
