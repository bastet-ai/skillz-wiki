# CISA Known Exploited Vulnerabilities (KEV)

This section captures **durable, actionable guidance** triggered by noteworthy additions to CISA’s *Known Exploited Vulnerabilities* catalog.

## How to use this

- Treat KEV entries as **“move now” signals**.
- Focus on:
  - **internet-exposed** assets
  - **identity / edge** products
  - **unauthenticated RCE / auth bypass** classes
- For each alert page, follow the **triage → mitigation → hunt** flow.

## Recent additions worth prioritizing

- **CVE-2024-1708 — ConnectWise ScreenConnect path traversal**
  - High-priority remote-management exposure.
  - Triage every internet-facing ScreenConnect deployment and isolate anything you cannot patch immediately.

- **CVE-2026-32202 — Microsoft Windows protection mechanism failure**
  - Track where Windows shell / spoofing exposure could affect trust decisions.
  - Prioritize managed endpoints that handle sensitive auth or admin workflows.

- **CVE-2026-39987 — Marimo remote code execution**
  - Treat exposed notebook services as direct code-execution paths.
  - Remove public access or isolate the service until patched.

## Feed

- Official KEV JSON feed: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
