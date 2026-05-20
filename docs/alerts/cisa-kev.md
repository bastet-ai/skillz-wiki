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

- **2026-05-20 KEV legacy client and Defender batch** — [guidance](2026-05-20-cisa-kev-legacy-client-and-defender-boundary-guidance.md)
  - CISA added exploited legacy Microsoft/Adobe client-side RCE surfaces and Microsoft Defender endpoint boundary issues: CVE-2008-4250, CVE-2009-1537, CVE-2009-3459, CVE-2010-0249, CVE-2010-0806, CVE-2026-41091, and CVE-2026-45498.
  - Prioritize EOL removal/isolation, Defender platform health, SMB/RPC exposure reduction, and post-exploitation hunting by the 2026-06-03 due date.

- **CVE-2026-42897 — Microsoft Exchange Server OWA cross-site scripting**
  - KEV-tracked Exchange web-render exposure with a CISA due date of 2026-05-29.
  - Patch or apply vendor mitigations, verify Exchange Emergency Mitigation Service health, restrict OWA exposure where possible, and hunt for suspicious OWA/session/mailbox-rule activity.

- **CVE-2026-20182 — Cisco Catalyst SD-WAN Controller authentication bypass**
  - Emergency-priority SD-WAN control-plane exposure with known exploitation and a CISA due date of 2026-05-17.
  - Restrict controller/manager exposure, apply ED 26-03 mitigation and hunt guidance, and rotate controller/admin secrets after compromise assessment.

- **CVE-2026-41940 — WebPros cPanel & WHM / WP2 authentication bypass**
  - Emergency-priority hosting control-panel exposure with reported exploitation.
  - Patch branch-specific fixed builds immediately and restrict WHM/cPanel management ports while validating compromise indicators.

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
