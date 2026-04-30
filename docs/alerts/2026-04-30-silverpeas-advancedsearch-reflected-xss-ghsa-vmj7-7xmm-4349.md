# Silverpeas AdvancedSearch reflected XSS (GHSA-vmj7-7xmm-4349 / CVE-2026-30139)

**Signal:** GitHub Security Advisories updated **2026-04-30**. Silverpeas Core has a reflected XSS in AdvancedSearch.

## What it is
Crafted input to Silverpeas Core AdvancedSearch can execute JavaScript in a victim browser. Impact depends on exposed authentication state, admin usage, and whether the deployment stores sensitive collaboration content.

Affected packages: Maven `org.silverpeas.core:silverpeas-core-war` and `org.silverpeas.core:silverpeas-core-web` through `6.4-feature13197`. GitHub Advisory did not list a first patched version when checked; upstream references include a fix PR/commit.

Reference: <https://github.com/advisories/GHSA-vmj7-7xmm-4349>

## Triage
1. Inventory Silverpeas portals and check whether AdvancedSearch is reachable by unauthenticated or low-privilege users.
2. Review versions and upstream patch status.
3. Inspect access logs for search requests containing HTML, event handlers, script tags, encoded angle brackets, or suspicious URL parameters.

## Mitigation
- Apply the upstream fix or vendor package when available.
- Require authentication and same-site protections around search endpoints.
- Add compensating WAF rules for obvious script/event-handler payloads until patched.

## Detection ideas
- Hunt for AdvancedSearch URLs shared externally or clicked by administrators.
- Review CSP reports, browser telemetry, and session anomalies after suspicious search requests.

## Durable lesson
Search pages are frequent reflected-XSS surfaces because they echo attacker-controlled text in rich UI contexts. Encode per output context and treat admin-facing reflected XSS as credential/session theft risk.
