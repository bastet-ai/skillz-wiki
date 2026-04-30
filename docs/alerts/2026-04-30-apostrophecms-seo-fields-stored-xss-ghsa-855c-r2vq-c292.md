# ApostropheCMS SEO fields stored XSS and API data exposure (GHSA-855c-r2vq-c292 / CVE-2026-35569)

**Signal:** GitHub Security Advisories updated **2026-04-30**. ApostropheCMS fixed stored XSS in SEO Title and Meta Description rendering that could expose authenticated API data.

## What it is
ApostropheCMS rendered user-controlled SEO fields into HTML contexts such as `<title>`, `<meta>` attributes, and structured JSON-LD without sufficient neutralization. An attacker with content-editing access, compromised editor credentials, or another path to modify SEO metadata could store JavaScript that later executes for authenticated users.

The advisory notes impact beyond pop-up XSS: because the script runs in the CMS origin for logged-in users, it can make authenticated API requests and exfiltrate sensitive content or administrative data.

Affected package: npm `apostrophe` `<= 4.28.0`.

Reference: <https://github.com/advisories/GHSA-855c-r2vq-c292>

## Triage
1. Identify ApostropheCMS deployments and their exact `apostrophe` package versions.
2. Review who can edit SEO Title, Meta Description, and related structured-data fields.
3. Search stored content revisions for script tags, event handlers, broken-out attributes, encoded `<` / `>` characters, `javascript:`, and suspicious JSON-LD fragments.
4. If suspicious content is found, review admin activity and API access during windows when privileged users viewed affected pages.

## Mitigation
- Upgrade ApostropheCMS to a fixed release containing the SEO-field escaping patch.
- Restrict SEO metadata editing to trusted roles until all deployments are patched.
- Sanitize and re-save existing SEO fields after patching; remove payloads from revision history where feasible.
- Apply a strong Content Security Policy to reduce script execution and data exfiltration impact.

## Detection ideas
- Alert on SEO fields containing HTML metacharacters, URL schemes, event-handler names, template delimiters, or unusually long encoded strings.
- Watch for authenticated API bursts immediately after editors/admins view public pages with recently changed SEO metadata.
- Monitor CSP violation reports for script execution attempts sourced from metadata contexts.

## Durable lesson
Metadata fields still render into executable browser contexts. Treat titles, descriptions, and JSON-LD as hostile content that needs context-aware escaping, not as safe administrative text.
