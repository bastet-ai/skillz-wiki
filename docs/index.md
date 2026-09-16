---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Infrastructure hard-coded trust defaults and framework fail-open authz: Central Dogma `ch4n63m3` silent ZK secret + always-true SSH verifier + LDAP search-first injection, mistral.rs ungated media-loader SSRF/file-read, Pimcore blocklist-regex report SQLi, October CMS safe-mode sandbox→session-forgery + deserialization sinks, Payload `overrideAccess` omission, Shopper Livewire authz drift (12 GHSAs)](alerts/2026-09-16-centraldogma-mistralrs-pimcore-octobercms-payload-shopper-failopen-boundaries-ghsa.md)
- [Identity-assertion, MCP-metadata, and client-render late-wave boundaries: Prowler SAML tenant-from-asserted-email cross-tenant ATO (CVSS 9.6), ZITADEL auto-link without IdP email verification + JWT `exp` replay, Okta Java SDK cross-request response race, Doris MCP metadata SQLi, JSON:API `__proto__` pollution, SiYuan Bazaar zero-click XSS→Electron RCE, Mattermost + NiFi route authorization drift (18 GHSAs)](alerts/2026-09-16-saml-tenant-claim-mcp-metadata-jsonapi-marketplace-and-route-authorization-ghsa.md)
- [Identity-provider authority boundaries: ZITADEL OAuth2 token-exchange provenance/scope-containment break (CVSS 8.1), Keycloak first-broker-login link-proof never revoked after link or unlink, Nezha Host-header redirect_uri regression on empty dashboard_host default (3 GHSAs)](alerts/2026-09-16-zitadel-keycloak-nezha-identity-provider-authority-boundaries-ghsa.md)
- [KEV wave 2026-09-09→14: NetScaler alternate-path auth bypass, MikroTik RouterOS pre-auth username-syntax privesc + btest memory leak, Cisco Secure Email Gateway email-parsing SQLi→root RCE, JFrog Artifactory scope/issuance drift, GitLab unauth commits-API file read, ScreenConnect client session gate (11 KEV entries, operator sweep angles)](alerts/2026-09-15-kev-wave-netscaler-cisco-routeros-jfrog-gitlab-screenconnect.md)
- [AI/agent local-surface week: MCP DNS-rebinding on local tool listeners, header-steered token-attaching SSRF, alternate-auth-path parity breaks, expression-sandbox grammar escapes, wildcard OAuth subjects, SAML tenant-from-asserted-email (44 GHSAs)](alerts/2026-09-15-mcp-dns-rebinding-alternate-auth-path-and-sandbox-boundaries-ghsa.md)
- [Http4s Ember + Traefik parser/header/route authority boundaries: CL.TE/TE.CL/TE.TE framing divergences, rootless opaque request-target, trailer-sourced trusted-header smuggling, header alias collapse (19 GHSAs)](alerts/2026-09-15-http4s-ember-traefik-parser-header-route-boundaries-ghsa.md)
- [Secret Server identity/crypto trust cluster + hardcoded OT update keys: Delinea Secret Server padding oracle, SAML impersonation, malicious-link XSS (3 criticals), plus hardcoded server/client crypto keys in Wärtsilä FOS-Onboard update controller and robot testing framework (5 GHSAs)](alerts/2026-09-16-secret-server-identity-crypto-boundaries-and-ot-hardcoded-update-keys-ghsa.md)
- [Adobe Commerce / Magento template-engine RCE KEV, actively exploited (CVE-2026-75650 / GHSA-fj37-xm58-mf28): CWE-1336 template-engine injection → arbitrary code execution, unauthenticated, no user interaction, CVSS 10.0 scope-changed, KEV 2026-09-08 due 2026-09-11 — render-context audit across core and extension writers on the ecommerce perimeter](alerts/2026-09-09-adobe-commerce-magento-template-engine-rce-kev-cve-2026-75650.md)
- [N-able N-Central pre-auth RCE KEV "static code injection" (CVE-2026-86218): CWE-96 pre-authentication remote code execution on the N-Central server, KEV 2026-09-08 with forensic-triage flag, 2026-09-11 due — generated-artifact audit and repeat-KEV route-family workflow](alerts/2026-09-09-n-able-n-central-preauth-rce-static-code-injection-kev-cve-2026-86218.md)
- [Okta Access Gateway / Hyperdrive trust-boundary cluster (17 GHSAs): generated-config injection into OAG nginx/PHP/OS-command/eval writers, client-header pass-through identity source, SAML→LDAP/SQL injection, protected-rule bypass, assertion/secret leakage into logs and MSI properties, and agent-side verdict/integrity gaps](alerts/2026-09-09-okta-oag-hyperdrive-config-injection-and-identity-boundaries-ghsa.md)



































































## What lives here

- **Skills**: installable, tool-specific guides that agents can execute step by step
- **Recon**: workflows for turning scope into a prioritized asset map
- **Exploit Paths**: concrete attack chains that are specific enough to replay during authorized testing
- **Templates**: reusable report skeletons and delivery formats
- **Notes**: editorial guidance, taxonomy, and source tracking
- **Blog**: short updates when major skills or exploit paths land

Older alert and mitigation-oriented reference pages may remain in the repo, but the primary site surface is intentionally centered on pentesting, red-team, and bug-bounty operator workflows.

## How the skills are written

Each skill page is structured so it can be reused outside the wiki:

- When to use the tool
- Required inputs and prerequisites
- Command patterns worth reusing
- Expected outputs and what to capture
- Safety constraints and scope boundaries

!!! warning "Authorized use only"
    These pages are for lawful research, lab work, and authorized assessments. Do not apply them to systems you do not own or lack explicit permission to test.
