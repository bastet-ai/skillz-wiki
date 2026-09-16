---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MCP OAuth resource-metadata spoofing + sanitizer/guard parity misses: rmcp drops the RFC 9728 `resource` binding → malicious MCP server relays a legitimate AS's real access token to the attacker (CVE-2026-63127) + unauthenticated permanent session-table leak (CVE-2026-63128); @nuxtjs/mdc exact-name sanitizer misses `xlink:href` and dead-code `data:text/html` deny entries (CVE-2026-63671); vLLM audio bomb guard wired to one route not its sibling (CVE-2026-57173); Grav pre-render validator bypassed by Twig `~` concatenation (folded into Aug 25 page)](alerts/2026-09-16-rmcp-oauth-resource-spoofing-mdc-sanitizer-gaps-and-vllm-route-guard-parity-ghsa.md)
- [Scanner, C2, and SOAR control-plane trust boundaries: Nuclei < 3.11.1 signature-verification cache trusts mtime not content → template substitution + mtime restore → scanner-host code execution, Covenant ≤ 0.6 unauthenticated SignalR hub mints operator JWTs (full C2 API: grunts/credentials/roster), Shuffle cross-tenant admin API-key reset (3 GHSAs)](alerts/2026-09-16-nuclei-signature-cache-covenant-hub-token-mint-shuffle-tenant-key-reset-ghsa.md)
- [Realtime view-framework state-binding boundaries: djust WebSocket `update_model` mass-assignment of any public view attribute (client-supplied field name, default allow-all), mount-path `__import__` of client-supplied module path before auth → unauthenticated arbitrary-module import (CVE-2026-61599), DEBUG-gated observability/eval endpoints with an opt-in localhost middleware the docs omit, WS/SSE-only tenant-isolation fail-open + `csrf_exempt` SSE CSRF + late-night sibling set, OpenTelemetry.Resources.Host macOS bare-name PATH hijack → local LPE (11 GHSAs)](alerts/2026-09-16-djust-websocket-mass-assignment-debug-gated-observability-and-otel-path-hijack-ghsa.md)
- [Pepperl+Fuchs ICE2/ICE3 IODD web-UI cluster: unauth `_account_log` auth bypass + unauth IODD upload → root script surviving reboot (both 9.8), viewer path traversal → SSH keys, ~10 command-injection endpoints; + Arista EOS gRPC management plane (Certz Rotate root command injection, gNMI root RCE, Pathz rule drift, gRPC-only AAA drift, Credentialz tampering, silent revoke race); + XikeStor unauth config download](alerts/2026-09-16-pepperlfuchs-iodd-web-ui-and-arista-grpc-management-plane-boundaries-ghsa.md)
- [CI/CD and app-server control-plane trust boundaries: GitLab developer-role policy-test pipeline reads protected CI/CD variables, Octopus Server feed-modification → arbitrary file overwrite → RCE, Ash field-policy filter oracle via calculation/aggregate miss, ZenHive mpp recovery-id malleability + cache-guarantee overwrite](alerts/2026-09-16-gitlab-variable-scope-octopus-feed-traversal-ash-filter-oracle-and-zenhive-payment-dedup-ghsa.md)
- [Infrastructure hard-coded trust defaults and framework fail-open authz: Central Dogma `ch4n63m3` silent ZK secret + always-true SSH verifier + LDAP search-first injection, mistral.rs ungated media-loader SSRF/file-read, Pimcore blocklist-regex report SQLi, October CMS safe-mode sandbox→session-forgery + deserialization sinks, Payload `overrideAccess` omission, Shopper Livewire authz drift (12 GHSAs)](alerts/2026-09-16-centraldogma-mistralrs-pimcore-octobercms-payload-shopper-failopen-boundaries-ghsa.md)
- [Identity-assertion, MCP-metadata, and client-render late-wave boundaries: Prowler SAML tenant-from-asserted-email cross-tenant ATO (CVSS 9.6), ZITADEL auto-link without IdP email verification + JWT `exp` replay, Okta Java SDK cross-request response race, Doris MCP metadata SQLi, JSON:API `__proto__` pollution, SiYuan Bazaar zero-click XSS→Electron RCE, Mattermost + NiFi route authorization drift (18 GHSAs)](alerts/2026-09-16-saml-tenant-claim-mcp-metadata-jsonapi-marketplace-and-route-authorization-ghsa.md)
- [Identity-provider authority boundaries: ZITADEL OAuth2 token-exchange provenance/scope-containment break (CVSS 8.1), Keycloak first-broker-login link-proof never revoked after link or unlink, Nezha Host-header redirect_uri regression on empty dashboard_host default (3 GHSAs)](alerts/2026-09-16-zitadel-keycloak-nezha-identity-provider-authority-boundaries-ghsa.md)
- [KEV wave 2026-09-09→16: NetScaler alternate-path auth bypass, MikroTik RouterOS pre-auth username-syntax privesc + btest memory leak, Cisco Secure Email Gateway email-parsing SQLi→root RCE, Cisco ISE unauth API auth bypass (CVSS 10.0), JFrog Artifactory scope/issuance drift, GitLab unauth commits-API file read, ScreenConnect client session gate (13 KEV entries, operator sweep angles)](alerts/2026-09-15-kev-wave-netscaler-cisco-routeros-jfrog-gitlab-screenconnect.md)
- [AI/agent local-surface week: MCP DNS-rebinding on local tool listeners, header-steered token-attaching SSRF, alternate-auth-path parity breaks, expression-sandbox grammar escapes, wildcard OAuth subjects, SAML tenant-from-asserted-email (44 GHSAs)](alerts/2026-09-15-mcp-dns-rebinding-alternate-auth-path-and-sandbox-boundaries-ghsa.md)



































































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
