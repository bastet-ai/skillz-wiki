---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [hawtio-operator OpenShift operator trust-boundary cluster: Service-CA private-key cert minting with attacker-controlled CN → arbitrary in-cluster service identity, tenant-controlled OAuth redirect on an auto-grant public client → consentless token theft, and ClusterRole all-namespace Secret read → operator-pod = cluster-secret-dump (3 GHSAs)](alerts/2026-09-08-hawtio-operator-openshift-service-ca-oauth-and-secrets-boundaries-ghsa.md)
- [knowns agent-server trust boundaries + Lara Dashboard admin-privilege breaks: unauth management API with public-tunnel republish, MCP tool-argument filesystem traversal, `code.replace` writing shell startup/SSH files, read-only-classification auth bypass, repo-config LSP binary exec, unauth import/template file write+read, embedding-model-test SSRF oracle; non-Superadmin marketplace module install RCE, `settings.edit` core-upgrade zip over live source, unauthorized post-builder media upload (11 GHSAs)](alerts/2026-09-08-knowns-mcp-file-boundaries-and-lara-dashboard-admin-breaks-ghsa.md)
- [389 Directory Server auth-boundary cluster, plus JetBrains, LibreNMS, and MISP trust boundaries: SASL PLAIN stale-identity crossbind to Directory Manager, Cockpit DN→shell RCE, SELFDN empty-DN ACI match, SASL I/O underflow; YouTrack Helpdesk self-asserted email ATO, Hub unauth trusted-service superuser, cross-tenant token cache; LibreNMS numeric-token type-coercion bypass + graph_title argument injection; MISP feed-redirect SSRF with credential forwarding (12 GHSAs)](alerts/2026-09-07-389-directory-server-auth-bypasses-and-jetbrains-librenms-trust-boundaries-ghsa.md)
- [AVideo notify file-write, socket-callback, and rate-limit boundary batch: unauth file write via replayed notify ciphertext, view-stats hash-param user-record leak, bot-UA rate-limit bypass, YPTSocket callback dispatch XSS, weak `rand()` external-login passwords (5 GHSAs)](alerts/2026-09-05-avideo-notify-filewrite-socket-callback-rate-limit-ghsa.md)
- [Agent/LLM + dev-console unauth wave: AutoAgent unauth TCP root RCE, Cua env-gated auth skip, SQL Chat unauth API-to-DB SQL relay, Coolify OAuth email-collision session mint, Axolotl `trust_remote_code` model-load RCE, MindsDB/Webstudio/Rowboat/Sim URL-relay SSRF (9 GHSAs)](alerts/2026-09-05-agent-ai-devconsole-unauth-rce-sql-relay-and-oauth-session-mint-ghsa.md)
- [Unauth RCE/admin KEV wave: Kestra suffix-match auth bypass → workflow RCE (CVE-2026-49869), Artifactory default-config unauth admin (CVE-2026-82329), and Sangoma Switchvox `/pa` PhoneIP SQLi → RCE (CVE-2026-9586)](alerts/2026-09-05-kestra-artifactory-switchvox-unauth-rce-admin-kev-ghsa.md)
- [CodeWhale / `deepseek-tui` agent-tool trust boundaries: repo-config shell override, git-tool argument injection, SSRF DNS-pinning TOCTOU, and env-symlink leaks (9 GHSAs)](alerts/2026-09-04-codewhale-agent-tool-trust-boundaries-ghsa.md)
- [AI/ML ingestion boundaries: URL-partitioning SSRF, SSRF redirect bypass, checkpoint deserialization, and non-superuser LLM-config overwrite (5 GHSAs)](alerts/2026-09-04-ai-ml-ingestion-ssrf-deserialization-and-config-authorization-ghsa.md)
- [SiYuan kernel: publish-access tiers, localhost-trust admin bypass, and attribute-view SQL/SSTI boundaries (30 GHSAs)](alerts/2026-09-04-siyuan-kernel-publish-tiers-localhost-admin-and-attribute-view-sql-ghsa.md)
- [OpenChoreo: unauth workflow trigger, cross-project command execution, and data-plane access boundaries (5 GHSAs)](alerts/2026-09-04-openchoreo-unauth-trigger-cross-project-command-and-data-plane-ghsa.md)


































































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
