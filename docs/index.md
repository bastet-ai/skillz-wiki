---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [N-able N-Central pre-auth RCE KEV "static code injection" (CVE-2026-86218): CWE-96 pre-authentication remote code execution on the N-Central server, KEV 2026-09-08 with forensic-triage flag, 2026-09-11 due — generated-artifact audit and repeat-KEV route-family workflow](alerts/2026-09-09-n-able-n-central-preauth-rce-static-code-injection-kev-cve-2026-86218.md)
- [Okta Access Gateway / Hyperdrive trust-boundary cluster (17 GHSAs): generated-config injection into OAG nginx/PHP/OS-command/eval writers, client-header pass-through identity source, SAML→LDAP/SQL injection, protected-rule bypass, assertion/secret leakage into logs and MSI properties, and agent-side verdict/integrity gaps](alerts/2026-09-09-okta-oag-hyperdrive-config-injection-and-identity-boundaries-ghsa.md)
- [XenForo before 2.3.13 trust-boundary cluster: OAuth2/PKCE token-lifecycle breaks (empty client_secret/code_verifier skip validation, authz-code reuse, refresh-token replay, redirect-URI binding), PayPal REST webhook unverified-external trust (fail-open signature, payment replay, cert-URL SSRF), passkey MFA bypass, and Windows backslash style-archive traversal (14 GHSAs)](alerts/2026-09-08-xenforo-oauth-pkce-webhook-mfa-and-traversal-boundaries-ghsa.md)
- [Ivanti Neurons for ITSM before 2026.2: five deserialization sinks (three unauthenticated) and three missing-authorization code-execution routes — the two-axis ITSM/CMDB appliance RCE audit (8 GHSAs)](alerts/2026-09-08-ivanti-neurons-itsm-deserialization-and-missing-authz-ghsa.md)
- [hawtio-operator OpenShift operator trust-boundary cluster: Service-CA private-key cert minting with attacker-controlled CN → arbitrary in-cluster service identity, tenant-controlled OAuth redirect on an auto-grant public client → consentless token theft, and ClusterRole all-namespace Secret read → operator-pod = cluster-secret-dump (3 GHSAs)](alerts/2026-09-08-hawtio-operator-openshift-service-ca-oauth-and-secrets-boundaries-ghsa.md)
- [knowns agent-server trust boundaries + Lara Dashboard admin-privilege breaks: unauth management API with public-tunnel republish, MCP tool-argument filesystem traversal, `code.replace` writing shell startup/SSH files, read-only-classification auth bypass, repo-config LSP binary exec, unauth import/template file write+read, embedding-model-test SSRF oracle; non-Superadmin marketplace module install RCE, `settings.edit` core-upgrade zip over live source, unauthorized post-builder media upload (11 GHSAs)](alerts/2026-09-08-knowns-mcp-file-boundaries-and-lara-dashboard-admin-breaks-ghsa.md)
- [389 Directory Server auth-boundary cluster, plus JetBrains, LibreNMS, and MISP trust boundaries: SASL PLAIN stale-identity crossbind to Directory Manager, Cockpit DN→shell RCE, SELFDN empty-DN ACI match, SASL I/O underflow; YouTrack Helpdesk self-asserted email ATO, Hub unauth trusted-service superuser, cross-tenant token cache; LibreNMS numeric-token type-coercion bypass + graph_title argument injection; MISP feed-redirect SSRF with credential forwarding (12 GHSAs)](alerts/2026-09-07-389-directory-server-auth-bypasses-and-jetbrains-librenms-trust-boundaries-ghsa.md)
- [AVideo notify file-write, socket-callback, and rate-limit boundary batch: unauth file write via replayed notify ciphertext, view-stats hash-param user-record leak, bot-UA rate-limit bypass, YPTSocket callback dispatch XSS, weak `rand()` external-login passwords (5 GHSAs)](alerts/2026-09-05-avideo-notify-filewrite-socket-callback-rate-limit-ghsa.md)
- [Agent/LLM + dev-console unauth wave: AutoAgent unauth TCP root RCE, Cua env-gated auth skip, SQL Chat unauth API-to-DB SQL relay, Coolify OAuth email-collision session mint, Axolotl `trust_remote_code` model-load RCE, MindsDB/Webstudio/Rowboat/Sim URL-relay SSRF (9 GHSAs)](alerts/2026-09-05-agent-ai-devconsole-unauth-rce-sql-relay-and-oauth-session-mint-ghsa.md)
- [Unauth RCE/admin KEV wave: Kestra suffix-match auth bypass → workflow RCE (CVE-2026-49869), Artifactory default-config unauth admin (CVE-2026-82329), and Sangoma Switchvox `/pa` PhoneIP SQLi → RCE (CVE-2026-9586)](alerts/2026-09-05-kestra-artifactory-switchvox-unauth-rce-admin-kev-ghsa.md)


































































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
