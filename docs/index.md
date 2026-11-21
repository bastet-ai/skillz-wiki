---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Two routes, one RCE: AIT-GUI's query route left your bytes in a static temp file when its error path skipped cleanup, and the run route executes that file as Python because only its sibling got the containment check, unauthenticated (high, fixed 2.5.1)**](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md)
- [**The setup endpoint never closed: Budibase's one-time admin init reads "does a user exist" from a tenant namespace you choose in the request body, so any unused tenantId mints a fresh global admin on self-hosted single-tenant installs (high, <= 3.38.1)**](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md)
- [**The image ID is a file path: MONAI Label's default-off auth plus an unvalidated `image` query parameter let anyone on the network write files anywhere the process can reach, agents weaponized it in September, and CISA still has not listed it (9.8, <= 0.8.5, ITW watch)**](alerts/2026-10-02-ai-serving-rag-stack-authz-and-path-wave-ghsa.md)
- [**One channel never calls the login check: vCenter's VMware Directory Service KEV'd auth bypass lets a network-position attacker skip authentication entirely, vCenter 7.0 has no public fix, and the second VDS bypass of 2026 says every sidecar is its own auth implementation (CVE-2026-123890, KEV)**](alerts/cisa-kev.md)
- [**One agent certificate roots the whole fleet: Postgres Enterprise Manager let any monitored host create SQL and shell jobs on every other agent, read the CA key that mints agent certs as the postgres user, and decrypt every stored server password with a key identical across all installs (9 GHSAs, fixed 10.6.1)**](alerts/2026-11-20-pem-wave-agent-certificate-fleet-rce-shared-key-credentials-and-definer-search-path-ghsa.md)
- [**The DMARC mailbox is the entry point: Poste.io saved mail to dmarc-reports@ your domain with no sender verification and a root script unpacked its attachments through the shell, so anyone who can reach port 25 gets root in the mail container (critical, fixed 2.5.22)**](alerts/2026-11-20-poste-io-dmarc-report-ingestion-root-rce-ghsa.md)
- [**Your clone runs their code: Git LFS let a repo's own `.lfsconfig` bypass its key allowlist, submodule config newlines forge a transfer command, SSH URL paths reach a remote shell unquoted, and redirects leak Cookies to the wrong host (4 GHSAs, fixed 3.8.1)**](alerts/2026-11-20-git-lfs-wave-repo-config-command-execution-ssh-url-injection-and-cookie-forwarding-ghsa.md)
- [**Any IdP will hand you the account: FlowIntel's SSO providers resolve a claimed email to accounts created by other sign-in methods, its Matrix relay authorizes with the bot's role and trusts editable profile names, its approval-locked tasks are still writable through reorder, link, convert, and delete side doors, and a shared MCP session runs your tool calls under someone else's key (30 GHSAs, before 4.1.0)**](alerts/2026-11-20-flowintel-wave-sso-email-collision-relay-bot-role-confusion-and-parent-only-idor-ghsa.md)
- [**Read-only in name only: XOneManager let a project member publish modified firmware updates to the whole managed fleet, run SQL as the service account across databases including the auth store, and create projects bound to any database name (6 GHSAs, 3.8.3.0)**](alerts/2026-11-20-xonemanager-wave-readonly-member-update-publication-and-service-account-sql-ghsa.md)
- [**The fee-bump prompt is the exploit: Electrum trusted its server's mempool view without checking signatures, so a malicious server swallows your broadcast, shows a suffix-matched attacker tx instead, and your RBF click pays the attacker (critical, before 4.8.3, in the wild)**](alerts/2026-09-16-secret-server-identity-crypto-boundaries-and-ot-hardcoded-update-keys-ghsa.md)




