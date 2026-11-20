---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**One agent certificate roots the whole fleet: Postgres Enterprise Manager let any monitored host create SQL and shell jobs on every other agent, read the CA key that mints agent certs as the postgres user, and decrypt every stored server password with a key identical across all installs (9 GHSAs, fixed 10.6.1)**](alerts/2026-11-20-pem-wave-agent-certificate-fleet-rce-shared-key-credentials-and-definer-search-path-ghsa.md)
- [**The DMARC mailbox is the entry point: Poste.io saved mail to dmarc-reports@ your domain with no sender verification and a root script unpacked its attachments through the shell, so anyone who can reach port 25 gets root in the mail container (critical, fixed 2.5.22)**](alerts/2026-11-20-poste-io-dmarc-report-ingestion-root-rce-ghsa.md)
- [**Your clone runs their code: Git LFS let a repo's own `.lfsconfig` bypass its key allowlist, submodule config newlines forge a transfer command, SSH URL paths reach a remote shell unquoted, and redirects leak Cookies to the wrong host (4 GHSAs, fixed 3.8.1)**](alerts/2026-11-20-git-lfs-wave-repo-config-command-execution-ssh-url-injection-and-cookie-forwarding-ghsa.md)
- [**Any IdP will hand you the account: FlowIntel's SSO providers resolve a claimed email to accounts created by other sign-in methods, its Matrix relay authorizes with the bot's role and trusts editable profile names, its approval-locked tasks are still writable through reorder, link, convert, and delete side doors, and a shared MCP session runs your tool calls under someone else's key (30 GHSAs, before 4.1.0)**](alerts/2026-11-20-flowintel-wave-sso-email-collision-relay-bot-role-confusion-and-parent-only-idor-ghsa.md)
- [**Read-only in name only: XOneManager let a project member publish modified firmware updates to the whole managed fleet, run SQL as the service account across databases including the auth store, and create projects bound to any database name (6 GHSAs, 3.8.3.0)**](alerts/2026-11-20-xonemanager-wave-readonly-member-update-publication-and-service-account-sql-ghsa.md)
- [**The fee-bump prompt is the exploit: Electrum trusted its server's mempool view without checking signatures, so a malicious server swallows your broadcast, shows a suffix-matched attacker tx instead, and your RBF click pays the attacker (critical, before 4.8.3, in the wild)**](alerts/2026-09-16-secret-server-identity-crypto-boundaries-and-ot-hardcoded-update-keys-ghsa.md)
- [**Etherpad's path sanitizer runs before the handler converts backslashes, so one anonymous `..%5C` GET on `/static/plugins/` reads `/etc/passwd`, `settings.json`, and `/proc/self/environ` with the admin password inside, and the plugin installer finishes the RCE chain (9.8, before 3.3.3, reverse proxies don't help, `%5C` passes through)**](alerts/2026-11-20-etherpad-static-handler-post-sanitizer-backslash-traversal-unauth-file-read-to-admin-rce-ghsa.md)
- [**The signature gate lives on only one promotion path: in Mareforma an unsigned claim converges with a signed peer and reaches REPLICATED trust, the search endpoint serves forged ESTABLISHED rows the query endpoint drops, and a post-signing Rekor block counts as transparency proof (5 GHSAs)**](alerts/2026-11-19-mareforma-coordinated-wave-signature-blind-convergence-verify-on-read-split-and-unsigned-rekor-metadata-ghsa.md)
- [**The Kotlin DSL sandbox is six sandboxes: TeamCity leaked through public reflection, boot classpath, script definitions, and two callbacks, while project viewers downloaded whole settings archives and guests pushed VCS labels with the server's stored credentials (82 GHSAs, before 2026.2.1 / 2026.1.5)**](alerts/2026-11-19-teamcity-coordinated-wave-kotlin-dsl-sandbox-escapes-viewer-credential-reads-and-guest-vcs-deputy-ghsa.md)
- [**Your fleet tokens are only as case-sensitive as the MySQL column: Fleet invite, email-change, MFA, and session tokens lived in `utf8mb4_unicode_ci` so any case-folded copy authenticates, and a team observer's live-query write into the session store lets a self-signed SAML response mint global admin (5 GHSAs)**](alerts/2026-11-19-fleet-coordinated-wave-case-insensitive-token-columns-session-store-saml-forgery-and-deprecated-enqueue-split-ghsa.md)




