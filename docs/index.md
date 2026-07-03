---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [fast-mcp Telegram and Steeltoe actuator follow-up](alerts/2026-07-02-developer-dashboard-identity-file-boundaries-ghsa.md#july-3-fast-mcp-telegram-and-steeltoe-actuator-follow-up)
- [Snapshot-write, SSR form fallback, and sudoers argument boundary checks](alerts/2026-07-03-snapshot-form-sudoers-boundaries-ghsa.md)
- [electerm remote filename command and transfer-path follow-up](alerts/2026-05-08-electerm-terminal-command-boundary-ghsa-8x35-hph8-37hq.md#july-3-expansion-remote-filenames-file-helpers-and-transfer-paths)
- [Rich-text import SSRF testing: redirect revalidation follow-up](methodology/rich-text-import-ssrf-testing.md#redirect-revalidation-harness)
- [Developer dashboard, identity handoff, and file-serving boundary checks](alerts/2026-07-02-developer-dashboard-identity-file-boundaries-ghsa.md)
- [Mautic campaign import, theme template, API owner-scope, and Focus SSRF checks](alerts/2026-07-02-mautic-campaign-theme-api-focus-boundaries-ghsa.md)
- [Craft CMS forced-folder-move and bulk-duplicate follow-up](alerts/2026-05-06-craft-pyload-and-wooey-app-authorization-boundary-batch-ghsa.md#july-2-forced-folder-move-and-bulk-duplicate-follow-up)
- [Grackle PowerLine worktree branch injection follow-up](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md#july-2-grackle-powerline-worktree-branch-injection-follow-up)
- [SFTPGo share, SpecifyJS URL/GraphQL, Casdoor SAML, and JWT empty-key checks](alerts/2026-07-02-sftpgo-specifyjs-casdoor-token-boundaries-ghsa.md)
- [Craft CMS peer-permission and entry-mutation follow-up](alerts/2026-05-06-craft-pyload-and-wooey-app-authorization-boundary-batch-ghsa.md#july-2-craft-cms-peer-permission-and-entry-mutation-follow-up)

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
