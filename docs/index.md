---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Ech0 scoped-token and dashboard-log boundary checks](alerts/2026-06-02-ech0-scoped-token-and-log-boundary-ghsa.md)
- [Apache Airflow Variable, event-log, and JWT cookie boundary batch](alerts/2026-06-01-airflow-variable-eventlog-cookie-boundary-batch-ghsa.md)
- [ActiveMQ Jolokia, Flink operator `jarURI`, and WebLogic middleware boundary batch](alerts/2026-06-01-activemq-flink-weblogic-control-plane-boundary-batch.md)
- [Mattermost shared-channel, AI rewrite, support-packet secret, and chatops boundary batch](alerts/2026-06-01-mattermost-shared-channel-ai-secret-boundary-batch-ghsa.md)
- [Mattermost OAuth/command boundaries, kas SHA-like branch checkout, and PraisonAI tenant IDOR batch](alerts/2026-06-01-mattermost-kas-praisonai-boundary-batch-ghsa.md)
- [Rattler/Pixi install writes, Vitest dev-server code execution, DOMPurify selectedcontent XSS, and MCP HTTP auth boundaries](alerts/2026-06-01-rattler-vitest-dompurify-mcp-boundary-batch-ghsa.md)
- [Sentry Python SDK subprocess environment boundary](alerts/2026-06-01-sentry-python-subprocess-env-boundary-ghsa.md)
- [Fission router invocation and runtime token boundaries](alerts/2026-06-01-fission-router-and-runtime-token-boundary-batch-ghsa.md)
- [Git LFS symlink and hard-link working-tree write boundaries](alerts/2026-05-31-git-lfs-symlink-working-tree-write-boundary-ghsa.md)
- [phpMyFAQ password-reset and admin IDOR account-takeover boundaries](alerts/2026-05-31-phpmyfaq-account-takeover-boundary-ghsa.md)

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
