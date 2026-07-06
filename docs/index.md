---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Coder cross-agent redirect file-authority follow-up](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md#july-6-late-coder-cross-agent-redirect-follow-up)
- [9router provider, database, and rate-limit follow-up](alerts/2026-07-02-developer-dashboard-identity-file-boundaries-ghsa.md#july-6-9router-provider-usage-database-and-rate-limit-follow-up)
- [OpenRemote crosstab export SQL follow-up](alerts/2026-07-06-cilium-formie-openremote-parser-boundaries-ghsa.md#july-6-openremote-datapoint-crosstab-sql-follow-up)
- [Langroid Neo4jChatAgent Cypher boundary follow-up](alerts/2026-02-07-langroid-waf-bypass-rce-ghsa-x34r-63hx-w57f.md#july-6-neo4jchatagent-cypher-boundary-follow-up)
- [Craft CMS referrer and file-read follow-up](alerts/2026-05-06-craft-pyload-and-wooey-app-authorization-boundary-batch-ghsa.md#july-6-craft-cms-referrer-and-file-read-follow-up)
- [uutils coreutils filesystem, temp-file, and script-parity follow-up](alerts/2026-04-29-uutils-coreutils-safety-and-data-integrity-batch-ghsa.md#july-6-filesystem-temp-file-and-script-parity-follow-up)
- [Coder workspace app-proxy, identity, and AI Bridge follow-up](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md#july-6-coder-workspace-app-proxy-identity-and-ai-bridge-follow-up)
- [OpenRemote KNX import and realm-boundary follow-up](alerts/2026-07-06-cilium-formie-openremote-parser-boundaries-ghsa.md#july-6-openremote-knx-import-and-realm-boundary-follow-up)
- [Linuxfabrik monitoring plugin command-construction follow-up](alerts/2026-07-03-snapshot-form-sudoers-boundaries-ghsa.md#july-6-linuxfabrik-command-construction-follow-up)
- [Nginx-UI hidden settings, certificate file-write, and ordered-query boundary checks](alerts/2026-07-06-nginx-ui-settings-command-boundaries-ghsa.md)

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
