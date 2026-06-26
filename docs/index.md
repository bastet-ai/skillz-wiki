---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [HTTP anomaly and WebSocket triage](methodology/http-anomaly-websocket-triage.md)
- [Agent checkpoint, SSH-agent, proxy identity, certificate control-plane, and appliance boundary checks](alerts/2026-06-25-agent-proxy-appliance-boundaries-ghsa-kev.md)
- [Tenant graph, i18n missing-key, and Markdown render boundary checks](alerts/2026-06-25-tenant-i18n-render-boundaries-ghsa.md)
- [OpenAM RADIUS response-binding boundary update](alerts/2026-06-24-olivetin-openam-concrete-boundaries-ghsa.md#openam-radius-response-binding-harness)
- [OpenAM push-registration SNS and token-store boundary update](alerts/2026-06-24-olivetin-openam-concrete-boundaries-ghsa.md#openam-push-registration-and-oauth-token-store-harness)
- [Claude Code `/copy` predictable temporary-file boundary update](alerts/2026-06-10-claude-code-action-mcp-and-baileys-event-boundaries-ghsa.md#claude-code-copy-predictable-temporary-file)
- [Concrete CMS file-manager and Express association CSRF update](alerts/2026-06-23-concrete-cms-package-file-block-boundaries-ghsa.md#later-june-24-file-manager-and-express-association-csrf-update)
- [Concrete CMS authorization, file, and package-control boundary update](alerts/2026-06-23-concrete-cms-package-file-block-boundaries-ghsa.md#june-24-concrete-cms-authorization-and-package-control-update)
- [OliveTin action-runner, OpenAM identity-store, and Concrete CMS trusted-render boundary checks](alerts/2026-06-24-olivetin-openam-concrete-boundaries-ghsa.md)
- [Hono JSX, n8n workflow, Flowise token, and Picklescan scanner-boundary checks](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md)

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
