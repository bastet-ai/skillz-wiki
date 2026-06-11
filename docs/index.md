---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MCP tool, codegen, redirect, and router boundaries](alerts/2026-06-11-mcp-codegen-redirect-and-router-boundaries-ghsa.md)
- [Guzzle PSR-7 host and XML serialization boundaries](alerts/2026-06-11-guzzle-psr7-host-and-xml-boundary-ghsa.md)
- [Netty DNS and Redis codec protocol-boundary checks](alerts/2026-06-11-netty-dns-redis-protocol-codec-boundaries-ghsa.md)
- [Undertow proxy-parser request-smuggling boundary](alerts/2026-06-11-undertow-proxy-parser-request-smuggling-boundary-ghsa.md)
- [Keycloak account-API feature-flag boundary](alerts/2026-06-10-keycloak-account-api-feature-flag-boundary-ghsa.md)
- [Nebula Mesh API-key redirect and mesh-management boundaries](alerts/2026-06-08-nebula-fuxa-magicmirror-langflow-mcp-boundary-batch-ghsa.md)
- [PDM wheel and project-local file-write boundaries](alerts/2026-06-10-pdm-wheel-and-project-local-file-write-boundaries-ghsa.md)
- [Claude Code Action MCP and Baileys event-boundary checks](alerts/2026-06-10-claude-code-action-mcp-and-baileys-event-boundaries-ghsa.md)
- [Litestar and Fission builder boundary checks](alerts/2026-06-10-litestar-fission-builder-boundary-batch-ghsa.md)
- [OpenTelemetry ServiceMonitor token-file boundary](alerts/2026-06-10-opentelemetry-servicemonitor-token-file-boundary-ghsa.md)

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
