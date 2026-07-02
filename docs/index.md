---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Coder workspace, Dulwich submodule, and Kerberos Hub redirect follow-up](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md#july-2-coder-dulwich-and-kerberos-hub-follow-up)
- [Langroid SQL and file-tool boundary follow-up](alerts/2026-02-07-langroid-waf-bypass-rce-ghsa-x34r-63hx-w57f.md#july-2-langroid-sql-and-file-tool-boundary-follow-up)
- [OpenClaw approval/tooling and MCP memory document-boundary checks](alerts/2026-07-02-openclaw-mcp-memory-agent-boundaries-ghsa.md)
- [GoFiber forwarded-IP and Artemis STOMP routing-type boundary checks](alerts/2026-07-02-gofiber-artemis-trust-boundaries-ghsa.md)
- [Agent-guided fuzzing campaigns](methodology/agent-guided-fuzzing-campaigns.md)
- [Ghost preview-cache, goshs share/WebDAV, and export file-boundary checks](alerts/2026-07-02-ghost-goshs-export-boundaries-ghsa.md)
- [Contour cookie-rewrite Lua boundary check](alerts/2026-07-01-contour-cookie-rewrite-lua-boundary-ghsa.md)
- [Keycloak CIBA, request-object, admin-role, client-policy, and organization updates](alerts/2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md#july-1-keycloak-ciba-request-object-and-admin-role-toctou-follow-up)
- [Langroid `TableChatAgent` WAF-bypass boundary check](alerts/2026-02-07-langroid-waf-bypass-rce-ghsa-x34r-63hx-w57f.md)
- [MCP authorization and ORAS redirect/file-store follow-up](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md#july-1-mcp-authorization-and-oras-redirectfile-store-follow-up)

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
