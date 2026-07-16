---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [ArcadeDB, Nuclio, and Pheditor control-boundary checks](alerts/2026-07-16-arcadedb-nuclio-pheditor-boundaries-ghsa.md)
- [Ansible Galaxy role dependency argument checks](alerts/2026-06-19-framework-report-iac-mcp-cms-package-boundaries-ghsa.md#july-16-ansible-galaxy-role-dependency-update)
- [Gateway, service-mesh, and local MCP boundary checks](alerts/2026-07-16-gateway-mesh-mcp-boundary-ghsa.md)
- [FortiSandbox command-wrapper boundary checks](alerts/2026-07-16-fortisandbox-command-wrapper-boundary-kev.md)
- [Diffusers custom-pipeline model-loading boundary checks](alerts/2026-07-16-diffusers-custom-pipeline-model-loading-ghsa.md)
- [Apple container pf rule-injection boundary checks](alerts/2026-07-16-apple-container-pf-rule-injection-ghsa.md)
- [Node host-inventory, Rails component, search deserialization, and operator boundary checks](alerts/2026-07-15-node-rails-search-operator-boundaries-ghsa.md)
- [TensorZero, ToolHive, local app, vault, and MCP documentation boundary checks](alerts/2026-07-15-local-ai-app-ssrf-file-boundaries-ghsa.md)
- [LangBot MCP STDIO command boundary checks](alerts/2026-07-15-langbot-mcp-stdio-command-boundary-ghsa.md)
- [Keycloak backchannel logout SSRF and UMA CORS origin checks](alerts/2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md#july-15-keycloak-backchannel-logout-ssrf-and-uma-cors-follow-up)

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
