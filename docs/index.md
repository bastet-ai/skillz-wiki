---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Claude Code Action MCP and Baileys event-boundary checks](alerts/2026-06-10-claude-code-action-mcp-and-baileys-event-boundaries-ghsa.md)
- [Litestar and Fission builder boundary checks](alerts/2026-06-10-litestar-fission-builder-boundary-batch-ghsa.md)
- [OpenTelemetry ServiceMonitor token-file boundary](alerts/2026-06-10-opentelemetry-servicemonitor-token-file-boundary-ghsa.md)
- [vLLM and Anyquery boundary checks](alerts/2026-06-10-vllm-lmdeploy-anyquery-boundary-batch-ghsa.md)
- [Nezha, Papra, Pipecat, SimpleSAMLphp, and Hulumi boundary checks](alerts/2026-06-10-nezha-papra-pipecat-simplesaml-hulumi-boundary-batch-ghsa.md)
- [SAML, MCP, OpenMetadata, MVT, and render-boundary checks](alerts/2026-05-21-saml-mcp-metadata-render-boundary-batch-ghsa.md)
- [MCP Java CORS and Ray Dashboard file-boundary checks](alerts/2026-06-10-mcp-java-cors-ray-dashboard-file-boundary-ghsa.md)
- [Pheditor, Dex, Phoenix Storybook, and Symfony Runtime boundary checks](alerts/2026-06-09-pheditor-dex-phoenixstory-symfony-boundary-batch-ghsa.md)
- [Svelte SSR spread and DOM-clobbering boundary checks](alerts/2026-06-09-svelte-ssr-spread-dom-clobbering-boundary-ghsa.md)
- [Net::IMAP raw argument command boundary](alerts/2026-06-09-net-imap-raw-argument-command-boundary-ghsa.md)

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
