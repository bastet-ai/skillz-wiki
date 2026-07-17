---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Prompt loader, MCP memory, and upload filename checks](alerts/2026-07-17-prompt-memory-upload-file-boundaries-ghsa.md)
- [MCP token, codegen, and map-import SSRF checks](alerts/2026-07-17-mcp-codegen-ssrf-boundaries-ghsa.md)
- [vLLM media/batch SSRF and remote-code trust follow-ups](alerts/2026-07-17-axios-ssh-vllm-runtime-boundaries-ghsa.md#vllm-media-and-batch-ssrf-checks)
- [Gitea Composer package source-link checks](alerts/2026-06-17-gitea-langchain4j-hapi-agent-websocket-boundary-batch-ghsa.md#july-17-gitea-composer-package-source-link-follow-up)
- [Axios proxy, SSH constraint, and vLLM runtime-channel checks](alerts/2026-07-17-axios-ssh-vllm-runtime-boundaries-ghsa.md)
- [JWT algorithm-confusion testing](methodology/jwt-algorithm-confusion-testing.md)
- [NLTK encoded resource traversal checks](alerts/2026-07-15-local-ai-app-ssrf-file-boundaries-ghsa.md#nltk-nltkdataload-encoded-traversal-checks)
- [ArcadeDB, Nuclio, and Pheditor control-boundary checks](alerts/2026-07-16-arcadedb-nuclio-pheditor-boundaries-ghsa.md)
- [Ansible Galaxy role dependency argument checks](alerts/2026-06-19-framework-report-iac-mcp-cms-package-boundaries-ghsa.md#july-16-ansible-galaxy-role-dependency-update)
- [Gateway, service-mesh, and local MCP boundary checks](alerts/2026-07-16-gateway-mesh-mcp-boundary-ghsa.md)

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
