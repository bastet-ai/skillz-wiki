---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Agent, SSRF, command, and local IPC boundary checks](alerts/2026-06-07-agent-ssrf-command-and-local-ipc-boundaries-ghsa.md)
- [NLTK, NiceGUI, Picklescan, and ML archive-boundary checks](alerts/2026-06-06-nltk-nicegui-picklescan-ml-archive-boundaries-ghsa.md)
- [lxml, LangChain, Langflow, and ML/AI file-boundary checks](alerts/2026-06-06-lxml-langchain-langflow-ml-ai-boundary-batch-ghsa.md)
- [Twig `__toString()` sandbox and Bugsink project-boundary checks](alerts/2026-06-05-twig-tostring-bugsink-project-boundary-batch-ghsa.md)
- [Twig source-policy sandbox, Shopper Livewire, and TinyMCE `data-mce` boundaries](alerts/2026-06-05-twig-shopper-tinymce-boundary-batch-ghsa.md)
- [TinyMCE nested-SVG, skillctl path-safety, and Admidio export-CSRF boundaries](alerts/2026-06-05-tinymce-skillctl-admidio-boundary-batch-ghsa.md)
- [NASA AIT, Gradio, Diffusers, Fickling, and identity boundary batch](alerts/2026-06-05-nasa-ait-gradio-diffusers-fickling-boundary-batch-ghsa.md)
- [DbGate, Sync-in Server, and Flux source-controller boundary batch](alerts/2026-06-05-dbgate-syncin-flux-rce-ssrf-file-boundaries-ghsa.md)
- [NocoDB, MCP Kubernetes, Omni, Authlib, and runtime boundary batch](alerts/2026-06-05-nocodb-mcp-kubernetes-omni-authlib-boundary-batch-ghsa.md)
- [Crawl4AI, changedetection.io, Dagster, and Django file/query boundary batch](alerts/2026-06-05-crawl4ai-changedetection-dagster-django-file-query-boundaries-ghsa.md)

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
