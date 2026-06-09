---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Puma PROXY, Arc DuckDB, and phpMyFAQ boundary checks](alerts/2026-06-09-puma-arc-phpmyfaq-boundary-batch-ghsa.md)
- [Nebula Mesh, FUXA, MagicMirror, Langflow, MCP, and local automation boundaries](alerts/2026-06-08-nebula-fuxa-magicmirror-langflow-mcp-boundary-batch-ghsa.md)
- [Check Point IKEv1 VPN authentication-bypass validation](alerts/2026-06-08-check-point-ikev1-vpn-auth-bypass.md)
- [Budibase, BentoML, Weblate, vLLM, and API/runtime boundary checks](alerts/2026-06-08-budibase-bentoml-weblate-vllm-runtime-boundary-batch-ghsa.md)
- [pyLoad, OpenHands, PyJWT, Netty, and ONNX boundary checks](alerts/2026-06-08-pyload-openhands-pyjwt-netty-onnx-boundary-batch-ghsa.md)
- [LiteLLM, Authlib, Dash uploader, and Vitest boundary checks](alerts/2026-06-08-litellm-authlib-dash-vitest-boundary-batch.md)
- [vm2 WASM, SMTP PROXY, and 1Panel file-write boundaries](alerts/2026-06-08-vm2-proxy-protocol-and-1panel-boundary-batch-ghsa.md)
- [GeoNode service-registration SSRF validation](alerts/2026-06-08-geonode-service-registration-ssrf.md)
- [Agent, SSRF, command, and local IPC boundary checks](alerts/2026-06-07-agent-ssrf-command-and-local-ipc-boundaries-ghsa.md)
- [NLTK, NiceGUI, Picklescan, and ML archive-boundary checks](alerts/2026-06-06-nltk-nicegui-picklescan-ml-archive-boundaries-ghsa.md)

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
