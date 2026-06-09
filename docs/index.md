---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [pretix email placeholder injection](alerts/2026-06-09-pretix-email-placeholder-injection.md)
- [shell-quote newline operator boundary](alerts/2026-06-09-shell-quote-newline-operator-boundary-ghsa.md)
- [Fides banner override, Froxlor API 2FA, and Ironic image-boundary checks](alerts/2026-06-09-fides-froxlor-ironic-boundary-batch-ghsa.md)
- [Auth parser, device-flow, HAXcms token, and redirect-cookie boundaries](alerts/2026-06-09-auth-device-haxcms-redirect-boundary-batch-ghsa.md)
- [File Browser command-scope and web3.py CCIP SSRF boundaries](alerts/2026-06-09-filebrowser-command-scope-and-web3-ccip-ssrf-boundary-ghsa.md)
- [Puma PROXY, Arc DuckDB, and phpMyFAQ boundary checks](alerts/2026-06-09-puma-arc-phpmyfaq-boundary-batch-ghsa.md)
- [Nebula Mesh, FUXA, MagicMirror, Langflow, MCP, and local automation boundaries](alerts/2026-06-08-nebula-fuxa-magicmirror-langflow-mcp-boundary-batch-ghsa.md)
- [Check Point IKEv1 VPN authentication-bypass validation](alerts/2026-06-08-check-point-ikev1-vpn-auth-bypass.md)
- [Budibase, BentoML, Weblate, vLLM, and API/runtime boundary checks](alerts/2026-06-08-budibase-bentoml-weblate-vllm-runtime-boundary-batch-ghsa.md)
- [pyLoad, OpenHands, PyJWT, Netty, and ONNX boundary checks](alerts/2026-06-08-pyload-openhands-pyjwt-netty-onnx-boundary-batch-ghsa.md)

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
