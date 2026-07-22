---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [n8n identity, credential, node, and filesystem boundary wave](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#late-july-22-n8n-identity-credential-node-and-filesystem-boundary-wave)
- [Netty HTTP bridge, text-protocol, CORS, XML, and OCSP checks](alerts/2026-06-11-netty-dns-redis-protocol-codec-boundaries-ghsa.md#july-22-http-bridge-text-protocol-cors-xml-and-ocsp-follow-up)
- [Dompdf data-URI SVG nested-resource validation](alerts/2026-07-22-dompdf-local-file-boundaries-ghsa.md#data-uri-svg-nested-resource-validation)
- [Agentic DAST unintended-solution-path auditing](methodology/agentic-dast-benchmark-validation.md#audit-unintended-solution-paths)
- [Dompdf local-file confinement and existence-oracle checks](alerts/2026-07-22-dompdf-local-file-boundaries-ghsa.md)
- [Check Point SmartConsole application-token authentication boundary](alerts/2026-07-22-check-point-smartconsole-application-token-auth-boundary.md)
- [n8n agent, Git TOCTOU, browser, and JWT credential-artifact checks](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#july-22-n8n-agent-git-browser-and-credential-artifact-follow-up)
- [Wagtail `TableBlock` class-attribute render boundary](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#july-22-wagtail-tableblock-attribute-rendering-follow-up)
- [ProjectDiscovery internal network scanning](skills/projectdiscovery-internal-network-scanning.md)
- [Final July 21 URL, schema-generation, sanitizer, Jackson, and xDS checks](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#final-july-21-url-schema-generation-sanitizer-and-authorization-boundaries)





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
