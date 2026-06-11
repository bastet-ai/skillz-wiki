---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Ivanti Sentry unmanaged-appliance command boundary](alerts/2026-06-11-ivanti-sentry-unmanaged-appliance-boundary-kev.md)
- [CodeIgniter4 upload extension validation boundary](alerts/2026-06-11-codeigniter-upload-extension-boundary-ghsa.md)
- [Kolibri SSRF, Hapi static-file, Keycloak IDP, Flowise vector-store, and Arc debug boundaries](alerts/2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md)
- [Sharp generic-download storage-object boundary](alerts/2026-06-11-sharp-generic-download-storage-boundary-ghsa.md)
- [MCP tool, codegen, redirect, and router boundaries](alerts/2026-06-11-mcp-codegen-redirect-and-router-boundaries-ghsa.md)
- [Guzzle PSR-7 host and XML serialization boundaries](alerts/2026-06-11-guzzle-psr7-host-and-xml-boundary-ghsa.md)
- [Netty DNS and Redis codec protocol-boundary checks](alerts/2026-06-11-netty-dns-redis-protocol-codec-boundaries-ghsa.md)
- [Undertow proxy-parser request-smuggling boundary](alerts/2026-06-11-undertow-proxy-parser-request-smuggling-boundary-ghsa.md)
- [Keycloak account-API feature-flag boundary](alerts/2026-06-10-keycloak-account-api-feature-flag-boundary-ghsa.md)
- [Nebula Mesh API-key redirect and mesh-management boundaries](alerts/2026-06-08-nebula-fuxa-magicmirror-langflow-mcp-boundary-batch-ghsa.md)

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
