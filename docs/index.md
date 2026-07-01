---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Rancher Fleet, JWKS cache, QUIC client, and SDK parameter boundary checks](alerts/2026-07-01-rancher-fleet-jwks-client-boundaries-ghsa.md)
- [ORAS registry realm and layer-extraction update](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md#july-1-oras-registry-and-layer-extraction-update)
- [SurrealDB query, session, and network-policy follow-up](alerts/2026-06-19-surrealdb-anki-agent-files-ssrf-boundary-batch-ghsa.md#july-1-surrealdb-query-session-and-network-policy-follow-up)
- [MCP Toolbox DNS-rebinding update](alerts/2026-06-19-framework-report-iac-mcp-cms-package-boundaries-ghsa.md#july-1-mcp-toolbox-dns-rebinding-update)
- [Agent repository, MCP file-read, and registry trust-boundary checks](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md)
- [Twig cached-template sandbox allow-list update](alerts/2026-06-05-twig-tostring-bugsink-project-boundary-batch-ghsa.md#july-1-twig-cached-template-sandbox-allow-list-update)
- [MCP SSRF, geospatial search, and model-ingestion boundary checks](alerts/2026-07-01-mcp-geospatial-model-ingestion-boundaries-ghsa.md)
- [Bouncy Castle CTR keystream-reuse boundary check](alerts/2026-07-01-bouncy-castle-ctr-keystream-boundary-ghsa.md)
- [Model parser, deserialization, and identity-extractor boundary checks](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md)
- [Template, OIDC discovery, path-prefix, and job-dashboard boundary checks](alerts/2026-06-30-template-oidc-path-job-boundaries-ghsa.md)

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
