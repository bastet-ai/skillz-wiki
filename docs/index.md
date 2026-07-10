---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MCP Atlassian, SafeInstall, BabelDOC, MLflow, Windmill, and NotrinosERP boundary checks](alerts/2026-07-10-mcp-agent-package-workflow-boundaries-ghsa.md)
- [File Browser proxy-auth, SiYuan local-app, Authorizer OAuth, and Pimcore CMS boundary checks](alerts/2026-07-10-filebrowser-siyuan-authorizer-pimcore-boundaries-ghsa.md)
- [MCP Atlassian DNS-rebinding TOCTOU SSRF guard bypass checks](alerts/2026-07-07-agent-deploy-ssrf-identity-boundaries-ghsa.md#mcp-atlassian-dns-rebinding-toctou-checks)
- [Joomla form/event upload KEV follow-up for Balbooa Forms and iCagenda](alerts/2026-07-08-joomla-page-builder-coldfusion-kev-boundaries.md#joomla-form-and-event-upload-follow-up)
- [DesktopCommanderMCP file-reader SSRF and MCP regex resource checks](alerts/2026-07-07-agent-deploy-ssrf-identity-boundaries-ghsa.md#mcp-file-reader-ssrf-and-regex-resource-checks)
- [HTTP client, package cache, identity, API serializer, and access-log boundary checks from July 10 GHSA updates](alerts/2026-07-10-http-client-package-cache-identity-boundaries-ghsa.md)
- [Rich-text import SSRF testing: Kimai-style Markdown invoice PDF renderer update](methodology/rich-text-import-ssrf-testing.md#why-this-matters)
- [Jupyter Server sibling-prefix path traversal validation update](alerts/2026-05-05-jupyter-vm2-and-token-type-boundary-batch-ghsa.md#jupyter-server-sibling-prefix-path-traversal-follow-up)
- [Sylius route-family drift and YesWiki form-builder sink checks](alerts/2026-07-09-agent-cms-render-export-boundaries-ghsa.md#sylius-payment-order-state-and-route-family-drift)
- [Agentic DAST benchmark fixtures and SSRF sink-validation controls](methodology/agentic-dast-benchmark-validation.md#turn-scanner-misses-into-benchmark-fixtures)

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
