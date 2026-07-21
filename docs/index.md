---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [WordPress REST batch-route and `WP_Query` SQL boundary chain](alerts/2026-07-21-wordpress-rest-batch-query-chain-kev.md)
- [Late parser, tenant, MCP, and token follow-up](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#late-july-21-parser-tenant-mcp-and-token-follow-up)
- [Langflow unauthenticated `exec_globals` KEV follow-up](alerts/2026-06-19-langflow-mailpit-outerbase-miniflux-render-boundaries-ghsa.md#july-21-unauthenticated-exec_globals-validation-route-kev-follow-up)
- [PKI, MCP, proxy-auth, updater, and cryptographic boundary checks](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md)
- [rclone Remote Control and inline-remote boundary checks](alerts/2026-07-21-rclone-remote-control-boundaries-ghsa.md)
- [Picklescan `idlelib` scanner/loader differential follow-up](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#picklescan-scanner-bypass-regression)
- [LightGlue nested model-loader trust follow-up](alerts/2026-07-16-diffusers-custom-pipeline-model-loading-ghsa.md#july-21-lightglue-nested-loader-follow-up)
- [Gogs reverse-proxy identity-header follow-up](alerts/2026-06-22-gogs-opencti-motioneye-paymenter-boundaries-ghsa.md#reverse-proxy-authentication-header-harness)
- [Astro late adapter-regex, path, render, RSS, and transition follow-ups](alerts/2026-07-18-nest-astro-route-render-fetch-boundaries-ghsa.md#july-20-late-follow-up-adapter-regex-path-spread-key-rss-and-transition-contexts)
- [Pillow TGA RLE output-disclosure follow-up](alerts/2026-07-20-cloudreve-pillow-token-image-boundaries-ghsa.md#pillow-tga-rle-output-disclosure-check)



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
