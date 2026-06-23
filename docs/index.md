---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [BoxLite sandbox and Alist storage-boundary checks](alerts/2026-06-23-boxlite-alist-storage-boundaries-ghsa.md)
- [Jupyter Enterprise Gateway kernel-ID and Cloudinary upload-signing boundary checks](alerts/2026-06-23-jupyter-eg-cloudinary-signing-boundaries-ghsa.md)
- [Budibase datasource/PWA/webhook, Gogs forge tenant/protocol/merge, Actual export/session, and automation boundary checks](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md)
- [Glances XML-RPC, Actual sync-server, OpenDJ, and Spinnaker control-plane boundary checks](alerts/2026-06-22-glances-opendj-spinnaker-control-plane-boundaries-ghsa.md)
- [Container build/runtime, OpenAM, XWiki, and ComfyUI boundary checks](alerts/2026-06-22-container-openam-xwiki-comfyui-boundaries-ghsa.md)
- [AVideo Authorize.Net webhook and Docker dotfile validation update](alerts/2026-06-04-avideo-openmeter-spree-boundary-batch-ghsa.md#june-22-authorizenet-webhook-and-docker-dotfile-update)
- [Gogs proxy-auth, OpenCTI ingestion SSRF, motionEye file-read, and Paymenter upload boundary checks](alerts/2026-06-22-gogs-opencti-motioneye-paymenter-boundaries-ghsa.md)
- [JCE profile upload, LiteSpeed cPanel symlink, and Cisco SD-WAN file-write boundary checks](alerts/2026-06-20-jce-litespeed-cisco-kev-boundaries.md)
- [Agent, secret-store, identity-token, and renderer boundary checks](alerts/2026-06-19-agent-secret-identity-render-boundary-batch-ghsa.md)
- [SurrealDB, Anki, MCP, file-read, SSRF, and workflow boundary checks](alerts/2026-06-19-surrealdb-anki-agent-files-ssrf-boundary-batch-ghsa.md)

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
