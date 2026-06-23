---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [OctoPrint upload reserved-field file-boundary checks](alerts/2026-06-23-octoprint-upload-reserved-field-boundary-ghsa.md)
- [AVideo Meet participant User-Agent admin-DOM update](alerts/2026-06-04-avideo-openmeter-spree-boundary-batch-ghsa.md#june-23-avideo-meet-participant-user-agent-update)
- [motionEye absolute-path, action, and pass-the-hash chain updates](alerts/2026-06-22-gogs-opencti-motioneye-paymenter-boundaries-ghsa.md#motioneye-media-and-configuration-harness)
- [mise local credential and task-include trust-boundary updates](alerts/2026-06-12-esbuild-mise-tomcat-radius-boundary-batch-ghsa.md#june-23-mise-local-credential-and-task-include-updates)
- [BoxLite sandbox and Alist storage-boundary checks](alerts/2026-06-23-boxlite-alist-storage-boundaries-ghsa.md)
- [Jupyter Enterprise Gateway kernel-ID and Cloudinary upload-signing boundary checks](alerts/2026-06-23-jupyter-eg-cloudinary-signing-boundaries-ghsa.md)
- [Budibase datasource/PWA/webhook, Gogs forge tenant/protocol/merge, Actual export/session, and automation boundary checks](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md)
- [Glances XML-RPC, Actual sync-server, OpenDJ, and Spinnaker control-plane boundary checks](alerts/2026-06-22-glances-opendj-spinnaker-control-plane-boundaries-ghsa.md)
- [Container build/runtime, OpenAM, XWiki, and ComfyUI boundary checks](alerts/2026-06-22-container-openam-xwiki-comfyui-boundaries-ghsa.md)
- [AVideo Authorize.Net webhook and Docker dotfile validation update](alerts/2026-06-04-avideo-openmeter-spree-boundary-batch-ghsa.md#june-22-authorizenet-webhook-and-docker-dotfile-update)

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
