---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Astro late adapter-regex, path, render, RSS, and transition follow-ups](alerts/2026-07-18-nest-astro-route-render-fetch-boundaries-ghsa.md#july-20-late-follow-up-adapter-regex-path-spread-key-rss-and-transition-contexts)
- [Pillow TGA RLE output-disclosure follow-up](alerts/2026-07-20-cloudreve-pillow-token-image-boundaries-ghsa.md#pillow-tga-rle-output-disclosure-check)
- [Axios proxy, serializer, and body-construction follow-ups](alerts/2026-07-17-axios-ssh-vllm-runtime-boundaries-ghsa.md#axios-inherited-basic-auth-subfield-checks)
- [File Browser username-home and share-secret follow-ups](alerts/2026-06-12-filebrowser-fleet-fabric-cordova-boundary-batch-ghsa.md#july-20-follow-up-username-to-home-collisions-and-share-secret-serialization)
- [Parser, dev-server, HTTP-client, CMS-cache, and RAG boundary checks](alerts/2026-07-20-parser-devserver-http-client-rag-boundaries-ghsa.md)
- [File Browser archive-rewrite follow-up](alerts/2026-06-12-filebrowser-fleet-fabric-cordova-boundary-batch-ghsa.md#july-20-follow-up-archive-builder-manufactures-traversal-separators)
- [Astro decode-depth authorization follow-up](alerts/2026-07-18-nest-astro-route-render-fetch-boundaries-ghsa.md#july-20-follow-up-decode-depth-authorization-mismatch)
- [Composer `bin` permissions and verbose URL credential follow-up](alerts/2026-07-20-composer-repository-package-boundaries-ghsa.md#july-20-follow-up-package-bin-permissions-and-verbose-url-credentials)
- [Cloudreve OAuth/remote-download and Pillow path/image boundary checks](alerts/2026-07-20-cloudreve-pillow-token-image-boundaries-ghsa.md)
- [Astro View Transition CSS/HTML context follow-up](alerts/2026-07-18-nest-astro-route-render-fetch-boundaries-ghsa.md#july-20-follow-up-view-transition-values-crossing-css-and-html-contexts)

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
