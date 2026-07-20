---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Cloudreve OAuth/remote-download and Pillow path/image boundary checks](alerts/2026-07-20-cloudreve-pillow-token-image-boundaries-ghsa.md)
- [Astro View Transition CSS/HTML context follow-up](alerts/2026-07-18-nest-astro-route-render-fetch-boundaries-ghsa.md#july-20-follow-up-view-transition-values-crossing-css-and-html-contexts)
- [Better Auth SSO provider creation role-drift follow-up](alerts/2026-07-07-better-auth-aider-netfoil-ckan-mcp-boundaries-ghsa.md#july-20-follow-up-sso-provider-creation-role-drift)
- [Apollo ConfigService AccessKey parser and collation follow-up](alerts/2026-07-13-decidim-apollo-geonode-boundaries-ghsa.md#apollo-configservice-accesskey-parser-differentials)
- [Composer repository metadata and package-install boundary checks](alerts/2026-07-20-composer-repository-package-boundaries-ghsa.md)
- [Axios inherited Basic-auth subfield boundary follow-up](alerts/2026-07-17-axios-ssh-vllm-runtime-boundaries-ghsa.md#axios-inherited-basic-auth-subfield-checks)
- [n8n webhook, sandbox, repository, and database boundary follow-up](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#july-20-n8n-webhook-sandbox-repository-and-database-follow-up)
- [Langflow public-playground and knowledge-base boundary follow-up](alerts/2026-06-19-langflow-mailpit-outerbase-miniflux-render-boundaries-ghsa.md#july-20-public-playground-and-knowledge-base-follow-up)
- [Building replayable target environments](methodology/target-environment-harness-design.md)
- [NestJS and Astro route, render, and image-fetch boundary checks](alerts/2026-07-18-nest-astro-route-render-fetch-boundaries-ghsa.md)


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
