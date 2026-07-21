---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [ProjectDiscovery internal network scanning](skills/projectdiscovery-internal-network-scanning.md)
- [Final July 21 URL, schema-generation, sanitizer, Jackson, and xDS checks](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#final-july-21-url-schema-generation-sanitizer-and-authorization-boundaries)
- [Final July 21 Gitea authentication, visibility, and lifecycle wave](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md#final-july-21-gitea-authentication-visibility-and-lifecycle-wave)
- [Gitea outbound-fetch, token, Actions/LFS, and attachment boundary wave](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md#late-july-21-gitea-forge-control-boundary-wave)
- [GitPython, Sigstore OCI, Vitest, SVG/DOM, and Jackson policy checks](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#late-july-21-git-pipeline-and-render-policy-boundaries)
- [Gitea migration redirect, stale approval, and revocation-residue checks](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md#july-21-gitea-migration-revocation-and-branch-policy-follow-up)
- [Flowise upload-file fallback traversal check](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#july-21-flowise-upload-file-fallback-traversal-follow-up)
- [Package-build normalization/command and URI authority checks](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#late-july-21-package-build-and-uri-authority-boundaries)
- [Hono concurrent request-context and `cx()` SSR escaping checks](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#july-21-hono-request-context-and-cx-ssr-follow-up)
- [Hono repeated-header and Windows encoded-backslash adapter checks](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#july-21-hono-adapter-parser-differential-follow-up)

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
