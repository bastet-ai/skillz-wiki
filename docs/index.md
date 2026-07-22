---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Agentic DAST unintended-solution-path auditing](methodology/agentic-dast-benchmark-validation.md#audit-unintended-solution-paths)
- [Dompdf local-file confinement and existence-oracle checks](alerts/2026-07-22-dompdf-local-file-boundaries-ghsa.md)
- [Check Point SmartConsole application-token authentication boundary](alerts/2026-07-22-check-point-smartconsole-application-token-auth-boundary.md)
- [n8n agent, Git TOCTOU, browser, and JWT credential-artifact checks](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#july-22-n8n-agent-git-browser-and-credential-artifact-follow-up)
- [Wagtail `TableBlock` class-attribute render boundary](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#july-22-wagtail-tableblock-attribute-rendering-follow-up)
- [ProjectDiscovery internal network scanning](skills/projectdiscovery-internal-network-scanning.md)
- [Final July 21 URL, schema-generation, sanitizer, Jackson, and xDS checks](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#final-july-21-url-schema-generation-sanitizer-and-authorization-boundaries)
- [Final July 21 Gitea authentication, visibility, and lifecycle wave](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md#final-july-21-gitea-authentication-visibility-and-lifecycle-wave)
- [Gitea outbound-fetch, token, Actions/LFS, and attachment boundary wave](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md#late-july-21-gitea-forge-control-boundary-wave)
- [GitPython, Sigstore OCI, Vitest, SVG/DOM, and Jackson policy checks](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#late-july-21-git-pipeline-and-render-policy-boundaries)




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
