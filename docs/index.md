---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [c3p0 JavaBean deserialization composition boundary](alerts/2026-07-23-c3p0-deserialization-composition-boundary-ghsa.md)
- [React Router navigation, RSC redirect, and hydration follow-up](alerts/2026-06-03-react-router-redirect-rsc-and-manifest-boundary-batch-ghsa.md#july-23-navigation-rsc-and-hydration-follow-up)
- [PostCSS, PhpSpreadsheet, and Auth.js trust-boundary checks](alerts/2026-07-23-postcss-phpspreadsheet-authjs-boundaries-ghsa.md)
- [DOMPurify state, policy, and reparse boundary checks](alerts/2026-07-23-dompurify-state-context-boundaries-ghsa.md)
- [Eclipse Jetty path, authority, trailer-state, and Digest-auth checks](alerts/2026-07-22-jetty-http-parser-auth-boundaries-ghsa.md)
- [Next.js Server Action, rewrite, cache, and middleware follow-up](alerts/2026-05-11-nextjs-middleware-cache-and-render-boundary-batch-ghsa.md#july-22-server-action-rewrite-cache-and-middleware-follow-up)
- [JupyterLab image and extension-policy checks](alerts/2026-06-19-jupyterlab-stanza-containerd-parse-symfony-archive-boundaries-ghsa.md#july-22-jupyterlab-image-and-extension-policy-follow-up)
- [LiteLLM guardrail, MCP, OIDC-file, and Skills checks](alerts/2026-06-08-litellm-authlib-dash-vitest-boundary-batch.md#july-22-litellm-guardrail-mcp-oidc-file-and-skills-follow-up)
- [n8n MCP, GraphQL, computer-use, and LLM credential checks](alerts/2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#final-july-22-n8n-mcp-graphql-computer-use-and-llm-credential-follow-up)
- [Dompdf nested-SVG local-path existence oracle](alerts/2026-07-22-dompdf-local-file-boundaries-ghsa.md#data-uri-svg-nested-resource-validation)








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
