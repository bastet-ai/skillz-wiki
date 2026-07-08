---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Apache Airflow KubernetesExecutor and logout token boundary update](alerts/2026-07-08-integration-deploy-mcp-boundaries-ghsa.md#apache-airflow-kubernetesexecutor-and-logout-token-boundaries)
- [Go x/crypto SSH parser and peer-message boundary update](alerts/2026-06-25-agent-proxy-appliance-boundaries-ghsa-kev.md#go-ssh-parser-and-peer-message-harness)
- [DAML controller-mutation testing for authorization gaps](best-practices/mutation-testing-for-the-agentic-era.md#daml-canton-authorization-checks)
- [Integration, deployment, and MCP boundary checks from July 8 GHSA wave](alerts/2026-07-08-integration-deploy-mcp-boundaries-ghsa.md)
- [Joomla page-builder upload and ColdFusion traversal KEV boundary checks](alerts/2026-07-08-joomla-page-builder-coldfusion-kev-boundaries.md)
- [Agent, deploy, SSRF, and identity boundary checks](alerts/2026-07-07-agent-deploy-ssrf-identity-boundaries-ghsa.md)
- [Better Auth identity/OAuth follow-up plus Aider, netfoil, CKAN MCP, and uutils boundary checks](alerts/2026-07-07-better-auth-aider-netfoil-ckan-mcp-boundaries-ghsa.md)
- [Langflow user-controlled-key auth-bypass KEV follow-up](alerts/2026-06-19-langflow-mailpit-outerbase-miniflux-render-boundaries-ghsa.md#july-7-langflow-user-controlled-key-auth-bypass-kev-follow-up)
- [DNS rebinding local-service testing](methodology/dns-rebinding-local-service-testing.md)
- [Open WebUI image-edit blind SSRF follow-up](alerts/2026-05-16-open-webui-rag-ssrf-and-knowledge-boundary-batch-ghsa.md#july-7-image-edit-blind-ssrf-update)

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
