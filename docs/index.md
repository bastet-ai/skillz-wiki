---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Agentic DAST benchmark fixtures and SSRF sink-validation controls](methodology/agentic-dast-benchmark-validation.md#turn-scanner-misses-into-benchmark-fixtures)
- [Agent, CMS, renderer, and export boundary checks from July 9 GHSA updates](alerts/2026-07-09-agent-cms-render-export-boundaries-ghsa.md)
- [CarrierWave MIME denylist and OpenStack Ironic image-boundary checks](alerts/2026-07-09-upload-and-baremetal-image-boundaries-ghsa.md)
- [Waku redirect, Skipper OPA body, and lxml sanitizer bypass updates](alerts/2026-07-08-integration-deploy-mcp-boundaries-ghsa.md#waku-server-action-csrf-and-redirect-helpers)
- [Serena/Joro browser-to-loopback and Nuclio/DSpace package-boundary updates](alerts/2026-07-08-integration-deploy-mcp-boundaries-ghsa.md#serena-and-joro-browser-to-loopback-control-planes)
- [Apache Airflow KubernetesExecutor and logout token boundary update](alerts/2026-07-08-integration-deploy-mcp-boundaries-ghsa.md#apache-airflow-kubernetesexecutor-and-logout-token-boundaries)
- [Go x/crypto SSH parser and peer-message boundary update](alerts/2026-06-25-agent-proxy-appliance-boundaries-ghsa-kev.md#go-ssh-parser-and-peer-message-harness)
- [DAML controller-mutation testing for authorization gaps](best-practices/mutation-testing-for-the-agentic-era.md#daml-canton-authorization-checks)
- [Integration, deployment, agent, CMS, and MCP boundary checks from July 8 GHSA wave](alerts/2026-07-08-integration-deploy-mcp-boundaries-ghsa.md)
- [Joomla page-builder upload and ColdFusion traversal KEV boundary checks](alerts/2026-07-08-joomla-page-builder-coldfusion-kev-boundaries.md)

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
