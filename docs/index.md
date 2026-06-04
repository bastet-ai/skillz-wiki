---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [APScheduler serializer RCE and BillaBear identifier-injection boundaries](alerts/2026-06-04-apscheduler-billabear-serialization-and-identifier-boundaries-ghsa.md)
- [MCP-for-Stata `log_file_name` command-injection boundary](alerts/2026-06-04-mcp-for-stata-log-file-name-command-injection-ghsa.md)
- [Shopware Store API/admin/media boundaries and AdGuard DoQ source-port oracle](alerts/2026-06-04-shopware-store-api-admin-media-and-adguard-dns-boundaries-ghsa.md)
- [AVideo WebSocket/gallery/payment, OpenMeter JSONPath SQLi, and Spree CSV export boundaries](alerts/2026-06-04-avideo-openmeter-spree-boundary-batch-ghsa.md)
- [Hono parser/auth, Nhost localhost configserver, and Singularity path-prefix boundaries](alerts/2026-06-04-hono-nhost-singularity-boundary-batch-ghsa.md)
- [GitHub CLI TUF mirror authorization-header boundary](alerts/2026-06-04-github-cli-tuf-mirror-authorization-header-boundary-ghsa.md)
- [Keycloak and MLflow authentication-boundary batch](alerts/2026-06-04-keycloak-mlflow-auth-boundary-batch-ghsa.md)
- [Nuclio, Better Auth, Doorkeeper, and WebOb boundary batch](alerts/2026-06-04-nuclio-betterauth-doorkeeper-webob-boundary-batch-ghsa.md)
- [Axios proxy-authorization redirect boundary](alerts/2026-06-04-axios-proxy-authorization-redirect-boundary-ghsa.md)
- [Starlette Host header URL-path boundary](alerts/2026-06-04-starlette-host-header-url-path-boundary-ghsa.md)

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
