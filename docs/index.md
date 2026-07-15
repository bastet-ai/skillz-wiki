---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [LangBot MCP STDIO command boundary checks](alerts/2026-07-15-langbot-mcp-stdio-command-boundary-ghsa.md)
- [Koel Subsonic SSRF and MantisBT SOAP/configuration boundary checks](alerts/2026-07-15-koel-mantisbt-boundaries-ghsa.md)
- [NetLicensing MCP and nebula-mesh control-plane boundary checks](alerts/2026-07-14-mcp-mesh-control-plane-boundaries-ghsa.md)
- [n8n-MCP backup, Woodpecker agent/Kubernetes identity, and Anyquery server-mode file-write checks](alerts/2026-07-14-workflow-ci-query-boundaries-ghsa.md)
- [Kimai, FacturaScripts, OpenCost, and App Store trust-boundary checks](alerts/2026-07-14-kimai-facturascripts-auth-boundaries-ghsa.md)
- [Anyquery SSRF, yutu MCP file-write, TidGi import RCE, TsDProxy IP spoofing, Auth0 query-token, and SonicWall SMA1000 checks](alerts/2026-07-14-agent-desktop-proxy-appliance-boundaries-ghsa-kev.md)
- [NukeViet forwarded-host CMS plus DIRAC eval, SQL, and pilot-bootstrap checks](alerts/2026-07-13-nukeviet-dirac-boundaries-ghsa.md)
- [Rust security testing workflow for audit targets](methodology/rust-security-testing-workflow.md)
- [Decidim tenant-boundary, Apollo config auth, and GeoNode trusted-render checks](alerts/2026-07-13-decidim-apollo-geonode-boundaries-ghsa.md)
- [TSDProxy management-token relay and melange/apko APK data-integrity checks](alerts/2026-07-10-http-client-package-cache-identity-boundaries-ghsa.md#tsdproxy-identity-header-management-token-relay)


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
