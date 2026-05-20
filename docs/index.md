---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Tomcat HTTP/2 resource-exhaustion boundary batch](alerts/2026-05-20-tomcat-http2-resource-exhaustion-boundary-batch-ghsa.md)
- [Tomcat, Rclone, Mako, and ML runtime-boundary batch](alerts/2026-05-20-tomcat-rclone-mako-and-ml-runtime-boundary-batch-ghsa.md)
- [Keycloak, Jetty, Axios, and parser-boundary batch](alerts/2026-05-20-keycloak-jetty-axios-and-parser-boundary-batch-ghsa.md)
- [SSR, proxy, supply-chain, and render-boundary batch](alerts/2026-05-19-ssr-proxy-supply-chain-and-render-boundary-batch-ghsa.md)
- [MCP, admin, parser, and service-boundary batch](alerts/2026-05-19-mcp-admin-parser-and-service-boundary-batch-ghsa.md)
- [MCP fetch, upload, cache, and parser-boundary batch](alerts/2026-05-19-mcp-upload-cache-and-parser-boundary-batch-ghsa.md)
- [Open WebUI, OpenClaw, Nomad, and filesystem boundary batch](alerts/2026-05-19-open-webui-openclaw-nomad-filesystem-boundary-batch-ghsa.md)
- [HAXcms, Algernon, Tomcat, and supply-chain boundary batch](alerts/2026-05-19-haxcms-algernon-tomcat-supply-chain-boundary-batch-ghsa.md)
- [Podman `kube play` symlink host-write boundary](alerts/2026-05-19-podman-kube-play-symlink-host-write-boundary-ghsa-wp3j-xq48-xpjw.md)
- [Apostrophe host-header password-reset boundary](alerts/2026-05-19-apostrophe-host-header-password-reset-boundary-ghsa-gf43-24g3-5hw2.md)

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
