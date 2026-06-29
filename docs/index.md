---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Upload, accounting, and ACL filesystem boundary checks](alerts/2026-06-29-upload-accounting-acl-boundaries-ghsa.md)
- [Andromeda Bytecode C2 Lab Workflow](skills/andromeda-bytecode-c2.md)
- [Froxlor DNS LOC/TLSA zone-file injection boundary update](alerts/2026-06-04-froxlor-dns-txt-bind-zone-injection-ghsa.md#june-29-follow-up-loctlsa-validation-regression)
- [pyLoad session, CSRF, and localhost-bypass control-plane update](alerts/2026-06-08-pyload-openhands-pyjwt-netty-onnx-boundary-batch-ghsa.md#june-28-pyload-session-csrf-and-localhost-bypass-update)
- [CMS, renderer, HTTP-client, package-manager, monitoring, and playlist boundary checks](alerts/2026-06-26-cms-renderer-http-client-package-boundaries-ghsa.md#final-hour-updates-pnpm-install-engines-nezha-secrets-and-media-playlist-apis)
- [MCP, identity, static-path, and panel boundary checks](alerts/2026-06-26-mcp-identity-static-panel-boundaries-ghsa.md)
- [Proxy, scanner, and container path boundary checks](alerts/2026-06-26-proxy-scanner-container-boundaries-ghsa.md)
- [Incus image, backup, and object-storage host-boundary checks](alerts/2026-06-26-incus-image-backup-host-boundaries-ghsa.md)
- [Fluentd log-ingestion placeholder, outbound HTTP, and monitor API boundary checks](alerts/2026-06-26-fluentd-observability-boundaries-ghsa.md)
- [OpenAM OAuth2 credential-rewrite and MSISDN LDAP-filter boundary update](alerts/2026-06-24-olivetin-openam-concrete-boundaries-ghsa.md#openam-oauth2-local-credential-and-msisdn-ldap-filter-harness)

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
