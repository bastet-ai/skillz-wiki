---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [uutils coreutils filesystem, temp-file, and script-parity follow-up](alerts/2026-04-29-uutils-coreutils-safety-and-data-integrity-batch-ghsa.md#july-6-filesystem-temp-file-and-script-parity-follow-up)
- [Nginx-UI hidden settings, certificate file-write, and ordered-query boundary checks](alerts/2026-07-06-nginx-ui-settings-command-boundaries-ghsa.md)
- [flyto-core HTTP MCP execution and SSRF guard-boundary checks](alerts/2026-07-06-flyto-mcp-ssrf-boundaries-ghsa.md)
- [Rich-text import SSRF testing: WeasyPrint presentational-hint CSS fetches](methodology/rich-text-import-ssrf-testing.md#presentational-hint-css-injection-harness)
- [Scriban TemplateContext cache, object mass-assignment, and sandbox-boundary checks](alerts/2026-07-06-scriban-template-context-boundaries-ghsa.md)
- [Cilium Envoy socket, Formie hidden-field SSTI, OpenRemote datapoint, and Open Babel parser-boundary checks](alerts/2026-07-06-cilium-formie-openremote-parser-boundaries-ghsa.md)
- [Kyverno policy SSRF and Kubernetes controller-boundary follow-up](alerts/2026-07-01-rancher-fleet-jwks-client-boundaries-ghsa.md#kyverno-cel-http-egress-harness)
- [fast-mcp Telegram and Steeltoe actuator follow-up](alerts/2026-07-02-developer-dashboard-identity-file-boundaries-ghsa.md#july-3-fast-mcp-telegram-and-steeltoe-actuator-follow-up)
- [Snapshot-write, SSR form fallback, and sudoers argument boundary checks](alerts/2026-07-03-snapshot-form-sudoers-boundaries-ghsa.md)
- [electerm remote filename command and transfer-path follow-up](alerts/2026-05-08-electerm-terminal-command-boundary-ghsa-8x35-hph8-37hq.md#july-3-expansion-remote-filenames-file-helpers-and-transfer-paths)

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
