---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Axios proxy-authorization redirect boundary](alerts/2026-06-04-axios-proxy-authorization-redirect-boundary-ghsa.md)
- [Starlette Host header URL-path boundary](alerts/2026-06-04-starlette-host-header-url-path-boundary-ghsa.md)
- [Froxlor DNS TXT BIND zone injection boundary](alerts/2026-06-04-froxlor-dns-txt-bind-zone-injection-ghsa.md)
- [Jupyter Enterprise Gateway, browserstack-runner, Froxlor API, and client-redirect boundaries](alerts/2026-06-03-jupyter-browserstack-froxlor-client-boundary-batch-ghsa.md)
- [React Router redirect, RSC, manifest, and deserialization boundaries](alerts/2026-06-03-react-router-redirect-rsc-and-manifest-boundary-batch-ghsa.md)
- [Docling HTML, XML, LaTeX, and resource-fetch boundaries](alerts/2026-06-03-docling-html-xml-latex-resource-boundary-batch-ghsa.md)
- [Docling EasyOCR model ZIP extraction boundary](alerts/2026-06-03-docling-easyocr-model-zip-slip-boundary-ghsa.md)
- [`launch-editor` Windows command-injection boundary](alerts/2026-06-03-launch-editor-windows-command-injection-ghsa.md)
- [Mirasvit Cache Warmer `CacheWarmer` cookie deserialization boundary](alerts/2026-06-03-mirasvit-cache-warmer-cookie-deserialization-boundary-kev.md)
- [Agent skill supply-chain testing](methodology/agent-skill-supply-chain-testing.md)

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
