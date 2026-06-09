---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Pheditor, Dex, Phoenix Storybook, and Symfony Runtime boundary checks](alerts/2026-06-09-pheditor-dex-phoenixstory-symfony-boundary-batch-ghsa.md)
- [Svelte SSR spread and DOM-clobbering boundary checks](alerts/2026-06-09-svelte-ssr-spread-dom-clobbering-boundary-ghsa.md)
- [Net::IMAP raw argument command boundary](alerts/2026-06-09-net-imap-raw-argument-command-boundary-ghsa.md)
- [Cisco Catalyst SD-WAN crafted-file root boundary](alerts/2026-06-09-cisco-sdwan-crafted-file-root-boundary.md)
- [Arista EOS tunnel decapsulation boundary validation](alerts/2026-06-09-arista-eos-tunnel-decap-boundary.md)
- [pretix email placeholder injection](alerts/2026-06-09-pretix-email-placeholder-injection.md)
- [shell-quote newline operator boundary](alerts/2026-06-09-shell-quote-newline-operator-boundary-ghsa.md)
- [Fides banner override, Froxlor API 2FA, and Ironic image-boundary checks](alerts/2026-06-09-fides-froxlor-ironic-boundary-batch-ghsa.md)
- [Auth parser, device-flow, HAXcms token, and redirect-cookie boundaries](alerts/2026-06-09-auth-device-haxcms-redirect-boundary-batch-ghsa.md)
- [File Browser command-scope and web3.py CCIP SSRF boundaries](alerts/2026-06-09-filebrowser-command-scope-and-web3-ccip-ssrf-boundary-ghsa.md)

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
