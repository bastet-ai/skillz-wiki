---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [AI-Native Knowledge Systems Need Rules, Sandboxes, and a Maturity Ladder](best-practices/ai-native-knowledge-systems.md)
- [OpenClaw advisory alert bundle](alerts/index.md)
- [SiYuan reflected XSS via SVG namespace-prefix bypass](alerts/2026-03-31-siyuan-reflected-xss-svg-namespace-prefix-bypass-ghsa-73g7-86qr-jrg3.md)
- [@tinacms/graphql FilesystemBridge path validation bypass via symlinks or junctions](alerts/2026-03-31-tinacms-graphql-filesystembridge-symlink-junction-bypass-ghsa-g9c2-gf25-3x67.md)
- [Mattermost account takeover substring matching flaw and login rate-limit DoS](alerts/2026-03-31-mattermost-account-takeover-and-login-dos-ghsa-fg35-5rf6-qg3g-ghsa-247x-7qw8-fp98.md)
- [Citrix NetScaler out-of-bounds read vulnerability](alerts/2026-03-30-citrix-netscaler-out-of-bounds-read-cve-2026-3055.md)
- [Webhook Secrets Need Brute-Force Resistance](best-practices/webhook-secrets-bruteforce-resistance.md)
- [Channel Policy Enforcement Must Happen Before Enqueueing](best-practices/channel-policy-enforcement.md)
- [Dimensional Analysis for Audit Workflows](blog/2026-03-28-dimensional-analysis-for-audit-workflows.md)
- [HTTP Probing with httpx](skills/httpx.md)
- [DNS Enumeration](skills/dns-enumeration.md)
- [Nmap Scanning](skills/nmap-scanning.md)

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
