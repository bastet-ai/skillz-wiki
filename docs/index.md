---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [DNS rebinding local-service testing](methodology/dns-rebinding-local-service-testing.md)
- [Open WebUI image-edit blind SSRF follow-up](alerts/2026-05-16-open-webui-rag-ssrf-and-knowledge-boundary-batch-ghsa.md#july-7-image-edit-blind-ssrf-update)
- [Open WebUI chat, citation, markdown, and uploaded-HTML render follow-up](alerts/2026-05-16-open-webui-model-render-cache-and-execution-boundary-batch-ghsa.md#july-7-chat-iframe-citation-markdown-and-uploaded-html-follow-up)
- [ArchiveBox AddView config-to-plugin follow-up](alerts/2026-05-04-runtime-package-and-build-execution-boundary-batch-ghsa.md#july-7-archivebox-addview-config-to-plugin-follow-up)
- [Netty DNS bailiwick and buffer-lifecycle follow-up](alerts/2026-06-11-netty-dns-redis-protocol-codec-boundaries-ghsa.md#july-7-dns-bailiwick-and-buffer-lifecycle-follow-up)
- [EGroupware template/mail, XWiki skin, and New API notification-boundary checks](alerts/2026-07-07-egroupware-xwiki-newapi-boundaries-ghsa.md)
- [Langroid raw tool JSON, eval, and SQL validator follow-up](alerts/2026-02-07-langroid-waf-bypass-rce-ghsa-x34r-63hx-w57f.md#july-6-raw-tool-json-tablechatagent-eval-and-sqlchatagent-regex-bypass-follow-up)
- [Cilium Local Redirect Policy cross-namespace service follow-up](alerts/2026-07-06-cilium-formie-openremote-parser-boundaries-ghsa.md#july-6-cilium-local-redirect-policy-cross-namespace-service-follow-up)
- [`decompress` archive extraction boundary follow-up](alerts/2026-05-06-archive-and-file-extraction-boundary-batch-ghsa.md#july-6-decompress-symlink-hardlink-prefix-and-mode-follow-up)
- [Coder cross-agent redirect file-authority follow-up](alerts/2026-07-01-agent-repo-registry-boundaries-ghsa.md#july-6-late-coder-cross-agent-redirect-follow-up)

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
