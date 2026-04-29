---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [n8n XML/RCE, credential replay, MCP, variables, and Hosted Chat batch](alerts/2026-04-29-n8n-rce-credential-and-chat-auth-batch-ghsa.md)
- [Admidio SSO, authorization, path traversal, and XSS batch](alerts/2026-04-29-admidio-sso-and-authorization-batch-ghsa.md)
- [OpenClaw webchat local-file read and wildcard command-owner issues](alerts/2026-04-29-openclaw-webchat-local-file-and-command-owner-ghsa.md)
- [InstructLab trust_remote_code execution and logs_dir path traversal](alerts/2026-04-29-instructlab-trust-remote-code-and-path-traversal-ghsa.md)
- [marked tokenizer infinite-recursion OOM denial of service](alerts/2026-04-29-marked-tokenizer-recursion-dos-ghsa-6v9c-7cg6-27q7.md)
- [Apache Camel Infinispan ProtoStream deserialization RCE](alerts/2026-04-29-camel-infinispan-deserialization-rce-ghsa-xfxp-ppx7-cqrp.md)
- [PhpSpreadsheet IOFactory SSRF/RCE and row-index DoS batch](alerts/2026-04-29-phpspreadsheet-iofactory-ssrf-rce-and-row-dos-ghsa.md)
- [Hyperledger Fabric SDK Java deserialization RCE](alerts/2026-04-29-hyperledger-fabric-sdk-java-deserialization-rce-ghsa-prf8-cf2x-rhx7.md)
- [Nginx-UI cluster proxy SSRF to internal services](alerts/2026-04-29-nginx-ui-cluster-proxy-ssrf-ghsa-wr32-99hh-6f35.md)
- [Spring Security servlet-path, issuer, and X.509 validation batch](alerts/2026-04-29-spring-security-servlet-path-and-issuer-validation-batch-ghsa.md)
- [n8n database node SQL injection and MCP OAuth redirect batch](alerts/2026-04-29-n8n-database-node-sqli-and-mcp-oauth-redirect-ghsa.md)
- [OpenTelemetry OneCollector exporter unbounded response body](alerts/2026-04-29-opentelemetry-onecollector-unbounded-response-ghsa-55m9-299j-53c7.md)
- [OpenTelemetry Azure resource detector unbounded metadata response](alerts/2026-04-29-opentelemetry-azure-metadata-unbounded-response-ghsa-vc24-j8c5-2vw4.md)
- [beets web UI stored XSS via raw metadata template interpolation](alerts/2026-04-29-beets-web-ui-stored-xss-ghsa-3gxm-wfjx-m847.md)
- [Agent Runtime Trust Boundaries Need Final Guards](best-practices/agent-runtime-trust-boundaries.md)
- [Fuzzing Harnesses Must Initialize Runtime Coverage Before the Driver Starts](best-practices/fuzzing-harness-runtime-initialization.md)
- [AI Security Testing Needs Evidence, Bounds, and Audit Trails](best-practices/ai-security-testing-trust-requirements.md)
- [CoreDNS TSIG authentication bypass on gRPC, QUIC, DoH, and DoH3](alerts/2026-04-29-coredns-tsig-auth-bypass-ghsa-vp29-5652-4fw9.md)
- [AgentScope SSRF in multimodal and URL-fetch helpers](alerts/2026-04-29-agentscope-ssrf-multimodal-fetch-ghsa.md)
- [PhpSpreadsheet HTML writer XSS via custom number format](alerts/2026-04-29-phpspreadsheet-html-writer-xss-ghsa-hrmw-qprp-wgmc.md)
- [Agentic DAST Benchmarks Need Isolation, Reset, and Real Validation](best-practices/agentic-dast-benchmark-hygiene.md)
- [KEV: ConnectWise ScreenConnect path traversal (CVE-2024-1708)](alerts/2026-04-28-connectwise-screenconnect-path-traversal-cve-2024-1708.md)
- [KEV: Microsoft Windows Shell spoofing / protection failure (CVE-2026-32202)](alerts/2026-04-28-microsoft-windows-shell-spoofing-cve-2026-32202.md)
- [Code Graphs Beat Lists for Security Analysis](best-practices/code-graphs-for-security-analysis.md)
- [KEV: Marimo remote code execution vulnerability (CVE-2026-39987)](alerts/2026-04-28-marimo-pre-auth-rce-cve-2026-39987.md)
- [Browser Engine Memory-Safety Bugs Are RCE Until Proven Otherwise](best-practices/browser-engine-memory-safety.md)
- [Mutation Testing Beats Coverage Theater](best-practices/mutation-testing-for-the-agentic-era.md)
- [MBA Obfuscation Needs Mechanical Simplification](best-practices/mba-obfuscation-mechanical-simplification.md)
- [AI-Native Knowledge Systems Need Rules, Sandboxes, and a Maturity Ladder](best-practices/ai-native-knowledge-systems.md)
- [OpenClaw advisory alert bundle](alerts/index.md)
- [SiYuan reflected XSS via SVG namespace-prefix bypass](alerts/2026-03-31-siyuan-reflected-xss-svg-namespace-prefix-bypass-ghsa-73g7-86qr-jrg3.md)
- [@tinacms/graphql FilesystemBridge path validation bypass via symlinks or junctions](alerts/2026-03-31-tinacms-graphql-filesystembridge-symlink-junction-bypass-ghsa-g9c2-gf25-3x67.md)
- [Mattermost account takeover substring matching flaw and login rate-limit DoS](alerts/2026-03-31-mattermost-account-takeover-and-login-dos-ghsa-fg35-5rf6-qg3g-ghsa-247x-7qw8-fp98.md)
- [Citrix NetScaler out-of-bounds read vulnerability](alerts/2026-03-30-citrix-netscaler-out-of-bounds-read-cve-2026-3055.md)
- [TrueConf Client download of code without integrity check](alerts/2026-04-02-trueconf-client-code-download-without-integrity-check-cve-2026-3502.md)
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
