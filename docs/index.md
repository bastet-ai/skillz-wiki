---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Tekton, Flink, and YesWiki execution-boundary batch](alerts/2026-05-22-tekton-flink-yeswiki-execution-boundary-batch-ghsa.md)
- [Prefect, Camel, ImageMagick, and Airflow boundary batch](alerts/2026-05-22-prefect-camel-imagemagick-airflow-boundary-batch-ghsa.md)
- [GitHub Actions static-analysis recon](methodology/github-actions-static-analysis-recon.md)
- [Tekton git resolver and Network-AI MCP boundary batch](alerts/2026-05-21-tekton-git-resolver-and-network-ai-mcp-boundary-batch-ghsa.md)
- [Boxlite, containerd, Twig, and token-boundary batch](alerts/2026-05-21-boxlite-containerd-twig-and-token-boundary-batch-ghsa.md)
- [Fission, NocoDB, MCP, and SSRF boundary batch](alerts/2026-05-21-fission-nocodb-mcp-and-ssrf-boundary-batch-ghsa.md)
- [Fission, MLflow, Langflow, SSRF, and Crabbox boundary batch](alerts/2026-05-21-fission-mlflow-langflow-ssrf-crabbox-boundary-batch-ghsa-kev.md)
- [SvelteKit, Markdown, SageMaker, and LM runtime-boundary batch](alerts/2026-05-21-svelte-markdown-sagemaker-lmdeploy-boundary-batch-ghsa.md)
- [SAML, MCP, metadata, and render-boundary batch](alerts/2026-05-21-saml-mcp-metadata-render-boundary-batch-ghsa.md)
- [CI/CD to cloud pivot chain](methodology/ci-cd-cloud-pivot-chain.md)
- [Strapi relational-filter oracle to admin reset-token extraction](alerts/2026-05-21-strapi-relational-filter-oracle-admin-token-ghsa-rjg2-95x7-8qmx.md)
- [Moby AuthZ and electerm command-boundary batch](alerts/2026-05-20-moby-authz-and-electerm-command-boundary-batch-ghsa.md)
- [Tomcat parser, client-certificate, and session-boundary batch](alerts/2026-05-20-tomcat-parser-clientcert-and-session-boundary-batch-ghsa.md)
- [pip archive type-confusion boundary](alerts/2026-05-20-pip-archive-type-confusion-boundary-ghsa-58qw-9mgm-455v.md)
- [Tomcat HTTP/2 resource-exhaustion boundary batch](alerts/2026-05-20-tomcat-http2-resource-exhaustion-boundary-batch-ghsa.md)
- [Tomcat, Rclone, Mako, and ML runtime-boundary batch](alerts/2026-05-20-tomcat-rclone-mako-and-ml-runtime-boundary-batch-ghsa.md)

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
