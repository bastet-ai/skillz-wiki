---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Auth middleware, VM socket, and supply-chain verifier boundary checks](alerts/2026-06-30-auth-middleware-vm-supply-chain-boundaries-ghsa.md)
- [Fission namespace and trigger boundary update](alerts/2026-06-10-litestar-fission-builder-boundary-batch-ghsa.md#june-30-fission-namespace-and-trigger-boundary-update)
- [Spring AI, MLflow, and Airflow boundary checks](alerts/2026-06-30-ai-artifact-airflow-boundaries-ghsa.md)
- [Paymenter checkout configuration injection update](alerts/2026-06-22-gogs-opencti-motioneye-paymenter-boundaries-ghsa.md#paymenter-checkout-configuration-injection-harness)
- [Agent context and broker-secret boundary checks](alerts/2026-06-30-agent-context-broker-secret-boundaries-ghsa.md)
- [Concrete CMS file-version and Express association update](alerts/2026-06-24-olivetin-openam-concrete-boundaries-ghsa.md#concrete-cms-file-version-and-express-association-harness)
- [TYPO3 sf_register frontend-group mass-assignment update](alerts/2026-06-29-typo3-extension-indexer-render-boundaries-ghsa.md#sf_register-frontend-group-mass-assignment-harness)
- [SimpleHelp OIDC identity-token boundary check](alerts/2026-06-29-simplehelp-oidc-token-boundary-kev.md)
- [Tomcat HTTP/0.9 method constraint boundary update](alerts/2026-06-12-esbuild-mise-tomcat-radius-boundary-batch-ghsa.md#tomcat-http09-method-constraint-validation)
- [TYPO3 extension indexer, crawler, and render-boundary checks](alerts/2026-06-29-typo3-extension-indexer-render-boundaries-ghsa.md)
- [OpenAM PKCE, private-key JWT, and script-sandbox boundary update](alerts/2026-06-24-olivetin-openam-concrete-boundaries-ghsa.md#openam-pkce-private_key_jwt-and-script-sandbox-harness)

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
