---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Bouncy Castle CTR keystream-reuse boundary check](alerts/2026-07-01-bouncy-castle-ctr-keystream-boundary-ghsa.md)
- [Model parser, deserialization, and identity-extractor boundary checks](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md)
- [Template, OIDC discovery, path-prefix, and job-dashboard boundary checks](alerts/2026-06-30-template-oidc-path-job-boundaries-ghsa.md)
- [Fission podspec and package-reference boundary update](alerts/2026-06-10-litestar-fission-builder-boundary-batch-ghsa.md#june-30-late-fission-podspec-and-package-reference-update)
- [Keycloak UMA resource and account-lookup update](alerts/2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md#keycloak-uma-resource-and-account-lookup-authorization-checks)
- [Paymenter credit race update](alerts/2026-06-22-gogs-opencti-motioneye-paymenter-boundaries-ghsa.md#paymenter-credit-race-harness)
- [Twig sandbox residual-bypass update](alerts/2026-06-05-twig-tostring-bugsink-project-boundary-batch-ghsa.md#june-30-twig-sandbox-residual-bypass-update)
- [Auth middleware, VM socket, and supply-chain verifier boundary checks](alerts/2026-06-30-auth-middleware-vm-supply-chain-boundaries-ghsa.md)
- [Fission namespace and trigger boundary update](alerts/2026-06-10-litestar-fission-builder-boundary-batch-ghsa.md#june-30-fission-namespace-and-trigger-boundary-update)
- [Spring AI, MLflow, and Airflow boundary checks](alerts/2026-06-30-ai-artifact-airflow-boundaries-ghsa.md)

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
