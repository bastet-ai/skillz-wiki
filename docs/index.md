---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Gitea, LangChain4j, HAPI FHIR, agent WebFetch, and WebSocket boundaries](alerts/2026-06-17-gitea-langchain4j-hapi-agent-websocket-boundary-batch-ghsa.md)
- [Angular hydration TransferState cache-poisoning boundary](alerts/2026-06-15-angular-hydration-transferstate-cache-boundary-ghsa.md)
- [Jupyter Server CORS origin-regex boundary update](alerts/2026-05-05-jupyter-vm2-and-token-type-boundary-batch-ghsa.md#jupyter-cors-origin-regex-validation-update)
- [Admidio log credential-sink and Aurora PostgreSQL wrapper privilege boundaries](alerts/2026-06-15-admidio-aurora-secret-and-db-privilege-boundaries-ghsa.md)
- [File Browser command allowlist, share, archive, symlink, Fleet, Fabric.js, and Cordova boundaries](alerts/2026-06-12-filebrowser-fleet-fabric-cordova-boundary-batch-ghsa.md)
- [esbuild, mise, Tomcat, Radius, and late TYPO3 boundaries](alerts/2026-06-12-esbuild-mise-tomcat-radius-boundary-batch-ghsa.md)
- [TYPO3, Budibase, GeoServer, and Appsmith control-plane boundaries](alerts/2026-06-12-typo3-budibase-geoserver-appsmith-boundary-batch-ghsa.md)
- [Budibase SSRF, SwiftNIO HTTP translation, LangGraph checkpoint, and Chisel tunnel boundaries](alerts/2026-06-12-budibase-swiftnio-langgraph-chisel-boundary-batch-ghsa.md)
- [Weak public-key recon](methodology/weak-public-key-recon.md)
- [GeoServer JNDI, WsgiDAV share-root, OpenFGA cache-key, DevGuard public-asset, and Filament scope boundaries](alerts/2026-06-11-geoserver-wsgidav-openfga-devguard-filament-boundary-batch-ghsa.md)

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
