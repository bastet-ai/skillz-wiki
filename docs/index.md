---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [File Browser command allowlist, share, archive, symlink, Fleet, Fabric.js, and Cordova boundaries](alerts/2026-06-12-filebrowser-fleet-fabric-cordova-boundary-batch-ghsa.md)
- [esbuild, mise, Tomcat, Radius, and late TYPO3 boundaries](alerts/2026-06-12-esbuild-mise-tomcat-radius-boundary-batch-ghsa.md)
- [TYPO3, Budibase, GeoServer, and Appsmith control-plane boundaries](alerts/2026-06-12-typo3-budibase-geoserver-appsmith-boundary-batch-ghsa.md)
- [Budibase SSRF, SwiftNIO HTTP translation, LangGraph checkpoint, and Chisel tunnel boundaries](alerts/2026-06-12-budibase-swiftnio-langgraph-chisel-boundary-batch-ghsa.md)
- [Weak public-key recon](methodology/weak-public-key-recon.md)
- [GeoServer JNDI, WsgiDAV share-root, OpenFGA cache-key, DevGuard public-asset, and Filament scope boundaries](alerts/2026-06-11-geoserver-wsgidav-openfga-devguard-filament-boundary-batch-ghsa.md)
- [Ivanti Sentry unmanaged-appliance command boundary](alerts/2026-06-11-ivanti-sentry-unmanaged-appliance-boundary-kev.md)
- [CodeIgniter4 upload extension validation boundary](alerts/2026-06-11-codeigniter-upload-extension-boundary-ghsa.md)
- [Kolibri SSRF, Hapi static-file, Keycloak IDP, Flowise vector-store, and Arc debug boundaries](alerts/2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md)
- [Sharp generic-download storage-object boundary](alerts/2026-06-11-sharp-generic-download-storage-boundary-ghsa.md)

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
