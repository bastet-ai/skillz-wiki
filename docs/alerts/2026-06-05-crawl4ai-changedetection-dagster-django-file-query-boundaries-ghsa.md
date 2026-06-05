# Crawl4AI, changedetection.io, Dagster, and Django file/query boundary batch

Source: GitHub Security Advisories REST API, updated 2026-06-05.

This batch is durable because the advisories map to reusable offensive testing patterns: **browser automation APIs crossing `file://` into host file reads**, **backup/XML import paths crossing into local file disclosure**, **workflow gRPC notebook paths crossing directory boundaries**, and **Django ORM helper kwargs crossing into SQL syntax**. Use the workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **Crawl4AI Docker API `file://` local file inclusion** — [GHSA-vx9w-5cx4-9796](https://github.com/advisories/GHSA-vx9w-5cx4-9796) / CVE-2026-26217: `crawl4ai` before `0.8.0` accepted `file://` URLs on Docker API endpoints including `/execute_js`, `/screenshot`, `/pdf`, and `/html`. When those endpoints are reachable without a strong access gate, a caller can make the browser/runtime read files from the server-side container or host filesystem context.
- **changedetection.io backup-restore local file read** — [GHSA-8757-69j2-hx56](https://github.com/advisories/GHSA-8757-69j2-hx56) / CVE-2026-43891: affected `changedetection.io` versions trusted restored watch snapshot paths from backup ZIP contents. A crafted backup could preserve attacker-controlled watch/history metadata that later resolves to local files readable by the application process.
- **changedetection.io XML/RSS XPath XXE** — [GHSA-v7cp-2cx9-x793](https://github.com/advisories/GHSA-v7cp-2cx9-x793) / CVE-2026-41895: XML/RSS include-filter parsing used `lxml` XML parsing without explicitly disabling external entity resolution in the affected path. Watches that parse attacker-controlled XML/RSS with XPath include filters may expose local-file or network-backed entity behavior, depending on runtime parser defaults.
- **Dagster gRPC notebook local file inclusion** — [GHSA-h7x8-jv97-fvvm](https://github.com/advisories/GHSA-h7x8-jv97-fvvm) / CVE-2025-51481: Dagster before `1.10.16` let callers with access to the gRPC server supply traversal sequences in `ExternalNotebookData.notebook_path`, bypassing the intended notebook extension check and reading arbitrary files reachable by the Dagster process.
- **Django ORM dictionary-expansion SQL injection family** — [GHSA-6w2r-r2m5-xq5w](https://github.com/advisories/GHSA-6w2r-r2m5-xq5w) / CVE-2025-57833, [GHSA-hpr9-3m2g-3j9p](https://github.com/advisories/GHSA-hpr9-3m2g-3j9p) / CVE-2025-59681, [GHSA-frmv-pr5f-9mcr](https://github.com/advisories/GHSA-frmv-pr5f-9mcr) / CVE-2025-64459, and [GHSA-rqw2-ghq9-44m7](https://github.com/advisories/GHSA-rqw2-ghq9-44m7) / CVE-2025-13372: multiple Django releases fixed SQL injection primitives where attacker-influenced dictionaries were expanded into ORM helper kwargs such as `QuerySet.annotate()`, `QuerySet.alias()`, `QuerySet.aggregate()`, `QuerySet.extra()`, `FilteredRelation`, `Q()`, `filter()`, `exclude()`, and `get()` across backend-specific paths.

## Operator triage

1. Search asset inventories for exposed Crawl4AI Docker/API deployments, AI crawling services, screenshot/PDF/HTML render workers, or agent tools that wrap Crawl4AI endpoints.
2. Prioritize Crawl4AI instances where `/execute_js`, `/screenshot`, `/pdf`, or `/html` are reachable from user-controlled jobs, unauthenticated network positions, shared workspaces, or low-trust tenants.
3. Search changedetection.io targets for administrative backup restore access, watch import workflows, XML/RSS monitors, and XPath include filters applied to attacker-controlled feed responses.
4. Search orchestrator inventories for Dagster gRPC servers, user-code deployments, notebooks exposed through Dagster metadata, and network paths where a tester or lower-privileged service can call notebook data APIs.
5. Search Django code for patterns that unpack request, JSON, form, GraphQL, or tenant-config dictionaries directly into ORM methods: `annotate(**data)`, `alias(**data)`, `aggregate(**data)`, `extra(**data)`, `filter(**data)`, `exclude(**data)`, `get(**data)`, `Q(**data)`, or `FilteredRelation(..., **data)`.
6. For Django, prioritize PostgreSQL, MySQL, and MariaDB apps that expose advanced filtering, reporting, analytics, saved-search, data-grid, or admin-builder features where users influence field aliases, connectors, or annotation names.

## Replayable validation boundaries

### Crawl4AI `file://` API proof

Use a disposable Crawl4AI lab or an explicitly approved non-production service. Do not request real secrets.

1. Create an inert marker file in the Crawl4AI runtime context, for example `/tmp/skillz-crawl4ai-marker.txt` with a unique string.
2. Send the target API path a server-side URL of `file:///tmp/skillz-crawl4ai-marker.txt`. For `/execute_js`, use a harmless script that returns page/body text; for `/html`, request the rendered content directly.
3. Vulnerable result: the API response, screenshot/PDF text extraction, or HTML output contains the marker content from the local filesystem.
4. Capture endpoint, auth state, package version, container/runtime identity, exact `file://` URL, and marker-only output. Avoid `/etc/passwd`, `/proc/self/environ`, SSH keys, cloud credentials, and application config files.

### changedetection.io crafted backup local-read proof

Keep this in a lab unless the client explicitly approves backup-restore testing.

1. Create a lab changedetection.io instance with a marker file outside the watch data directory.
2. Build a backup ZIP that restores a watch directory and a controlled `history.txt`/snapshot reference matching the advisory's trust-boundary pattern.
3. Restore the backup through the normal UI/API path using an authorized admin-equivalent account.
4. Trigger the restored watch history/snapshot display path.
5. Vulnerable result: the application reads or displays marker content from outside the intended restored watch data.
6. Capture backup structure, restored watch UUID, version, request path, and marker-only evidence. Do not use production backup archives or sensitive local paths.

### changedetection.io XML/RSS XXE canary

Use a canary XML feed and a marker file; do not exfiltrate real files.

1. Host a controlled XML/RSS response with a DOCTYPE/entity referencing only the marker file path available in the lab runtime.
2. Configure a watch that fetches the canary feed and enables an XPath include filter, forcing the XML helper path.
3. Trigger the watch fetch and compare parser output, diff text, logs, and outbound callbacks if using a network entity canary.
4. Vulnerable result: the marker entity is expanded or the parser attempts the controlled external lookup.
5. Capture parser behavior, dependency versions, watch configuration, and marker-only output.

### Dagster gRPC notebook path traversal proof

Only test gRPC paths where access is in scope.

1. Create a Dagster lab with a legitimate notebook path and a marker file outside the notebook directory.
2. Call the same notebook-data gRPC method used by the environment with a traversal value in `notebook_path`, adjusted to reach the marker file while preserving any extension constraints the target enforces.
3. Vulnerable result: the response returns marker file content rather than rejecting the path as outside the notebook root.
4. Capture Dagster version, gRPC reachability, caller identity, supplied `notebook_path`, and marker-only response.

### Django ORM kwargs injection proof

Prefer source review plus a tiny canary harness over blind production payloads.

1. Identify a route where user-controlled dictionaries flow into ORM kwargs by expansion.
2. Reproduce in a lab with the same Django minor version and database backend.
3. Use a harmless alias/connector canary that changes generated SQL shape without reading unrelated rows or modifying data. Confirm through query logging, generated SQL inspection, or a controlled fixture table.
4. Vulnerable result: attacker-controlled dictionary keys or `_connector` values appear as SQL syntax rather than quoted identifiers/validated operators.
5. Capture code path, Django version, database backend, generated SQL excerpt, and controlled fixture result. Do not run destructive SQL or time-based payloads against production.

## Reporting heuristics

- Frame Crawl4AI findings as **render/crawler API local-file boundary** issues. Include whether the vulnerable endpoint is unauthenticated, tenant-accessible, or shielded by an internal gateway.
- Frame changedetection.io backup findings as **trusted backup metadata crossing into application file reads**. Evidence should use a purpose-built backup and marker file only.
- Frame changedetection.io XXE findings as **untrusted feed XML parser configuration** issues. Record the exact watch settings and dependency/parser behavior; avoid overstating impact when entity expansion is blocked by runtime defaults.
- Frame Dagster findings as **workflow control-plane gRPC path containment** issues. Distinguish internet exposure, internal service exposure, and authenticated developer-only reachability.
- Frame Django findings as **user-controlled ORM dictionary expansion** issues, not generic SQL injection. The decisive evidence is the user-controlled dictionary key/value crossing into generated SQL syntax on an affected Django/database combination.
- Keep all proofs marker-only, non-destructive, and scoped to approved systems.

## Sources

- GitHub Advisory Database: [GHSA-vx9w-5cx4-9796 / CVE-2026-26217](https://github.com/advisories/GHSA-vx9w-5cx4-9796)
- Crawl4AI upstream advisory: [unclecode/crawl4ai GHSA-vx9w-5cx4-9796](https://github.com/unclecode/crawl4ai/security/advisories/GHSA-vx9w-5cx4-9796)
- GitHub Advisory Database: [GHSA-8757-69j2-hx56 / CVE-2026-43891](https://github.com/advisories/GHSA-8757-69j2-hx56)
- changedetection.io upstream advisory: [dgtlmoon/changedetection.io GHSA-8757-69j2-hx56](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-8757-69j2-hx56)
- GitHub Advisory Database: [GHSA-v7cp-2cx9-x793 / CVE-2026-41895](https://github.com/advisories/GHSA-v7cp-2cx9-x793)
- changedetection.io upstream advisory: [dgtlmoon/changedetection.io GHSA-v7cp-2cx9-x793](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-v7cp-2cx9-x793)
- GitHub Advisory Database: [GHSA-h7x8-jv97-fvvm / CVE-2025-51481](https://github.com/advisories/GHSA-h7x8-jv97-fvvm)
- Dagster fix reference: [dagster-io/dagster pull request 30002](https://github.com/dagster-io/dagster/pull/30002)
- GitHub Advisory Database: [GHSA-6w2r-r2m5-xq5w / CVE-2025-57833](https://github.com/advisories/GHSA-6w2r-r2m5-xq5w)
- GitHub Advisory Database: [GHSA-hpr9-3m2g-3j9p / CVE-2025-59681](https://github.com/advisories/GHSA-hpr9-3m2g-3j9p)
- GitHub Advisory Database: [GHSA-frmv-pr5f-9mcr / CVE-2025-64459](https://github.com/advisories/GHSA-frmv-pr5f-9mcr)
- GitHub Advisory Database: [GHSA-rqw2-ghq9-44m7 / CVE-2025-13372](https://github.com/advisories/GHSA-rqw2-ghq9-44m7)
- Django security release archive: <https://docs.djangoproject.com/en/dev/releases/security/>
