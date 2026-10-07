---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Backstage seven-GHSA wave — TechDocs `mkdocs.yml` sanitizer allow-list misses (`extra_templates`, `pymdownx.snippets` base_path/url_download) → repo-commit-to-backend RCE, Scaffolder `order=` secret oracle, task event/log credential reflection (Oct 7 16:2xZ)](alerts/2026-10-07-backstage-techdocs-sanitizer-allowlist-and-scaffolder-order-oracle-wave-ghsa.md)

- [Veeam Backup & Replication wave — Backup Viewer→SYSTEM RCE via Mount Service deserialization, EM master-key tamper, Cloud Connect tenant→provider arbitrary file read, AAP cleartext creds in guest logs; lowest-tier backup-role audit rule (Oct 7 11:1xZ)](alerts/2026-10-07-veeam-br-cloud-connect-backup-plane-role-and-boundary-wave-ghsa.md)

- [HPE ClearPass + AOS-S coordinated wave — unauthenticated deserialization/format-string/SQLi/auth-bypass ladder on the NAC management plane, path-traversal role oracle, OnGuard agent fleet as second network-facing surface, ArubaOS-Switch wired sibling; pre-auth-parse-is-the-boundary rule (Oct 6 21:3xZ)](alerts/2026-10-07-hpe-clearpass-aos-s-unauth-primitive-ladder-nac-trust-boundaries-ghsa.md)

- [Coraza WAF evasion wave — `SecArgumentsLimit` silent-drop ARGS bypass (94% at 10k args), truncated-multipart 200003 voiding, Native audit-log CRLF forgery; WAF fingerprint via drop-behavior differentials (Oct 6 20:3xZ)](alerts/2026-10-06-coraza-waf-evasion-wave-argument-limit-silent-drop-multipart-truncation-and-audit-log-forgery-ghsa.md)

- [Payload CMS fifteen-GHSA wave — case-sensitive `and/or` query validation, unvalidated join sort, join-predicate reset-token oracle, auth-verb field-ACL misses (refresh/reset/duplicate/API-key/password), redirect whitespace-prefix drift, unauth import-export RCE (Oct 6 16:0xZ)](alerts/2026-10-06-payload-cms-eight-leg-wave-query-validation-join-sort-and-redirect-normalization-ghsa.md)

- [vm2 coordinated dump — incomplete-fix genealogy as recon map, default-config escapes, shared Buffer-pool cross-realm memory (Oct 5 22:3xZ)](alerts/2026-10-05-vm2-coordinated-dump-incomplete-fix-family-and-default-config-escapes-ghsa.md)

- [Joomla extension wave — token-existence-only download authz, guest-reachable `jform` save controllers, unauthenticated task triggers, picker SSRF with admin OAuth token (Oct 5 18:34Z)](alerts/2026-10-05-joomla-extension-token-existence-public-controller-and-task-trigger-ghsa.md)

- [Oct 2 23:18Z wave — two folds, no new page: Gitea act_runner `container.options` host-namespace escape (workflow YAML → runner-host root despite privileged-mode-disabled) + SiYuan agent-plane DNS-rebinding TOCTOU and MCP `asset.upload` absolute-path read](alerts/2026-06-17-gitea-langchain4j-hapi-agent-websocket-boundary-batch-ghsa.md#october-2-follow-up-act_runner-containeroptions-host-namespace-escape-folded)

- [Airflow 3.3.1 wave — deserializer gadgets into the scheduler, dependency-vs-handler parser discrepancy, secret-masker shape gaps (Oct 2 23:1xZ)](alerts/2026-10-02-airflow-deserializer-gadgets-parser-discrepancy-and-masker-shape-gaps-ghsa.md)

- [UTMStack — static `Utm-Internal-Key` env-var header = full admin API + any-user STOMP `/command/{hostname}` agent RCE (Oct 2 21:32Z)](alerts/2026-10-02-utmstack-internal-key-header-and-agent-command-transport-ghsa.md)

