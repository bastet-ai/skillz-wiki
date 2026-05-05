# CMS, import, and deserialization boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because admin-facing import, plugin, package, and integration features are repeatedly crossing from "configuration" into code execution. Treat ZIP uploads, backup restores, package metadata, route parameters, and Java deserialization endpoints as execution boundaries even when they sit behind an admin UI.

## Advisories covered

- **Grav direct plugin install** — [GHSA-w48r-jppp-rcfw](https://github.com/advisories/GHSA-w48r-jppp-rcfw): malicious plugin ZIP upload can reach remote code execution.
- **Grav API** — [GHSA-r945-h4vm-h736](https://github.com/advisories/GHSA-r945-h4vm-h736): API privilege escalation to super admin.
- **Apache Camel MINA** — [GHSA-vpr3-2659-rw55](https://github.com/advisories/GHSA-vpr3-2659-rw55): deserialization of untrusted data.
- **Apache Camel PQC** — [GHSA-v3vg-332r-mw99](https://github.com/advisories/GHSA-v3vg-332r-mw99): deserialization of untrusted data.
- **pyLoad `set_package_data`** — [GHSA-838g-gr43-qqg9](https://github.com/advisories/GHSA-838g-gr43-qqg9) and [GHSA-97r3-5w84-r4q8](https://github.com/advisories/GHSA-97r3-5w84-r4q8): package folder names can trigger path traversal.
- **changedetection.io backup restore** — [GHSA-8757-69j2-hx56](https://github.com/advisories/GHSA-8757-69j2-hx56): crafted backup restore can read arbitrary local files.
- **Dynamic-Datasource** — [GHSA-6rmm-pg23-5f8q](https://github.com/advisories/GHSA-6rmm-pg23-5f8q): injection vulnerability.
- **ShowDoc** — [GHSA-fm5r-cj7v-rj2c](https://github.com/advisories/GHSA-fm5r-cj7v-rj2c): injection vulnerability.

## Operator triage

1. Inventory CMS/admin import paths: plugin ZIP installs, backup restores, package-management APIs, route-driven import actions, and data-source configuration endpoints.
2. Disable direct install/import endpoints that are internet-facing or reachable by low-trust admin roles until patched.
3. Hunt for unexpected plugin directories, newly written PHP/Java/Python files, backup restore activity, package folders containing `../`, absolute paths, symlinks, or control characters.
4. For Camel routes, identify endpoints that deserialize objects or accept untrusted transport payloads; move them behind strict authentication and type allowlists.
5. Treat successful plugin installation, backup restore, or path-traversal writes as host compromise, not just application compromise.

## Durable controls

- Import and plugin features need canonical extraction roots, symlink refusal, extension/type allowlists, archive bomb limits, and post-extraction path verification.
- Admin APIs should authorize the exact action on the exact resource; "admin panel access" is not enough for super-admin or install privileges.
- Java integration components should reject native deserialization for network input unless a minimal class allowlist is enforced.
- Backup restore code must never dereference paths from archive metadata without normalization under an operator-selected restore root.
- Injection-prone configuration values should be parsed as data, not concatenated into SQL, shell, expression, or template contexts.
