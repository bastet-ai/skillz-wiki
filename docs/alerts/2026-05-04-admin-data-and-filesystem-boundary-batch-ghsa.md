# Admin, data, and filesystem-boundary batch (GHSA)

**Signal:** GitHub Security Advisories surfaced a **2026-05-04** batch where admin-like panels and filesystem adapters failed to separate low-trust users, station/project data, and host files.

## Advisories in this batch

- **zrok WebDAV drive symlink escape** — `github.com/openziti/zrok <= 1.1.11` and `github.com/openziti/zrok/v2 < 2.0.2` allowed WebDAV drive backends to follow symlinks outside `DriveRoot`, enabling host filesystem read/write. Reference: <https://github.com/advisories/GHSA-74m3-9qvm-rp9h>, CVE-2026-42275.
- **Pelican Web UI privilege escalation** — `github.com/pelicanplatform/pelican` before build `0.0.0-20260408120501-7f73b9c3e677` was affected by a critical Web UI privilege escalation issue. Reference: <https://github.com/advisories/GHSA-rpfr-x88x-xwcw>, CVE-2026-42571.
- **phpVMS importer authorization bypass** — `nabeel/phpvms < 7.0.6` exposed `/importer` behavior that could be reached without proper authorization and wipe the database. Reference: <https://github.com/advisories/GHSA-fv26-4939-62fh>, CVE-2026-42569.
- **livewire-markdown-editor arbitrary upload/stored XSS** — `mckenziearts/livewire-markdown-editor < 1.3` allowed arbitrary attachment upload leading to stored XSS. Reference: <https://github.com/advisories/GHSA-gxxh-8vcj-w2mh>.
- **n8n-MCP sensitive argument logging** — `n8n-mcp < 2.47.13` logged sensitive MCP tool-call arguments on authenticated HTTP-mode requests. Reference: <https://github.com/advisories/GHSA-wg4g-395p-mqv3>, CVE-2026-42282.
- **ParquetSharp stack overflow** — `ParquetSharp >= 18.1.0, < 23.0.0.1` could stack overflow on Parquet files with large decimal type widths. Reference: <https://github.com/advisories/GHSA-rrjr-v56m-ww88>, CVE-2026-42241.

## Why this is durable

Admin utilities, importers, WebDAV, markdown attachments, model/tool logs, and data readers often sit beside trusted workflows. Attackers look for these “supporting” paths because they frequently skip the same authorization, path containment, output encoding, secret redaction, and resource limits as the main product.

## Immediate triage

1. Patch zrok, Pelican, phpVMS, livewire-markdown-editor, n8n-MCP, and ParquetSharp where present.
2. Disable phpVMS importers and destructive maintenance endpoints unless they are behind strong admin auth and CSRF protection.
3. Audit WebDAV roots for symlinks and unexpected files created or modified outside intended storage.
4. Redact and rotate MCP/tool secrets that may have been logged in n8n-MCP HTTP mode.
5. Quarantine untrusted Parquet files and process them with resource limits until patched.

## Hunt ideas

- Search WebDAV access logs for symlink names, dot segments, encoded separators, and writes near host config paths.
- Review phpVMS logs for `/importer` hits from non-admin sessions or unauthenticated clients, followed by table drops or mass deletes.
- Search uploaded markdown attachments for HTML, SVG, polyglot images, executable MIME mismatches, and stored-script payloads.
- Grep n8n-MCP logs for `Authorization`, API tokens, prompt/tool arguments, filesystem paths, and credential-shaped strings.

## Durable controls

- Use no-follow opens and canonical path containment for every filesystem adapter, not just HTTP file serving.
- Require explicit admin authorization and confirmation for importers, migrations, resets, and destructive utilities.
- Store tool-call logs behind redaction middleware with field-level deny lists for secrets, prompts, tokens, and credentials.
- Put parser-heavy data formats behind depth, size, type-width, and CPU/memory budgets.

## Operator lesson

Support features are production attack surface. If it imports, mounts, uploads, logs, or parses on behalf of a user, test it like an admin panel.
