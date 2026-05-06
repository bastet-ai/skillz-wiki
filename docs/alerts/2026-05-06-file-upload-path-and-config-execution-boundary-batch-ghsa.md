# File upload, path, and config-execution boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-06** cluster where file names, upload types, project paths, and configuration values crossed into filesystem writes or command execution.

## Advisories covered

- **Cockpit dangerous upload, path traversal, and RCE batch** — [GHSA-j2rx-4jg9-79mw](https://github.com/advisories/GHSA-j2rx-4jg9-79mw), [GHSA-p46p-7pmj-m34f](https://github.com/advisories/GHSA-p46p-7pmj-m34f), [GHSA-fm6c-rhcf-7439](https://github.com/advisories/GHSA-fm6c-rhcf-7439): upload and traversal boundaries could reach dangerous server-side effects.
- **mcpo-simple-server path traversal** — [GHSA-3jmq-qhg3-f58j](https://github.com/advisories/GHSA-3jmq-qhg3-f58j): path input could escape the intended file root.
- **Grav Form Plugin anonymous content overwrite** — [GHSA-w4rc-p66m-x6qq](https://github.com/advisories/GHSA-w4rc-p66m-x6qq): uploaded filenames could overwrite page content.
- **Jenkins Credentials Binding Plugin path traversal** — [GHSA-p2rf-wpxj-mx2g](https://github.com/advisories/GHSA-p2rf-wpxj-mx2g): credential-binding paths needed strict containment.
- **Dolibarr configuration-triggered command injection** — [GHSA-w5j3-8fcr-h87w](https://github.com/advisories/GHSA-w5j3-8fcr-h87w): `MAIN_ODT_AS_PDF` configuration could become an OS command execution path.

## Why this is durable

Upload handlers and admin configuration both look like data-entry features, but they frequently become write primitives or execution primitives. The invariant is simple: user-controlled names, paths, and command-like configuration must never be interpreted in a more privileged filesystem or shell context.

## Immediate triage

1. Patch affected applications and plugins; prioritize internet-facing admin consoles and file-upload workflows.
2. Inventory writable upload roots and verify generated storage names are server-owned, random, and extension allowlisted.
3. Test path inputs with encoded separators, absolute paths, symlink targets, Windows drive prefixes, and archive-style traversal.
4. Review configuration fields that select binaries, converters, templates, or shell fragments; replace free-form command values with allowlisted modes.
5. Hunt for unexpected writes under content roots, plugin directories, build workspaces, credential-binding workspaces, and document-conversion temp paths.

## Durable controls

- Canonicalize and re-check the final path after joins, symlink resolution, archive extraction, and temporary-file moves.
- Store uploads outside executable/content-served roots unless a separate publication step sanitizes and copies immutable artifacts.
- Treat admin-set command paths as privileged code deployment and require explicit allowlists, audit logs, and rollback.
- Run converters and upload processors in least-privilege sandboxes with no access to application secrets.
