# Agent, Git, and file execution-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because it repeats a modern tooling lesson: developer helpers, MCP tools, Git libraries, media processors, and package wrappers become execution boundaries whenever untrusted input can choose paths, command arguments, submodule metadata, or export destinations.

## Advisories covered

- **wireshark-mcp `export_objects`** — [GHSA-3r68-x3xc-rxpg](https://github.com/advisories/GHSA-3r68-x3xc-rxpg): arbitrary file write when `WIRESHARK_MCP_ALLOWED_DIRS` is not configured.
- **simple-git** — [GHSA-hffm-xvc3-vprc](https://github.com/advisories/GHSA-hffm-xvc3-vprc): remote code execution through unsafe Git command construction.
- **exiftool-vendored** — [GHSA-cw26-7653-2rp5](https://github.com/advisories/GHSA-cw26-7653-2rp5): argument injection through newline characters in tag names.
- **gix/gitoxide submodule state traversal** — [GHSA-fr8x-3vfx-f45h](https://github.com/advisories/GHSA-fr8x-3vfx-f45h): unvalidated submodule names can redirect `.git/modules` state/open operations to another repository.
- **gix/gitoxide symlinked `.gitmodules`** — [GHSA-pg4w-g64p-qwhj](https://github.com/advisories/GHSA-pg4w-g64p-qwhj): symlinked `.gitmodules` can be followed and parsed outside the repository.
- **gix-pack** — [GHSA-x494-mj8g-cj27](https://github.com/advisories/GHSA-x494-mj8g-cj27): crafted pack data can trigger unchecked indexing panics and uncapped memory allocations.
- **gitoxide `.gitmodules` command bypass** — [GHSA-f26g-jm89-4g65](https://github.com/advisories/GHSA-f26g-jm89-4g65): `CommandForbiddenInModulesConfiguration` can be bypassed in `gix_submodule::File::update()` to enable command execution.
- **gix submodule validation and credential disclosure** — [GHSA-p3hw-mv63-rf9w](https://github.com/advisories/GHSA-p3hw-mv63-rf9w): submodule-name validation bypass plus trust inheritance can enable path traversal and credential disclosure.
- **gix-transport curl backend** — [GHSA-9857-6mw7-fq2m](https://github.com/advisories/GHSA-9857-6mw7-fq2m): HTTP credentials can leak to redirected hosts.

## Operator triage

1. Inventory tools that parse attacker-controlled repositories, packets, media, EXIF metadata, or MCP requests.
2. Pin/upgrade affected Git, simple-git, gix/gitoxide, ExifTool wrapper, and wireshark-mcp dependencies before processing untrusted inputs.
3. Disable MCP file-export tools unless an explicit allowed-directory list is configured and enforced after canonical path resolution.
4. Hunt build and analysis hosts for writes outside expected scratch directories, unexpected `.git/modules` paths, symlinked `.gitmodules`, suspicious submodule names, and Git config keys that spawn commands.
5. Treat credentials used during repository fetches as exposed if redirects to untrusted hosts occurred.

## Durable controls

- Every helper that writes files needs a final canonical-path check under an operator-selected root, plus symlink refusal and extension/size limits.
- Never pass user-controlled metadata into command-line arguments without structural separation and rejection of control characters.
- Repository parsers must treat `.gitmodules`, submodule names, pack files, and transport redirects as hostile input.
- Credentials used for Git fetches should be scoped per host and stripped on cross-origin redirects.
- MCP tools should fail closed when capability configuration is absent; permissive defaults are unsafe.
