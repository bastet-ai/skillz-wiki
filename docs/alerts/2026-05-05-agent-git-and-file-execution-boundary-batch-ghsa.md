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

## October 6 follow-up: simple-git denylist family — five ways to miss the one spelling that matters (4 GHSAs, 23:47–23:48Z)

`simple-git` 3.36.0 shipped a four-advisory wave in one minute — another coordinated dump, and the cleanest public worked example of why **every denylist-based guard is an enumeration that fails by omission**. All legs share the precondition: the app flows attacker-influenced values into `customArgs`, instance `config`, or child env while relying on `blockUnsafeOperationsPlugin` defaults.

- **`-c include.path=<file>` absent from the config denylist** ([GHSA-g4wm-2vf7-vfgr](https://github.com/advisories/GHSA-g4wm-2vf7-vfgr) / CVE-2026-102826, 8.1): loads any local file as gitconfig, which sets `core.sshCommand` (an otherwise-denied key), and the next remote op in the same clone executes it. The pending fix's regex `/\s*include.path/` still misses the **conditional form `includeIf.<cond>.path`** — the advisory shows a fix that names one spelling of a multi-spelling feature. Denylist-differential rule: for every gated config key, enumerate the grammar variants Git actually accepts (`include`, `includeIf.onbranch:.path`, section-case, escaped quotes).
- **Long-option prefix abbreviation bypass** ([GHSA-858h-whjf-mvg5](https://github.com/advisories/GHSA-858h-whjf-mvg5) / CVE-2026-102827, 8.1): the guard matches literal spellings (`/--(upload|receive)-pack/`, `'--exec'`) but the argv parser keeps the raw token as `flag.name` while **git itself unambiguously abbreviates** `--receive-p` → `--receive-pack`, `--exe` → `--exec` — executed on local/file remotes. The clone-side rule (`--u` substring) covers abbreviations; the push-side rules don't. Durable axis: **when a guard regexes an option name and the real binary accepts unambiguous prefixes, the guard must match the prefix set, not the full spelling** — fuzz every blocked flag by truncating it one character at a time.
- **`trailer.<token>.cmd` not classified unsafe** ([GHSA-x6jw-m9v5-85vh](https://github.com/advisories/GHSA-x6jw-m9v5-85vh) / CVE-2026-102828): a documented shell-command config key for `git interpret-trailers` missing from the denylist entirely — same shape as `include.path`: the denylist enumerates *known-exploited* keys, not *all command-executing keys*. Audit rule for any git wrapper: enumerate every git config key whose docs say "command" or "shell" (`core.editor`, `core.pager`, `core.sshCommand`, `sequence.editor`, `hooks.*`, `trailer.*.cmd`, `credential.helper`, `pager.*`, `alias.*`) and test each against the wrapper's guard — `alias.*` is the classic never-listed one.
- **`VISUAL` env var omitted from editor detection** ([GHSA-v5rq-49vh-5v5c](https://github.com/advisories/GHSA-v5rq-49vh-5v5c) / CVE-2026-102829): `GitEnvKeys` maps `EDITOR`/`GIT_EDITOR`/`GIT_SEQUENCE_EDITOR` to `allowUnsafeEditor` but drops `VISUAL` before inspection — while git falls back to `VISUAL` for editor resolution. Env-guard parity rule: enumerate the **full fallback chain** of the underlying binary (git's editor chain is GIT_EDITOR → core.editor → VISUAL → EDITOR → pager), not just the obvious names.

Operator summary: these four plus CVE-2026-28291/28292 form the longest public denylist-incomplete-fix chain in a developer library. For authorized assessments of CI bots, repo-parsing agents, or web apps shelling out via simple-git, the harness is: (1) inline `-c` key battery over the command-executing-key enumeration, (2) truncated-abbreviation battery over every blocked flag, (3) env-var fallback-chain battery, (4) proof with a `touch`-marker command against a local file remote only. Report the *class* (guard is enumeration-based) with the concrete surviving spelling — prior advisories in this chain each named their predecessor, so the fix-genealogy grep (`detectVulnerableConfigWrites`, `preventUnsafeConfig`) on the vendored source is the fastest fingerprint.
