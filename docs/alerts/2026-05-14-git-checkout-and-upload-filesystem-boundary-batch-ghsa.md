# Git checkout and upload filesystem-boundary batch

**Signal:** The **2026-05-14 23:15 UTC** advisory scan surfaced two older but newly updated GitHub Security Advisories that share a durable lesson: attacker-controlled paths must not be allowed to cross from repository/archive/upload metadata into trusted server filesystem locations.

## Advisories

- [GHSA-4j5j-58j7-6c3w](https://github.com/advisories/GHSA-4j5j-58j7-6c3w) / CVE-2014-9706: **Dulwich arbitrary code execution via `.git/` checkout paths**
  - **Package:** pip `dulwich`
  - **Affected:** `< 0.9.10`
  - **Fixed:** `0.9.10`
  - **Severity:** critical
  - **Boundary failure:** `build_index_from_tree` did not safely handle a commit containing a directory path starting with `.git/` when checking out a working tree. A malicious repository object could therefore write into Git control metadata and turn a checkout into code execution.
- [GHSA-9hxg-w7qf-hh93](https://github.com/advisories/GHSA-9hxg-w7qf-hh93) / CVE-2018-20303: **Gogs upload directory traversal**
  - **Package:** Go `gogs.io/gogs`
  - **Affected:** `< 0.11.80-0.20181218063808-ff93d9dbda5c`
  - **Fixed:** `0.11.80-0.20181218063808-ff93d9dbda5c`
  - **Severity:** high
  - **Boundary failure:** file-upload path handling could create a file under `data/sessions` on the server, echoing prior Gogs session-file traversal chains.

## Why this matters

Repository checkout, archive extraction, and web upload features often look like simple file writes, but they sit on high-value boundaries. A single special path segment can move attacker-controlled bytes from a data directory into Git metadata, session storage, hook paths, configuration, templates, or other execution-adjacent locations.

The common mistake is validating for `../` traversal but missing control-directory names (`.git`, `.hg`, `.svn`), alternate separators, symlinks, case-insensitive filesystem behavior, Unicode normalization, or post-normalization prefix escapes.

## Triage

1. Upgrade `dulwich` to `0.9.10+` and any Gogs deployments to a fixed release; old vendored copies matter if a product embeds Git checkout or Gogs-like upload logic.
2. Search for repository checkout, archive extraction, template import, backup restore, and upload handlers that preserve client- or repository-supplied paths.
3. Add regression payloads for `.git/`, `.git/hooks/`, `.git/config`, `../`, encoded separators, absolute paths, Unicode/case variants, and symlink-mediated escapes.
4. For self-hosted Git or code-hosting servers, inspect upload/session directories and repository working trees for unexpected files created near control metadata or session storage.

## Durable controls

- Canonicalize after decoding and before writing; then enforce that the final resolved path remains under the intended storage root.
- Deny reserved control directories and execution-adjacent paths at every depth, not only as top-level names.
- Extract/check out into a temporary quarantine directory, validate the full tree, then atomically promote safe files.
- Keep session stores, hook/config directories, and executable/plugin paths outside any upload- or checkout-writable tree.
- Prefer generated server-side filenames for uploads; if original names are needed, store them as metadata rather than path components.
