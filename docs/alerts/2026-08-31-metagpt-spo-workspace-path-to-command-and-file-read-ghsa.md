# MetaGPT SPO extension and class-view rebuild

Source: GitHub Security Advisories REST API, published 2026-08-31.

These two records are durable because they show the same operator pattern two ways in one agent framework: **an attacker-influenceable repository/workspace path crossing a command boundary and a filesystem containment boundary**. MetaGPT agents routinely clone and analyze repositories whose names and contents are attacker-influenced, so "path" is not a trusted internal value here.

## What changed

- **MetaGPT `RepoParser.rebuild_class_views()` OS command injection**, [GHSA-w32p-36mf-mmvj](https://github.com/advisories/GHSA-w32p-36mf-mmvj) / CVE-2026-79408 (CWE-78): `metagpt/repo_parser.py` `rebuild_class_views()` interpolates the caller-supplied `path` argument unquoted into `f"pyreverse {str(path)} -o dot"` and runs it with `subprocess.run(command, shell=True)`. The two guards (`path.exists()` and `(path / "__init__.py").exists()`) only require that a directory whose *name* contains shell metacharacters exists with an `__init__.py`, trivially satisfied by a checked-out repository whose directory name is attacker-chosen. Reachable through `metagpt/actions/rebuild_class_view.py` where `path=Path(self.i_context)` (the action's workspace context), and indirectly through `GitRepository.clone_from`, which derives the clone directory name from the repository URL.
- **MetaGPT SPO extension arbitrary file read**, [GHSA-2p3m-whr7-9m4w](https://github.com/advisories/GHSA-2p3m-whr7-9m4w) / CVE-2026-79407 (CWE-22): `metagpt/ext/spo/utils/load.py` `load_meta_data()` joins the attacker-controlled `FILE_NAME` (set via `set_file_name()`) to `metagpt/ext/spo/settings/` with no containment check, so `../`-based values escape the settings directory and read arbitrary files reachable by the process user. The related sink `metagpt/ext/spo/app.py` `save_yaml_template()` performs an unvalidated arbitrary file *write* through `template_path` when the SPO Streamlit UI is reachable by an untrusted user.

## Operator triage

1. Inventory agent/LLM-framework deployments that ingest attacker-influenced repository or workspace paths: MetaGPT 0.8.1 and derivatives, and any framework that shells out with a path taken from a clone URL, task prompt, or UI field.
2. In scoped code review, enumerate `subprocess.run`/`os.system`/`Popen` call sites whose command string contains a path, URL-derived name, or filename field, and flag `shell=True` or unquoted interpolation. The reusable heuristic: **a "validate the path" guard that checks existence but not lexical form does not stop command substitution in the path's directory name.**
3. Enumerate file-open sinks that join user-settable names to a fixed settings/template/config root without a canonicalized containment check (`Path(base) / user_name` with no `resolve().is_relative_to(base)` equivalent).
4. Prioritize deployments where an untrusted user can supply the repository URL, the cloned directory name, or SPO `FILE_NAME`/`template_path` values.

## Replayable validation boundaries

### Workspace-path command-injection canary

Use this for MetaGPT-style class-view rebuilds and any agent helper that shells out on a path.

1. In a disposable clone of the affected release (or a minimal lab app that reproduces the sink), create a directory whose name embeds an inert marker, for example `metagpt_poc_$(touch /tmp/skillz-metagpt-marker)` containing an `__init__.py` so the preconditions pass.
2. Point the sink at that directory with the framework's normal entry path (in MetaGPT, `RepoParser(base_directory=p).rebuild_class_views(path=p)`).
3. Vulnerable result: the marker file exists after the call, or logs show the shell interpreted metacharacters. Note the marker fires even when the named tool (e.g. `pyreverse`) is not installed, the substitution happens before the tool runs.
4. Capture the exact sink, the `shell=True` call site, who can set the path, the required preconditions, and execution identity. Do not exfiltrate environment data or run destructive commands; a marker file is the complete proof.
5. Negative controls: the same directory with a plain name (no metacharacters) must not create a marker, proving the shell interpretation is the boundary.

### SPO settings-directory file-read canary

Use this for MetaGPT SPO `load_meta_data()` and similar settings-root joins.

1. Plant a synthetic marker (YAML with a unique token) in a disposable directory outside the intended settings root; never use real credentials, keys, or production data.
2. Call `set_file_name()` with a relative `../` sequence that resolves to the marker, then trigger `load_meta_data()`.
3. Vulnerable result: the loader returns the marker's contents. Record the raw `FILE_NAME`, the joined path, the canonical target, and whether the read recorder fired.
4. For the adjacent write sink (`save_yaml_template`), replace the final `open(..., 'w')` with a deny-and-record sink and prove only that the caller-selected `template_path` escapes the template root; do not overwrite retained files.
5. Compare against a fixed build or a `resolve().is_relative_to(root)` control to show the containment boundary.

## Reporting heuristics

- Frame both issues as **attacker-influenceable repository/workspace path crossing a command boundary (CVE-2026-79408) and a filesystem containment boundary (CVE-2026-79407)** in the same agent framework. Strong reports include the URL-to-clone-directory derivation, the guard analysis (existence checks do not neutralize shell metacharacters in directory names), and the exact `shell=True` call site.
- Keep PoCs to inert marker files and synthetic settings; do not read real secrets, mutate production repositories, or execute payloads beyond a marker `touch`.
- Include the MetaGPT version, the reachable action/extension (class-view rebuild, SPO UI), the authentication state needed to set the path or `FILE_NAME`, and the execution identity.
- For the write sink, report the escape path but stop at the denied write recorder; arbitrary file write to command-executable locations is a separate impact claim that requires explicit lab authorization.
- The same feed wave included a large batch of sparse WordPress plugin/theme records (unauthenticated SQLi/XSS/auth-bypass/broken-access-control themes and plugins), availability-only records, and re-surfaced old advisories; those were reviewed and marked processed without publication because they are product-specific with no reusable operator boundary.

## Sources

- GitHub Advisory Database: [GHSA-w32p-36mf-mmvj / CVE-2026-79408](https://github.com/advisories/GHSA-w32p-36mf-mmvj)
- GitHub Advisory Database: [GHSA-2p3m-whr7-9m4w / CVE-2026-79407](https://github.com/advisories/GHSA-2p3m-whr7-9m4w)
- MetaGPT SPO writeups: <https://github.com/REYu6/Metagpt-vul/blob/main/CVE-1-MetaGPT-command-injection.md> and <https://github.com/REYu6/Metagpt-vul/blob/main/CVE-2-MetaGPT-path-traversal.md>
- MetaGPT source: <https://github.com/FoundationAgents/MetaGPT>
- Related wiki page: [Agent, SSRF, command, and local IPC boundary checks](2026-06-07-agent-ssrf-command-and-local-ipc-boundaries-ghsa.md) (MetaGPT `mermaid.path` command-injection boundary)
