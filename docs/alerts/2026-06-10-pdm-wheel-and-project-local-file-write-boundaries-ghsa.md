# PDM wheel and project-local file-write boundaries

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-78v8-vpjp-cjqh](https://github.com/advisories/GHSA-78v8-vpjp-cjqh) / CVE-2026-47764 for PDM wheel installation path traversal through `InstallDestination.write_to_fs()`, and [GHSA-ghq2-5c67-fprm](https://github.com/advisories/GHSA-ghq2-5c67-fprm) / CVE-2026-47763 for project-local state and config writes following symlinks.

This batch is durable for operators because it gives a reusable Python package-manager testing pattern: **attacker-controlled package or repository content crossing from the project tree into arbitrary filesystem writes by the invoking user**.

## Why it matters for assessments

PDM is often run by developers, CI jobs, release workers, and automation that trust repository-local metadata. The two advisories expose adjacent file-boundary primitives:

- a malicious wheel can include traversal entries that are joined into the install destination without the base installer's resolved-path containment check;
- a malicious repository can place project-local PDM state files as symlinks so later `pdm` operations overwrite the symlink target.

Neither proof requires leaking real secrets. Good evidence shows that a controlled canary file outside the project or install root was created or modified by a normal package-manager action.

## What to map

1. Find projects, CI workflows, devcontainer images, release scripts, or build agents that run `pdm install`, `pdm sync`, `pdm add`, `pdm config -l`, or `pdm use` against contributor-controlled branches or dependencies.
2. Record the PDM version and interpreter path. The wheel traversal advisory affects PDM `<= 2.22.4`; the symlink-write advisory affects PDM `< 2.27.0`.
3. Identify whether the actor can influence wheel contents, direct URL dependencies, package indexes, lockfile entries, or checked-out repository files.
4. Map the privilege context: local developer shell, CI runner, release builder, container root, package-publishing job, or shared workstation.
5. Pick the lowest-impact writable canary target outside the project or install root. Do not target shell startup files, SSH material, package credentials, service units, or production config.

## Wheel traversal validation boundary

Use a lab package or an explicitly approved dependency-confusion/supply-chain test. Do not publish a malicious wheel to a public package name or replace a real dependency.

Safe proof shape:

1. Build a disposable wheel containing only a traversal-path canary entry that writes a marker such as `skillz-pdm-wheel-canary` to a temporary directory outside the intended install root.
2. Install it with the same PDM path and options used by the target workflow, preferably in a temporary virtual environment or disposable CI job.
3. Confirm whether the marker lands outside the expected installation destination.
4. Capture redacted evidence: PDM version, command, wheel source under tester control, expected destination, actual canary path, and file metadata.
5. Stop at canary write proof. Do not overwrite executable startup paths or sensitive files.

A strong finding demonstrates both attacker control over the wheel source and execution of a normal PDM install path in a context whose filesystem privileges matter.

## Project-local symlink write validation boundary

Use a temporary clone or approved lab repository. The advisory notes `pdm.toml` as a stable sink, with related sinks including `.pdm-python` and `.python-version`.

Minimal canary flow:

```bash
# Use the same interpreter/PDM entrypoint as the tested workflow.
PDM_PY=/path/to/python-with-pdm
lab=$(mktemp -d)
target="$lab/outside-target.toml"

cat > "$target" <<'EOF'
[seed]
value = 1
EOF

mkdir "$lab/repo"
ln -s "$target" "$lab/repo/pdm.toml"
cat > "$lab/repo/pyproject.toml" <<'EOF'
[project]
name = "skillz-pdm-symlink-canary"
version = "0.0.1"
EOF

(
  cd "$lab/repo" &&
  "$PDM_PY" -m pdm config -l venv.in_project false
)

printf '\n--- canary target ---\n'
cat "$target"
```

Expected vulnerable signal: the TOML file outside the repository gains a `[venv]` section or other PDM-written configuration. If `pdm.toml` does not parse as TOML, this specific sink may fail before the write path; use a parseable canary target for this proof.

## Reporting heuristics

- Lead with the boundary: **untrusted package or repository content caused PDM to write outside the intended project/install root as the invoking user**.
- Include PDM version, affected command, attacker-controlled input source, expected containment root, actual canary target, and the runner/user privilege context.
- For CI impact, show whether the job also has release tokens, package-publishing rights, repository write tokens, cache directories, or artifact-signing access; do not print token values.
- Keep proof narrow and reversible. Use temporary canary files, not real dotfiles, credentials, deployment manifests, or shell profiles.
- Avoid claiming code execution unless you separately prove that the file-write primitive reaches an executable or auto-loaded path in the assessed environment.
