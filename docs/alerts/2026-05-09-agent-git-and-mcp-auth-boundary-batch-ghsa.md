# Agent, Git, and MCP auth-boundary batch

**Signal:** The **2026-05-09 00:15 UTC** scan added agent/Git control-plane advisories where local developer tools exposed privileged tokens or trusted Git configuration writes.

## Advisory cluster

- **GitLab MCP Server unauthenticated SSE transport** — [GHSA-8jr5-6gvj-rfpf](https://github.com/advisories/GHSA-8jr5-6gvj-rfpf) / CVE-2026-44895: `@yoda.digital/gitlab-mcp-server <0.6.0` exposed `/sse` and `/messages?sessionId=...` without authentication, set wildcard CORS, and bound to all interfaces when `USE_SSE=true`, allowing callers or malicious browser tabs to invoke GitLab tools with the operator's PAT. Patch to **0.6.0+**.
- **GitPython config section newline injection** — [GHSA-mv93-w799-cj2w](https://github.com/advisories/GHSA-mv93-w799-cj2w): the CVE-2026-42215 patch validated only config values; attacker-controlled `section` or `option` names could inject new config headers such as `[core] hooksPath`, restoring RCE via Git hooks. Patch `GitPython` to **3.1.50+**.
- **Langchain-Chatchat predictable uploaded-file IDs** — [GHSA-jv4p-mhmp-69vw](https://github.com/advisories/GHSA-jv4p-mhmp-69vw) / CVE-2026-7847: `_get_file_id` used insufficient randomness in the uploaded-file handler through **0.3.1.3**; no patched version was listed at scan time.

## Why this matters

Agent and developer tooling often runs “locally” with powerful bearer tokens, filesystem access, and repository mutation rights. If an HTTP/SSE transport is unauthenticated, if CORS invites browser-origin calls, or if Git config writers accept untrusted control characters, the safe-local assumption collapses into token-backed remote operations.

## Triage

1. Disable `USE_SSE=true` GitLab MCP deployments until patched and configured with authentication, loopback binding, and an explicit CORS allowlist.
2. Rotate any GitLab PAT used by an exposed MCP server if the port was reachable from a browser, LAN, VPN, cloud security group, container network, or shared host.
3. Patch GitPython to **3.1.50+** and audit code paths where branch names, user names, remotes, project metadata, or LLM output can reach `config_writer().set_value()` section/option arguments.
4. Hunt for unexpected `core.hooksPath`, duplicate injected config sections, or newline characters in generated Git config keys.
5. Replace predictable upload IDs with cryptographically random, unguessable IDs and authorization checks keyed to owner/session, not identifier secrecy alone.

## Durable controls

- Local HTTP transports that can mutate external systems must require auth by default, bind to loopback by default, and reject wildcard CORS.
- Treat every Git config field as syntax, not text; validate section, option, and value names against a strict grammar before writing.
- Put agent tools behind least-privilege tokens and separate read-only, write, and destructive operations into distinct credentials.
- Log MCP session creation and tool calls with caller origin, remote address, token identity, and destructive-operation markers.

## October 1 follow-up: the GitPython wave — untrusted repositories as a code-execution input (Sept 30 GHSA train)

Source: GitHub Security Advisories published 2026-09-30 (fixed 3.1.60/3.1.62). Four advisories, one target library, one durable target class: **any service that opens or clones attacker-supplied repositories with GitPython** — CI fork-PR builders, code scanners/SBOM services, mirrors, dependency bots, AI code-review agents.

- **Repository content impersonates the git directory → hook RCE** ([GHSA-239g-whfq-7xj9](https://github.com/advisories/GHSA-239g-whfq-7xj9), CVE-2026-87817, high, fixed 3.1.60): `Repo.__init__` tests candidate git-dirs in an order that considers the real `.git` **last** — a root-level `gitdir` + `commondir` + `HEAD` file triple satisfies the first check, and `is_git_dir` needs only `objects/` + `refs/` dirs with an unvalidated `HEAD`. GitPython then resolves `git_dir` to the **working-tree root** while real git resolves `<root>/.git`; every "inside the git dir" operation — including `hooks/pre-commit`, which it **executes** on the next `index.commit()` — reads attacker-authored tracked files. Four ordinary tracked files (three regular-mode, one 100755 hook) are the payload; `git fsck` stays clean because git itself never sees the shadow. Operator rules: (1) **git reserves only the literal name `.git` — `HEAD`, `config`, `objects/`, `hooks/` at a repo root are legal tracked content**, so any library with its own git-dir discovery is a parser-differential target; diff "what does the library think git_dir is" vs `git rev-parse --git-dir` on the same clone; (2) for CI/scanner hunting, clone-then-commit pipelines (automated commits, version bumpers, linters that write) fire the hook — fingerprint them from fork-PR access by submitting the four-file canary repo in an authorized lab runner.
- **`--no-index` defeats the diff unsafe-option hardening — alternate-route-to-same-property pattern** ([GHSA-whh4-5q6c-9v3x](https://github.com/advisories/GHSA-whh4-5q6c-9v3x), fixed 3.1.60): 3.1.59 blocked `-O/--orderfile` local-file reads with `UnsafeOptionError`, but `--no-index` (allowed under default `allow_unsafe_options=False`) reinterprets `paths` as arbitrary filesystem operands, and `-I/--ignore-matching-lines` turns the diff result into a **content-dependent boolean** (empty DiffIndex vs `GitCommandError` exit 1) — a blind local-file content oracle against apps that forward diff options/paths. Audit rule: after any option-blocklist fix, enumerate **semantically equivalent alternate spellings** (`--no-index`, `--git-dir=`, `-c` config overrides, separator tricks) rather than trusting the blocked-token list; the fix closes a token, not the property.
- **`.gitmodules` `path` consumed raw while `name` got the containment guard** ([GHSA-59cr-6r3x-644w](https://github.com/advisories/GHSA-59cr-6r3x-644w), ≤3.1.61, fixed 3.1.62): the prior fix added `_validated_name()` for the submodule name and wired it into six call sites, and added `_to_relative_path()` guarding `add()` and `move()` — but `update()`-family consumers of the raw `path` value stayed unguarded. Per-consumer validator coverage drift, the same shape as the per-tool MCP validators (Sept 22) and per-auth-branch SSRF hooks: when a library adds a sanitizer, enumerate **every** consumer of the tainted field, not the one named in the advisory.
- **ReDoS in commit-author parsing — data inside the repo burns the scanner** ([GHSA-g5vv-9gxw-82hx](https://github.com/advisories/GHSA-g5vv-9gxw-82hx), high, fixed 3.1.60): `name_email_regex = r"(.*) <(.*?)>"` catastrophically backtracks (>2 min per call) on a commit author/committer header with a long unterminated `<`. One crafted commit object stalls every CI/scanner call that reads `.author`. This is the repo-data-attacks-parser axis: attacker-controlled *content fields* (not just paths/options) reach library regexes; for any repo-ingest service, craft author strings, tag names, and filenames as first-class DoS/gadget probes.

Validation stays bounded: disposable repos with marker-writing inert hooks in temp directories, scratch files for the oracle leg, and never hooks that mutate anything outside the lab root. The reusable sweep rules — git-dir differential, alternate-spelling fix review, all-consumers validator audit, content-field ReDoS probes — extend this page's Git-config trust boundary to repository *content* as untrusted input to the tooling that opens it.
