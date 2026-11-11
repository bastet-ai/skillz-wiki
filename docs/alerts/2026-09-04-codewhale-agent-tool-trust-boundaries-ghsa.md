# CodeWhale

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (CodeWhale / `codewhale` + `deepseek-tui` CLI agent-tool cluster). Durable because CodeWhale is a local coding agent that bundles a set of filesystem/git/shell tools around an LLM, and the nine-advisory cluster maps one repeatable trust axis: **which tool inputs are treated as trusted configuration or data, versus which cross into shell, filesystem, network, or prompt authority without an approval gate.** The cluster generalizes the agent-tool boundary checks this wiki already carries for Claude Code, Aider, and MCP tool packs, but CodeWhale is notable for bundling the whole class into one npm/Rust CLI and for shipping a git-arg-injection primitive that reaches both file read and file write.

All nine entries target the `codewhale` (npm + rust) and `deepseek-tui` (npm + rust) packages; the `codewhale` line is affected `>= 0.8.41, < 0.8.64` and the `deepseek-tui` line `>= 0.3.27/0.8.5/0.8.8/0.8.32, <= 0.8.41` depending on the specific boundary. The critical anchor is [GHSA-6V2G-FPXH-PMMH](https://github.com/advisories/GHSA-6v2g-fpxh-pmmh) / CVE-2026-75856 (SSRF bypass, TOCTOU on DNS failure for DNS pinning). Full cluster:

| GHSA | Boundary | Defect | Reusable check |
| --- | --- | --- | --- |
| [GHSA-6V2G-FPXH-PMMH](https://github.com/advisories/GHSA-6v2g-fpxh-pmmh) / CVE-2026-75856 | SSRF / DNS pinning | TOCTOU on DNS failure lets a pin-check and the actual connect resolve to different hosts, bypassing the SSRF allow/deny decision | Drive a URL whose validation-time and connect-time DNS answers differ (owned lab resolver); record pinned host vs dialed host vs callback. |
| [GHSA-GX45-XRJ5-G6C4](https://github.com/advisories/GHSA-gx45-xrj5-g6c4) / CVE-2026-75911 | Project config `allow_shell` | a value inside a cloned repository's project config overrides the user's shell policy, enabling arbitrary shell command execution | Clone a repo whose project config sets `allow_shell`; confirm whether the tool honors repo-controlled config over the user's deny policy. |
| [GHSA-62F5-CP2P-VQ95](https://github.com/advisories/GHSA-62f5-cp2p-vq95) / CVE-2026-75859 | Project config `instructions` | repo-controlled `instructions` field injects arbitrary file contents into the AI system prompt | Point `instructions` at a marker file; capture whether file bytes enter the system prompt context. |
| [GHSA-WRJ3-VJ8C-784F](https://github.com/advisories/GHSA-wrj3-vj8c-784f) / CVE-2026-75858 | `rlm_eval` auto-approve | `rlm_eval` auto-approves arbitrary Python execution, bypassing the user's approval policy (RCE) | Invoke `rlm_eval` with an inert canary; record whether it executes without an approval prompt. |
| [GHSA-C6MW-8XH8-GPQ6](https://github.com/advisories/GHSA-c6mw-8xh8-gpq6) / CVE-2026-75912 | `git_blame` argument injection | crafted argument to `git_blame` reads arbitrary files without approval | Supply a git argument that escapes the intended repo; record whether an out-of-root marker is read. |
| [GHSA-7J5W-7R7X-9V27](https://github.com/advisories/GHSA-7j5w-7r7x-9v27) / CVE-2026-75913 | `git_show` argument injection | crafted argument to `git_show` writes arbitrary files without approval | Supply a git argument that writes; record whether an out-of-root marker is created/modified. |
| [GHSA-G29H-PFMP-QP9R](https://github.com/advisories/GHSA-g29h-pfmp-qp9r) / CVE-2026-75857 | `exec_shell_interact` | LLM-controlled input is sent to a running shell with no approval prompt (privilege escalation) | Feed a canary command through the interact path; record whether it reaches the shell without approval. |
| [GHSA-H539-C7R8-3XQ4](https://github.com/advisories/GHSA-h539-c7r8-3xq4) / CVE-2026-75915 | `js_execution` env scrub | parent environment leaks into model context because the execution env is not scrubbed | Seed a marker env var; capture whether it is visible to the executed JS/model context. |
| [GHSA-W7WX-5Q49-R59W](https://github.com/advisories/GHSA-w7wx-5q49-r59w) / CVE-2026-75914 | `image_analyze` symlink | follows workspace symlinks, leaking external file bytes | Place a symlink inside the workspace pointing at a sibling marker; record whether the analyzer reads the target. |

Fixed control across the cluster is the `0.8.64`-line for `codewhale` and the corresponding `0.8.41`-line for `deepseek-tui`; treat any earlier in-range build as in-scope for these boundaries.

!!! warning "Authorized validation only"
    Keep proofs to a disposable CodeWhale/`deepseek-tui` install with a synthetic repository, synthetic markers, and denied file/network/process sinks. Use a lab DNS resolver you own for the SSRF TOCTOU leg. Do not execute real payloads, read real credentials or environment secrets, reach internal/metadata services, or point the tool at a repository you do not own.

## Why this cluster is one audit axis

The 2026-02 Claude Code and Aider pages established the pattern: a coding agent that reads repository-controlled configuration (`settings.json`, project files, `.claude/` config) and then executes tools is only as safe as the boundary between *repo data* and *operator policy*. CodeWhale is the same class with more legs, because the tool family exposes six distinct sinks that each accept an unvalidated caller field:

- **Repo-config → shell:** `allow_shell` and `instructions` are read from the cloned repository and treated as policy. A malicious repo therefore both enables the shell and injects prompt content, the two strongest primitives in the cluster.
- **Git-tool argument injection → file read AND file write:** `git_blame`/`git_show` are ordinary read/show verbs, but the argument surface lets a crafted value reach a filesystem read (75912) and a filesystem write (75913) with no approval. This is the unusual leg, most agent-tool findings are read-only; a git-arg write primitive is an escalation primitive.
- **Approval-policy bypass:** `rlm_eval` auto-approves Python and `exec_shell_interact` forwards LLM-controlled input to a running shell, so the user's "ask me before running commands" control is bypassed by two separate paths.
- **SSRF pin TOCTOU:** the DNS-pinning SSRF guard resolves the host once for the policy check and again at connect; a DNS-failure-induced race means the two resolutions can disagree.
- **Env + symlink exfil:** `js_execution` does not scrub the parent environment into model context, and `image_analyze` follows workspace symlinks, both are disclosure legs that turn a read primitive into a secret/file read.

## Replayable validation boundaries

### Repo-config shell/prompt override (`allow_shell`, `instructions`)

1. Prepare a synthetic repository whose project config (the file CodeWhale reads at clone/open) sets `allow_shell` to true and an `instructions` field that names one inert marker file outside the repo root.
2. Run a disposable CodeWhale build `>= 0.8.6, < 0.8.64` against it in a throwaway account with a *denied* user-level shell policy.
3. Record: does the shell policy come from the user profile or from the repo config? Does `instructions` cause the marker file's bytes to appear in the system prompt context?
4. Negative control: the `0.8.64` build, and a build where the user-level deny is the controlling policy.

Report as **cloned-repo project config -> user shell/prompt policy** and name the exact config key and the marker content boundary. Do not run a real shell payload; prove the override with the marker file entering prompt context and the shell becoming enabled.

### Git-tool argument injection (read via `git_blame`, write via `git_show`)

1. In a disposable repo, place a marker file just outside the intended repo root.
2. Drive `git_blame` with an argument value that would resolve to that sibling path (e.g. a crafted pathspec/repo arg); record whether the tool's read primitive returns the marker.
3. Drive `git_show` with an argument value that would write to a sibling path; record whether the marker path is created or modified.
4. Keep the git operation to inert values and a single marker. Do not read credentials, do not overwrite startup files, and do not run `git` against a repository with hooks or credentials.

Report as **git tool argument -> filesystem path outside repo root** for each of read and write, with the exact argument form and the resolved path.

### Approval-policy bypass (`rlm_eval`, `exec_shell_interact`)

1. Configure a disposable CodeWhale with the user approval/confirm-on-command control enabled.
2. Trigger `rlm_eval` with an inert canary and `exec_shell_interact` with a canary command; record whether either reaches execution without the approval prompt that the control would normally raise.
3. Negative control: the fixed build or the control exercised on a benign command.

Report as **user approval control enabled -> tool path executes without prompt**, naming the tool.

### SSRF DNS-pinning TOCTOU

1. Use a lab DNS resolver you control for one owned hostname; make its A answer differ between the policy-check resolution and the connect-time resolution (owned, no cloud metadata, no RFC1918 production hosts).
2. Point the tool's guarded fetch at the hostname; record the host the pin-check accepted and the host actually dialed (owned listener callback as the dial proof).
3. A positive is policy = deny/pinned-host-X while the connection reaches your denied listener via host-Y.

Do not use metadata IPs, uncontrolled public DNS rebinding, or internal targets.

### Env-scrub and symlink leak

- Seed one marker environment variable; run `js_execution`; capture whether the variable value is visible to the executed context or model. Prove disclosure with the marker only.
- Create a symlink inside the workspace pointing at a sibling marker; run `image_analyze`; record whether the target's bytes are returned. Do not point the symlink at real secrets or credentials.

## Durable operator value

1. **Repo config is a policy input, not just data.** Any agent that reads `allow_shell` / `instructions` / settings from the working repository can be redirected by a malicious clone. The reusable check is: *for every policy key, which source wins, user profile or repo file?*
2. **Ordinary git verbs are not read-only.** `git_blame`/`git_show` expose argument-injection paths to filesystem read and write. When auditing coding-agent tool wrappers, treat every git/git2 invocation as a path-escape candidate, not a safe read.
3. **Approval controls are per-tool, not global.** A "confirm before running" switch that two tools (`rlm_eval`, `exec_shell_interact`) both bypass means the control is a whitelist, not a gate. Audit each tool's path through the approval predicate separately.
4. **DNS-pinning SSRF is a TOCTOU, not a config bug.** Validate-then-connect with two independent resolutions is bypassable whenever the DNS layer can fail over between them. The reusable check is the pinned-host vs dialed-host differential.
5. **Env + symlink are the exfil legs.** Disclosure of parent env and symlink-following are what turn a read primitive into a secret read; keep proofs to markers so the page stays a recon heuristic rather than a payload sheet.

## Safety

- **Disposable install + synthetic repo.** Throwaway account, no credentials, no plugins, denied file/network/process sinks.
- **No real shell/RCE payloads.** Prove overrides with marker content and marker files.
- **No real data/secret reads.** Env and symlink legs use markers only.
- **No internal/metadata reach.** SSRF uses an owned lab resolver and listener.
- **No hook-bearing or credentialed repos** in the git-arg tests.

---

*Source: hourly offensive-security scan, 2026-09-04. All 9 CodeWhale/`deepseek-tui` advisories tracked in the [source index](../notes/source-index.md).*
