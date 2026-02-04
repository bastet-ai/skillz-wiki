# Agent tool command injection (argument injection via `shell=True`)

## Why this matters
Agent frameworks often expose “tools” that wrap OS commands (e.g., `find`, `grep`, `curl`, `git`). If a tool constructs a shell command using **untrusted input** (LLM output, web content, ticket text, PR comments, etc.) and executes it with a shell (e.g., Python `subprocess.Popen(..., shell=True)`), attackers can **inject flags or new commands** and obtain code execution.

This is especially dangerous in agentic systems because the injection can be triggered indirectly ("prompt injection") by:
- HTML comments / hidden text in a webpage the agent fetches
- issues/PRs the agent reads
- documentation the agent summarizes

## Example: argument injection via `find`
### CVE-2026-25130 (CAI framework)
A reviewed GitHub Security Advisory describes an argument injection vulnerability in CAI’s `find_file()` tool (CVE-2026-25130): user-controlled `args` is interpolated into a `find` command, which is executed via a shell. Attackers can pass `-exec ...` to run arbitrary commands.

### Claude Code: bypassing user approval prompts via `find`
GitHub also published an advisory for **@anthropic-ai/claude-code** describing a command injection issue where untrusted input could bypass the confirmation prompt and trigger execution through the `find` command.

Even if your system “asks the user first”, treat this as a reminder that **prompt gates are not a security boundary** unless the tool interface is strictly structured/validated and the executor is sandboxed.

**Core anti-pattern:**
- string interpolation into a shell command
- `shell=True`
- passing LLM-controlled strings into “safe” tools without a human confirmation boundary

## Defensive guidance (durable)
### 1) Never concatenate command strings with untrusted input
- Prefer `subprocess.run(["find", file_path, ...], shell=False, check=True)`
- Use strict typing: pass structured arguments, not free-form strings.

### 2) Design tools with *allowlisted* parameters
Instead of an `args: str` escape hatch, expose:
- `max_depth: int`
- `name_glob: str` (validated)
- `file_type: enum {"f","d"}`
- `case_insensitive: bool`

Reject anything else.

### 3) If you must accept “extra args”, parse and validate
- Parse with a real argument parser (not `split()`)
- Allowlist safe flags only
- Explicitly **block dangerous flags** and metacharacters:
  - `-exec`, `-ok`, `-delete`, `-printf` (context-dependent), `--checkpoint-action` (tar), etc.
  - `; | & $ ( ) < > \n` and backticks

### 4) Run tools in a sandbox with least privilege
- No secrets in environment by default
- No SSH keys, cloud creds, or CI tokens unless required
- Read-only filesystem when possible
- Network egress restrictions for tools that don’t need the internet

### 5) Treat retrieved content as untrusted
Assume any content fetched from the web or repos can contain attacker instructions.
- Separate **instruction** channels from **data** channels
- Require explicit policy checks / approvals before executing tools
- Log tool invocations with parameters for audit and incident response

## Quick checklist
- [ ] `shell=True` is forbidden in tool implementations
- [ ] Tools accept structured, validated inputs (no “args string”)
- [ ] Dangerous flags and metacharacters are blocked
- [ ] Tool execution is sandboxed and least-privileged
- [ ] Human approval boundary exists for risky actions

## References
- GitHub Advisory (CAI framework, `find` argument injection): https://github.com/advisories/GHSA-jfpc-wj3m-qw2m
- GitHub Advisory (Claude Code, `find` command injection / approval bypass): https://github.com/advisories/GHSA-qgqw-h4xq-7w8w
