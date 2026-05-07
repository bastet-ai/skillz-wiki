# Agent, Git, sandbox, and local-execution boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where local files, Git checkout behavior, sandbox filters, CLI arguments, and agent/tool boundaries crossed into code execution or secret exposure.

## Advisories covered

- **gix-fs symlink worktree escape** — [GHSA-f89h-2fjh-2r9q](https://github.com/advisories/GHSA-f89h-2fjh-2r9q): prefix reuse during checkout can follow symlinks outside the intended worktree.
- **Playwright Capture local-file/internal-network access** — [GHSA-687h-xw6f-q2qw](https://github.com/advisories/GHSA-687h-xw6f-q2qw): page capture tooling can become an SSRF/LFI bridge unless file and network capabilities are constrained.
- **mcp-server-semgrep command injection** — [GHSA-86hp-qxqp-w9wv](https://github.com/advisories/GHSA-86hp-qxqp-w9wv): tool arguments crossing into shell execution need structured argv and allowlists.
- **Lupa sandbox escape and RCE** — [GHSA-69v7-xpr6-6gjm](https://github.com/advisories/GHSA-69v7-xpr6-6gjm): incomplete `attribute_filter` enforcement across `getattr`/`setattr` can expose host capabilities.
- **Vercel CLI argument disclosure** — [GHSA-pgf8-2hgj-grqg](https://github.com/advisories/GHSA-pgf8-2hgj-grqg): non-interactive helper output can leak secrets passed on command lines.
- **OpenClaw host execution and environment boundary issues** — [GHSA-42mx-vp8m-j7qh](https://github.com/advisories/GHSA-42mx-vp8m-j7qh), [GHSA-3qpv-xf3v-mm45](https://github.com/advisories/GHSA-3qpv-xf3v-mm45), [GHSA-m866-6qv5-p2fg](https://github.com/advisories/GHSA-m866-6qv5-p2fg): sandbox mirror mode, workspace `.env`, and unblocked host env variables can convert untrusted project files into host hook execution.
- **Axonflow OpenClaw cache and credential-file hardening** — [GHSA-cqmh-pcgr-q42f](https://github.com/advisories/GHSA-cqmh-pcgr-q42f): plugin caches and credential files need strict ownership and permissions.

## Why this is durable

Agent and developer tools routinely cross from untrusted repository content into privileged host actions. The durable control is not “trust the workspace”; it is to keep checkout, capture, sandbox, CLI, and environment inputs from becoming executable host policy.

## Immediate triage

1. Patch affected Git, capture, MCP, sandbox, CLI, and OpenClaw components.
2. Rebuild any workspace that processed untrusted repositories with vulnerable checkout or mirror/hook behavior.
3. Search logs and shells for secrets supplied as CLI arguments; rotate any exposed tokens.
4. Deny `file://`, loopback, link-local, cloud metadata, and internal CIDR fetches in capture tools unless explicitly scoped.
5. Confirm host env allowlists block hook roots, Git templates, cloud config files, and package-manager config injection.

## Durable controls

- Use structured argv and no-shell execution for tool adapters; maintain positive command and flag allowlists.
- Resolve symlinks after every filesystem step and prove the final path remains inside the intended root.
- Run browser/capture and sandboxed language runtimes with network, filesystem, and process capabilities disabled by default.
- Keep project `.env`, hooks, templates, and package-manager config out of privileged host startup paths.
