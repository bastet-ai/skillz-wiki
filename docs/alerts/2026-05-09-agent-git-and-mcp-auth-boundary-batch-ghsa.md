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
