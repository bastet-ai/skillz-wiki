# OpenClaw gateway, media, and filesystem boundary batch (GHSA)

**Signal:** GitHub Security Advisories Atom/REST surfaced a **2026-05-04** OpenClaw batch where gateway bootstrap, media delivery, filesystem bridges, connector configuration, MCP loopback ownership, ACP child sessions, outbound media fetches, and shell allowlist analysis all depended on final trust-boundary checks.

## Advisories in this batch

- **Gateway Control UI bootstrap config required Gateway auth** — `openclaw <= 2026.4.21` tightened bootstrap/config access so UI setup paths require authenticated Gateway context. References: <https://github.com/advisories/GHSA-93rg-2xm5-2p9v>.
- **OpenShell FS bridge read pinning** — `openclaw <= 2026.4.21` now pins and verifies opened files before bytes are returned, preventing path swaps after validation. References: <https://github.com/advisories/GHSA-5h3g-6xhh-rg6p>.
- **OpenShell FS bridge write pinning** — `openclaw <= 2026.4.21` keeps writes pinned to the sandbox mount root. References: <https://github.com/advisories/GHSA-wppj-c6mr-83jj>.
- **Assistant media trusted-proxy scope enforcement** — `openclaw < 2026.4.20` missed scope enforcement for a trusted-proxy media route; GHSA-qgx9-6px9-7p75 is a duplicate of GHSA-v8qf-fr4g-28p2. References: <https://github.com/advisories/GHSA-v8qf-fr4g-28p2>, <https://github.com/advisories/GHSA-qgx9-6px9-7p75>, CVE-2026-41908.
- **Exec allowlist heredoc analysis** — `openclaw <= 2026.4.21` rejects shell expansion in unquoted heredocs during exec allowlist analysis. References: <https://github.com/advisories/GHSA-x3h8-jrgh-p8jx>.
- **MCP loopback owner context** — `openclaw <= 2026.4.21` derives MCP loopback owner context from server-issued bearer tokens. References: <https://github.com/advisories/GHSA-r6xh-pqhr-v4xh>.
- **Workspace dotenv connector endpoint guard** — `openclaw <= 2026.4.21` prevents workspace dotenv files from overriding connector endpoint hosts. References: <https://github.com/advisories/GHSA-55cf-xx38-4p9p>.
- **ACP child session security envelope inheritance** — `openclaw <= 2026.4.21` ensures ACP children inherit subagent security envelope constraints. References: <https://github.com/advisories/GHSA-q3jj-46pq-826r>.
- **Zalo outbound photo URL SSRF guard** — `openclaw <= 2026.4.21` validates outbound Zalo photo URLs through the SSRF guard. References: <https://github.com/advisories/GHSA-2hh7-c75g-qj2r>.

## Why this is durable

Agent runtimes often validate an action early, then hand work to helpers that operate with stronger privileges or broader filesystem/network reach. The durable control is to repeat authority checks at the final sink: opened file descriptors, proxy media routes, connector endpoints, loopback requests, child-session envelopes, and outbound fetchers.

## Immediate triage

1. **Upgrade OpenClaw** to a release after the affected ranges, prioritizing any deployment that exposes Gateway UI, media routes, OpenShell, MCP loopback, ACP harnesses, or connector dotenv loading.
2. **Audit recent helper access:** media-route hits using trusted-proxy headers, OpenShell file reads/writes near symlinks or mount boundaries, MCP loopback requests, and ACP child-session launches.
3. **Review dotenv and connector overrides:** check workspaces for `.env` or generated dotenv content that attempts to change connector hosts or loopback URLs.
4. **Recheck allowlisted shell jobs:** search for unquoted heredocs in commands assumed to be blocked by allowlist analysis.
5. **Treat duplicate advisories as one control gap:** GHSA-qgx9-6px9-7p75 duplicates GHSA-v8qf-fr4g-28p2; track one remediation item but record both IDs for dependency scanners.

## Hunt ideas

- Look for media requests where proxy trust headers appear without a matching scoped session or channel authorization.
- Diff OpenShell read/write paths against resolved mount roots and inspect any symlink-heavy paths touched by automated agents.
- Grep workspace dotenv files for connector, webhook, proxy, base URL, loopback, or host override variables.
- Query MCP loopback logs for bearer-token mismatches, missing owner context, or requests from unexpected local processes.
- Review ACP child session metadata for missing inherited sandbox, policy, channel, or owner constraints.
- Search command history for `<<EOF`, `<<-EOF`, or unquoted heredocs inside supposedly constrained exec calls.

## Durable controls

- Bind every helper request to an explicit owner, scope, and policy envelope at execution time, not only at dispatch time.
- Resolve and pin filesystem objects with file descriptors before reading or writing; never rely only on string-path prechecks.
- Keep connector endpoints operator-owned; workspace files may configure workload behavior but must not redirect privileged connectors.
- Treat trusted-proxy and loopback headers as claims that require server-issued tokens or mTLS-backed identity.
- Parse shell constructs before allowlist decisions; heredocs, command substitution, globbing, and expansions are part of the command.

## Operator lesson

For agent infrastructure, ask “what privileged helper consumes this next?” If that helper can read files, fetch URLs, proxy media, mutate config, or spawn children, it needs its own final authorization guard.
