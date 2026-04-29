# Claude SDK local filesystem memory tool creates overly permissive files (GHSA-p7fg-763f-g4gf / CVE-2026-41686)

**Signal:** GitHub Security Advisories published **2026-04-29**. The Anthropic TypeScript SDK fixed insecure default modes in the beta local filesystem memory tool.

## What it is
`BetaLocalFilesystemMemoryTool` created memory files with Node's default `0o666` mode and directories with `0o777`. With a normal umask this can make agent memory world-readable; with permissive container umasks it can become world-writable. Local users or co-resident container processes may read persisted agent state or tamper with memory used in later model runs.

Affected package: npm `@anthropic-ai/sdk` `>= 0.79.0, < 0.91.1`. Fixed version: `0.91.1`.

Reference: <https://github.com/advisories/GHSA-p7fg-763f-g4gf>

## Triage
1. Inventory apps using `BetaLocalFilesystemMemoryTool` or local agent memory with the Anthropic TypeScript SDK.
2. Locate memory directories and inspect ownership/modes from the account that runs the agent.
3. Treat stored prompts, retrieved context, tool outputs, and credentials embedded in memory as potentially exposed on shared hosts.

## Mitigation
- Upgrade `@anthropic-ai/sdk` to `0.91.1` or later.
- Set agent memory directories to `0700` and files to `0600`; enforce a restrictive process umask such as `077`.
- In containers, avoid world-writable volumes for memory and run agents as a dedicated non-root user.

## Detection ideas
- Scan for memory files not owned by the agent user or with group/other read or write bits.
- Review file mtimes and integrity of memory entries if the host or container may have been shared with less-trusted users.

## Durable lesson
Agent memory is sensitive state. Treat it like credentials: private by default, scoped to one principal, and never dependent on ambient umask behavior.
