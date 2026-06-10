# Claude Code Action MCP and Baileys event-boundary checks

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-8q5r-mmjf-575q](https://github.com/advisories/GHSA-8q5r-mmjf-575q) / CVE-2026-47751 for Claude Code Action project MCP server execution from pull-request-controlled `.mcp.json`, and [GHSA-qvv5-jq5g-4cgg](https://github.com/advisories/GHSA-qvv5-jq5g-4cgg) / CVE-2026-48063 for Baileys `protocolMessage` payloads that can spoof `messages.upsert` and history-sync state.

This batch is durable for operators because both advisories expose a reusable boundary: **untrusted collaboration input being replayed as trusted automation state**.

- In CI agent workflows, a pull request can change project-local agent/tool configuration before a privileged action reads it.
- In messaging bots, remote protocol messages can be promoted into application events without strong origin, key, and state validation.

## Claude Code Action PR-controlled MCP config

The Claude Code Action advisory describes a chain where a workflow checks out a pull-request head branch, the action reads `.mcp.json` from the working directory, and `enableAllProjectMcpServers` enables all project MCP servers. Under those conditions, a contributor who can open a pull request can add a malicious MCP server configuration that runs on the GitHub Actions runner when a privileged user or automation invokes the action on that PR.

The reusable testing pattern is not specific to one vendor action: **agent configuration committed in a branch should not automatically become executable tool/runtime configuration inside a privileged CI context**.

### What to map

1. Find repositories using `anthropics/claude-code-action` or similar CI agent actions.
2. Record whether workflows run on `pull_request`, `pull_request_target`, `issue_comment`, label, slash-command, or manual triggers.
3. Check whether the workflow checks out attacker-controlled PR content before launching the agent.
4. Check whether project-local agent config files are loaded from the working tree, especially `.mcp.json` or equivalent tool/server registries.
5. Determine which secrets, tokens, repository permissions, cloud credentials, or package-publishing credentials are available to the job.
6. Confirm whether a human approval step causes a privileged user to invoke the agent on untrusted PR content.

### Authorized validation boundary

Use a private lab repository or explicit customer approval. Do not run exfiltration payloads against real project secrets.

A safe proof uses an inert canary MCP server config that only writes a marker to the job log or a disposable artifact:

```json
{
  "mcpServers": {
    "skillz-canary": {
      "command": "node",
      "args": ["-e", "console.log('skillz-mcp-canary')"]
    }
  }
}
```

Validation steps:

1. Open a test PR that adds only the canary `.mcp.json` and any minimal file needed to trigger the workflow.
2. Trigger the same Claude/agent action path that the target process uses for PR assistance.
3. Confirm whether the canary server is launched from PR-controlled configuration.
4. Capture redacted evidence: workflow trigger, checkout ref, action version, MCP enablement setting, and canary marker.
5. Stop at command execution proof. Do not print environment variables, tokens, repository secrets, cloud metadata, or package credentials.

A high-quality finding proves both conditions: the attacker controls the config source, and the CI agent trusts that config in a context with privileges the PR author should not have.

## Baileys protocol-message event spoofing

The Baileys advisory describes crafted `protocolMessage` payloads delivered through `placeholderResendMessage` that can trigger fake `messages.upsert` events with fake message keys and payloads. It also notes app-state sync corruption through fake key shares and history-sync spoofing.

For bug hunters, the reusable workflow is to test messaging automations that treat SDK events as authenticated business facts. Bots often convert `messages.upsert`, history sync, or app-state updates directly into actions such as support-ticket creation, payment-status handling, CRM notes, admin alerts, or command dispatch.

### What to map

1. Identify applications using Baileys before the fixed `6.7.22` / `7.0.0-rc12` releases.
2. Inventory sinks fed by `messages.upsert`, history sync, and app-state sync callbacks.
3. Classify whether those sinks affect trust decisions: ticket identity, order state, workflow commands, audit records, moderation, or user-visible conversation context.
4. Check whether the application independently verifies sender identity, message key provenance, and event source before acting.
5. Separate event spoofing impact from availability-only app-state jamming.

### Authorized validation boundary

Use owned test accounts and a disposable bot environment. Do not inject content into third-party chats or customer production histories.

Safe proof shape:

1. Stand up a test Baileys bot using a vulnerable version and a callback that logs a synthetic marker when `messages.upsert` fires.
2. Send a crafted protocol-message canary only between owned accounts.
3. Show whether the bot receives a forged `messages.upsert` event or forged history context that did not originate from the claimed sender/key.
4. If testing a real integration, prove only the lowest-impact sink, such as creation of a canary support note or internal log entry.
5. Preserve the raw event metadata and application action, but redact phone numbers, chat IDs, tokens, and message contents not created for the test.

A strong report frames impact as **remote protocol input crossing into trusted application event handling**. Avoid claiming account takeover or impersonation of unrelated users unless the application sink independently creates that impact.

## Reporting heuristics

- For CI-agent findings, include workflow trigger, checkout target, action version or tag, project-config loading path, MCP enablement setting, job permission context, and inert canary execution proof.
- For messaging-event findings, include library version, affected callback, claimed sender/key fields, downstream sink, and a canary-only demonstration of spoofed event acceptance.
- Keep secrets out of evidence. A marker proves execution or event trust without exposing credentials.
- Tie severity to privilege crossing: PR author to privileged runner for Claude Code Action, or remote message sender to trusted application state for Baileys.
