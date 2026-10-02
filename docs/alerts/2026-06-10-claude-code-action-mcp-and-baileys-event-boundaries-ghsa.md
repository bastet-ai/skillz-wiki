# Claude Code Action MCP and Baileys event-boundary checks

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-8q5r-mmjf-575q](https://github.com/advisories/GHSA-8q5r-mmjf-575q) / CVE-2026-47751 for Claude Code Action project MCP server execution from pull-request-controlled `.mcp.json`, and [GHSA-qvv5-jq5g-4cgg](https://github.com/advisories/GHSA-qvv5-jq5g-4cgg) / CVE-2026-48063 for Baileys `protocolMessage` payloads that can spoof `messages.upsert` and history-sync state. June 25 Claude Code local temp-file update: [GHSA-4vp2-6q8c-pvq2](https://github.com/advisories/GHSA-4vp2-6q8c-pvq2) / CVE-2026-46406.

This batch is durable for operators because the advisories expose reusable boundaries: **untrusted collaboration input being replayed as trusted automation state** and **agent output being written through predictable local filesystem paths**.

- In CI agent workflows, a pull request can change project-local agent/tool configuration before a privileged action reads it.
- In messaging bots, remote protocol messages can be promoted into application events without strong origin, key, and state validation.
- In shared developer workstations or multi-user jump hosts, agent CLI helper commands can write responses to predictable temporary files that another local user can read or pre-seed with symlinks.

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

## Claude Code `/copy` predictable temporary file

The Claude Code `/copy` advisory describes a local boundary: affected `@anthropic-ai/claude-code` versions wrote copied responses to the predictable path `/tmp/claude/response.md`, used a world-traversable directory, created world-readable files, and did not protect against symlink pre-creation. A local unprivileged user on the same machine could read a privileged user's copied response or cause the response text to overwrite an attacker-chosen symlink target.

This is useful to operators who review AI-assisted developer environments, bastion hosts, training labs, shared CI workers, and remote desktop boxes: **agent output files may contain credentials, prompts, private code snippets, bug-bounty targets, or triage notes even when the agent process itself is not network-exposed**.

### What to map

1. Identify shared hosts where multiple Unix users can run agent CLIs or where privileged users run agents after `sudo`, SSH, VDI, or pair-programming handoff.
2. Record affected `@anthropic-ai/claude-code` versions before `2.1.128` and whether auto-update is disabled.
3. Inventory helper commands that export responses, transcripts, diffs, artifacts, or clipboard buffers to `/tmp`, workspace temp directories, or fixed filenames.
4. Check path ownership, directory mode, file mode, symlink handling, and whether output contains sensitive prompt/response material.
5. Treat the finding as local privilege/cross-user disclosure unless the environment gives the local attacker a stronger primitive through writable symlink targets.

### Authorized validation boundary

Use a lab host with two disposable Unix users. Do not read another person's real prompts or responses.

Safe proof shape:

1. As the low-privileged test user, watch only the known canary path and pre-create harmless symlink targets under a disposable directory you own.
2. As the privileged test user, run Claude Code with a synthetic prompt such as `skillz-copy-canary` and invoke `/copy`.
3. Confirm whether `/tmp/claude/response.md` is world-readable or whether the symlink target receives only the synthetic response text.
4. Capture redacted evidence: package version, host sharing model, path modes, UID/GID ownership, marker content, and fixed-version negative control.
5. Do not use `/etc/passwd`, shell startup files, credentials, customer workspaces, real reports, or production shared hosts as overwrite targets.

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
- For local agent temp-file findings, include package version, host user-sharing model, fixed path, mode/ownership, symlink behavior, and synthetic marker-only response evidence.
- For messaging-event findings, include library version, affected callback, claimed sender/key fields, downstream sink, and a canary-only demonstration of spoofed event acceptance.
- Keep secrets out of evidence. A marker proves execution or event trust without exposing credentials.
- Tie severity to privilege crossing: PR author to privileged runner for Claude Code Action, or remote message sender to trusted application state for Baileys.

## July 24 Claude Code worktree path-confusion follow-up

[GHSA-7835-87q9-rgvv](https://github.com/advisories/GHSA-7835-87q9-rgvv) adds a repository-to-sandbox boundary for `@anthropic-ai/claude-code >= 2.1.38, < 2.1.163`. A malicious repository with prompt-injection content could steer worktree handling through a `.git`-named worktree, out-of-sandbox navigation, symlink manipulation, and Git filesystem-monitor execution. The reported chain could overwrite a home-directory startup file and later execute outside macOS seatbelt restrictions. Reliable exploitation requires the user to clone the repository and run Claude Code against it; package presence alone is not enough.

### Disposable worktree harness

1. Use a throwaway OS account, temporary `HOME`, local repository, and Claude Code with no credentials, plugins, MCP servers, network access, or valuable files.
2. Place synthetic marker files inside the expected sandbox/worktree root and a second marker target in the temporary home. Do not use `.zshenv`, shell profiles, Git global config, credentials, or the real home directory.
3. Instrument Git/worktree invocations and filesystem writes. Exercise normal worktree creation, a `.git`-named worktree request, an outside-root path, and a symlinked path using only inert repository content.
4. If fsmonitor reachability must be shown, configure a test-only helper that appends a fixed marker to a temp log. It must not invoke a shell payload, inspect environment variables, or access the network.
5. Record the requested path, canonical worktree/git-dir path, sandbox profile, helper decision, and marker writes. Repeat on 2.1.163 or later.

Report **repository/prompt-controlled worktree operation -> Git directory or canonical-path confusion -> filesystem/helper action escapes the intended sandbox context**. Stop at a disposable outside-root marker; do not overwrite a startup file or demonstrate persistence.

## September 4 Claude Code Studio unauthenticated OS command injection follow-up

[GHSA-79WM-X847-7CVG](https://github.com/advisories/GHSA-79wm-x847-7cvg) / CVE-2026-73222 (high, CVSS 8.8) is an **unauthenticated OS command injection (RCE) in the `claude-code-templates` npm package `<= 1.29.2`**, reachable through the Claude Code Studio server started with `--studio`. This is a different surface from the worktree/persistent-config findings above: it is not a repo-clone or sandbox-escape chain, it is the *local server* exposing an HTTP/template route that reaches shell execution with no authentication.

### What to map

1. Identify hosts running `claude-code-templates` (Claude Code Studio) at or below `1.29.2`, especially where the `--studio` server is bound beyond loopback or fronted by a proxy.
2. Inventory the Studio server's HTTP routes that accept a user-controlled field (template id, command, path, or payload) and trace which reach a shell/exec sink.
3. Confirm whether the route is authenticated: the reported path is unauthenticated, so the check is route-reachability + exec-sink, not a bypass of an existing authn layer.
4. Separate the command-injection sink from any template-rendering side effects; the durable primitive is the unauthenticated exec, not XSS.

### Authorized validation boundary

Use a disposable Studio server on a loopback-only, credential-free host with no real repo, credentials, or network access.

1. Start `--studio` on the vulnerable version behind a recorder that denies real shell execution.
2. Send a request to the unauthenticated route with an inert canary (a marker argument that the recorder logs, not a real payload).
3. Record the route, the accepted field, and whether the exec sink is reached with no credential. Prove with the marker only.
4. Negative control: the fixed version and a request that is not the injection route.

Report as **unauthenticated Studio HTTP route -> user-controlled field -> OS command sink**, naming the exact route and field. Do not execute a real payload, read environment secrets, or target a shared/production Studio host.

- Include package version, the `--studio` binding, the route/field, and the inert canary evidence.
- Keep severity tied to the unauthenticated exec primitive; do not inflate a route-reachability check into a claim about internal-data access unless the sink independently reaches it.

## October 2 follow-up: MLS Welcome roster validation — signaling-path position joins the E2EE trust list (Discord libdave)

- **Discord libdave before 1.2.0** (CVE-2026-104480, [GHSA-3q99-x36r-rchh](https://github.com/advisories/GHSA-3q99-x36r-rchh), critical): the client **did not reject an MLS Welcome message when the resulting group roster contained an unrecognized participant**. An attacker controlling the DAVE signaling path — the voice gateway, or any position able to add/alter/withhold signaling messages to a client — gets the client to accept an unauthorized member into the end-to-end encrypted media session, breaking E2EE confidentiality/integrity of audio/video. Durable rules, same family as this page's Baileys axis (remote protocol input promoted into trusted state without origin validation): (1) **E2EE guarantees do not extend to the signaling path** — if group-formation/welcome processing trusts the relay to deliver rosters verbatim, the relay operator (or anyone who compromises/positions on it) is your adversary even when keys are fine; when assessing any MLS/DAVE/Signal-protocol deployment, treat signaling servers, gateways, and relays as attacker-influenced channels and ask what client-side invariant rejects a bad roster/welcome, not just what the server promises. (2) The check that would have caught it is a **membership-existence invariant** ("every participant in the derived roster resolves in the credential/KEM tree") — for protocol clients, fuzz the accept-path with well-formed messages whose embedded roster references *unknown* identities; "did the parser crash" batteries miss exactly this accept-what-you-can't-verify class. (3) Report shape: name the position required (signaling-path, not network-path), the missing client-side rejection, and stop at demonstrating roster acceptance with an identity you can prove is not a legitimate member — never join or decrypt real user sessions; lab-bounded with owned accounts in a group you control.
