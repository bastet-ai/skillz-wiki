# VS Code Copilot `applyPatchTool` TOCTOU agent-boundary bypass

Source: Hacktron AI Research, published 2026-05-13: [RCE in VSCode Copilot Chat](https://www.hacktron.ai/blog/rce-in-vscode-copilot).

This is durable because it is not just a single product bug. It is a clean example of an agentic-tool boundary failure: the approval check reviewed the apparent patch source path, while the later tool execution honored a different move destination. Any AI coding agent that asks humans to approve high-level edits but then executes richer patch semantics can repeat this pattern.

## What changed

- **Issue text can become an agent instruction stream:** in the reported flow, a repository issue opened through “Code with Agent Mode” in a Codespace could cause Copilot to process attacker-controlled issue text as work instructions.
- **Confirmation covered the wrong object:** `applyPatchTool` reportedly collected paths from `Update File` / `Add File` directives for approval, but did not include the destination from `Move to` directives in the same patch.
- **Execution used the unchecked destination:** the patch application path honored the move destination and then wrote content there. A patch that looked like it updated harmless workspace files could land in sensitive destinations such as `.git/config` or `.vscode/settings.json`.
- **RCE followed from local trust hooks:** poisoning `.git/config` plus enabling Git autofetch can turn a later routine Git operation into command execution and token exposure.

## Operator triage

1. **Patch VS Code / Copilot tooling promptly.** Treat AI coding extensions as security-sensitive execution surfaces, not editor cosmetics.
2. **Disable or restrict issue-to-agent automation where possible.** Do not let public issue bodies, pull-request text, or dependency metadata drive agent mode without a human review step that treats the text as untrusted.
3. **Protect repository control files.** Monitor and gate writes to `.git/config`, `.vscode/settings.json`, shell startup files, CI config, package manager hooks, and editor/task definitions.
4. **Constrain Codespace and developer tokens.** Use least-privilege GitHub tokens, short lifetimes, environment-specific scopes, and secret-scanning on outbound logs/webhooks.
5. **Hunt for suspicious config changes.** Review recent commits, local working trees, Codespace histories, and endpoint telemetry for unexpected `core.sshCommand`, `credential.helper`, `git.autofetch`, task, shell, or hook changes.

## Replayable validation boundaries

- **Patch-move approval test:** in a disposable workspace, submit a patch whose source file is benign but whose move destination is a protected path; expected result is explicit approval naming the final destination or hard rejection.
- **Sensitive-path write test:** attempt agent writes to `.git/config`, `.vscode/settings.json`, `.env`, shell startup files, CI definitions, and package lifecycle scripts; expected result is block-by-default or a clear high-risk confirmation.
- **Untrusted issue simulation:** create a lab issue containing tool-invocation instructions and open it through any agent-mode workflow; expected result is summarization or safe planning, not direct tool execution.
- **Git operation canary:** audit whether editor settings can silently trigger Git network operations after agent edits; expected result is user-visible consent and no execution of attacker-controlled Git configuration.

## Durable controls

- Authorize the exact effect, not the parser’s first impression. Approval UIs must include resolved final paths, symlink/junction resolution, move destinations, generated files, and follow-on operations.
- Treat patch formats as executable languages. Parse once into a normalized AST, run policy on that AST, and execute only the same approved AST.
- Put protected-path policies below the agent layer, close to filesystem and workspace-edit primitives, so a missed caller-side check does not become RCE.
- Separate untrusted planning context from executable tool input. Public issues and PR text should not be able to smuggle raw patch/tool syntax into privileged developer environments.
