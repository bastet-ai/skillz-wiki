# PraisonAI agent/platform control boundaries and Formie submission overwrite batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-vg22-4gmj-prxw](https://github.com/advisories/GHSA-vg22-4gmj-prxw) / CVE-2026-47391, [GHSA-4mr5-g6f9-cfrh](https://github.com/advisories/GHSA-4mr5-g6f9-cfrh) / CVE-2026-47392, [GHSA-8444-4fhq-fxpq](https://github.com/advisories/GHSA-8444-4fhq-fxpq) / CVE-2026-47393, [GHSA-9cr9-25q5-8prj](https://github.com/advisories/GHSA-9cr9-25q5-8prj) / CVE-2026-47394, [GHSA-5cxw-77wg-jrf3](https://github.com/advisories/GHSA-5cxw-77wg-jrf3) / CVE-2026-47395, [GHSA-86qc-r5v2-v6x6](https://github.com/advisories/GHSA-86qc-r5v2-v6x6) / CVE-2026-47396, [GHSA-hvhp-v2gc-268q](https://github.com/advisories/GHSA-hvhp-v2gc-268q) / CVE-2026-47397, [GHSA-78r8-wwqv-r299](https://github.com/advisories/GHSA-78r8-wwqv-r299) / CVE-2026-47398, [GHSA-5c6w-wwfq-7qqm](https://github.com/advisories/GHSA-5c6w-wwfq-7qqm) / CVE-2026-47390, [GHSA-3qg8-5g3r-79v5](https://github.com/advisories/GHSA-3qg8-5g3r-79v5) / CVE-2026-47410, [GHSA-h8q5-cp56-rr65](https://github.com/advisories/GHSA-h8q5-cp56-rr65) / CVE-2026-47407, [GHSA-6h6v-6m7w-7vxx](https://github.com/advisories/GHSA-6h6v-6m7w-7vxx) / CVE-2026-47399, [GHSA-gv23-xrm3-8c62](https://github.com/advisories/GHSA-gv23-xrm3-8c62) / CVE-2026-48169, [GHSA-h37g-4h4p-9x97](https://github.com/advisories/GHSA-h37g-4h4p-9x97) / CVE-2026-47405, [GHSA-w388-2392-px73](https://github.com/advisories/GHSA-w388-2392-px73) / CVE-2026-47409, [GHSA-c2m8-4gcg-v22g](https://github.com/advisories/GHSA-c2m8-4gcg-v22g) / CVE-2026-47416, [GHSA-4x6r-9v57-3gqw](https://github.com/advisories/GHSA-4x6r-9v57-3gqw) / CVE-2026-47406, [GHSA-5jx9-w35f-vp65](https://github.com/advisories/GHSA-5jx9-w35f-vp65) / CVE-2026-47414, and [GHSA-pgxq-p76c-x9cg](https://github.com/advisories/GHSA-pgxq-p76c-x9cg) / CVE-2026-47266.

This batch is durable because it captures reusable offensive validation patterns for agent stacks: public unauthenticated agent control planes, LLM-driven tool invocation into unsafe sinks, prompt/mention SSRF, MCP file-read boundaries, sandbox escape regression checks, untrusted project/module execution, workspace-scope IDOR, role escalation, hardcoded development secrets, and unauthenticated form-submission overwrite.

## What changed

- **PraisonAI A2A example tool execution** — the first-party unauthenticated A2A example binds to `0.0.0.0`, accepts `/a2a` `message/send`, and registers an unsafe `calculate` tool implemented with Python `eval()`.
- **PraisonAI Python sandbox escape** — `execute_code()` subprocess mode missed `print.__self__` and `vars()` paths that can recover the real builtins module despite earlier sandbox patches.
- **PraisonAI generated API server auth-disabled default** — `praisonai deploy --type api` can emit a Flask `/chat` and `/agents` server where `auth_enabled` defaults to false while user workflows may bind externally.
- **PraisonAI call server fail-open auth** — `CALL_SERVER_TOKEN` unset makes the agent invocation router return successfully from its auth dependency, exposing agent listing, metadata, invocation, and deletion.
- **PraisonAI MCP file-read residuals** — the prior rules-path fix missed `workflow.show`, `workflow.validate`, and `deploy.validate`, leaving unauthenticated MCP `tools/call` paths that read arbitrary host files or leak fragments through parser errors.
- **PraisonAI SSRF and file-write agent boundaries** — `@url:` prompt mentions and spider tools can fetch loopback/private-like URLs through weak normalization, while web-crawled hidden metadata can steer `write_file` when production passes `workspace=None`.
- **PraisonAI untrusted module execution** — YAML-controlled `module_path` values in `agents_generator.py` still reach unguarded `spec.loader.exec_module()` sinks, bypassing earlier local-tool gates.
- **PraisonAI Platform tenant isolation failures** — workspace routes check membership on the URL workspace but fetch inner resources by global ID; member-management routes only require ordinary membership; several advisories also cover hardcoded `dev-secret-change-me` JWT defaults, role-promotion, member removal, dependency/label IDOR, and activity-log disclosure.
- **Formie front-end submission overwrite** — unauthenticated users can post a known or guessed submission ID to the front-end save action and overwrite existing Craft CMS Formie submissions.

## Operator triage

1. **Separate example risk from deployed pattern risk:** the A2A `eval()` issue is strongest where teams copied the official unauthenticated example or exposed an A2A service with comparable unsafe local tools.
2. **Map every agent-facing network listener:** check A2A, generated Flask API, call server, MCP server, and platform API separately; each has a distinct auth/default boundary.
3. **Treat prompt preprocessing as fetch-capable input:** `@url:` and crawler-derived content are pre-tool trust boundaries, not harmless context decoration.
4. **Bind workspace ID to object ID:** PraisonAI Platform findings are a clean test case for cross-tenant object substitution in routes that appear workspace-scoped.
5. **Use canaries, not secrets:** validate file reads/writes, SSRF, and code execution with synthetic files, callback endpoints, marker values, and disposable workspaces only.
6. **For Formie, require owner-approved test records:** submission overwrite validation should use a known lab submission ID, never guessed production records.

## Replayable validation boundaries

### PraisonAI exposed agent service checks

- Inventory reachable PraisonAI listeners and record component, bind address, version, and authentication state.
- For A2A, use a lab server copied from the affected example and a harmless calculation/canary tool. Prove that unauthenticated `message/send` can reach tool invocation without running OS-impacting commands.
- For generated Flask API, run `deploy --type api` in a disposable project and confirm whether `/chat` and `/agents` accept requests without an auth header under default config.
- For the call server, start a lab instance with `CALL_SERVER_TOKEN` unset and verify unauthenticated agent listing/invocation against a benign echo agent; repeat with a token set to show the missing-token default is the boundary.

### PraisonAI MCP and local filesystem checks

- Use a disposable MCP server process under a test Unix user.
- Create a canary file outside the expected workflow directory, then call `workflow.show`, `workflow.validate`, or `deploy.validate` with that path.
- Capture whether the response returns full content, file-existence evidence, or parser-error fragments.
- Avoid targeting real keys, `.env` files, cloud credentials, or system secrets; the report should show the path-containment gap without collecting sensitive data.

### PraisonAI prompt fetch, crawler, and write-file checks

- For `@url:`, run the CLI with a tester-controlled loopback HTTP service that returns a synthetic marker and confirm it is prepended to model context.
- Repeat with alternate loopback spellings only in a lab to show URL-normalization drift.
- For crawler-to-write-file, host a page containing benign hidden metadata that requests a temp-directory canary write. Verify that production `workspace=None` skips containment and writes only the marker file.
- Record the exact prompt/crawler path that introduced the attacker-controlled metadata; this distinguishes model behavior from tool-boundary failure.

### PraisonAI sandbox and module-loading checks

- For `execute_code()`, validate in an isolated container with no secrets mounted. Use a marker-only proof such as reading an environment variable set solely for the test or writing a temp canary.
- Confirm the bypass survives the target version's existing blocked-attribute patches before claiming regression impact.
- For `agents_generator.py`, supply a YAML `module_path` to a benign local module that only emits a marker, then show it executes without `PRAISONAI_ALLOW_LOCAL_TOOLS` or equivalent approval.

### PraisonAI Platform workspace isolation checks

- Create two disposable workspaces and two low-privileged users.
- In workspace A, make the caller a normal member. In workspace B, create synthetic agents, projects, issues, labels, comments, and dependencies.
- Send requests under `/api/v1/workspaces/{workspace_A}/...` while substituting object IDs from workspace B; stop at read-only proof where possible, or mutate only synthetic records.
- Test member-management actions from a normal member account: self-promotion, adding an owner/admin, role changes, and member removal. Restore all lab memberships afterward.
- If `PLATFORM_ENV` is unset, verify whether JWTs signed with the documented development secret are accepted against a lab account; do not forge real-user tokens.

### Formie submission overwrite check

- In a lab Craft CMS/Formie instance or explicitly authorized staging form, create a harmless submission and record its ID.
- Submit to `actions/formie/submissions/save-submission` or the equivalent front-end action without authentication, using only the lab submission ID.
- Prove that fields are overwritten or rejected based on the patched/unpatched version. Avoid guessing or enumerating production IDs.

## Reporting heuristics

- For PraisonAI, report by boundary rather than dumping all CVEs together: exposed service auth, prompt/URL fetch, MCP file access, sandbox escape, untrusted module loading, and platform tenant isolation.
- Include the exact role used, environment variables set or unset, bind address, route, and whether the test came from a documented quickstart/example.
- For tenant IDOR, always include both IDs: the workspace authorized by the route prefix and the object whose owning workspace differed.
- For sandbox/module execution, keep evidence to marker-only execution and name the missing validation primitive (`__self__`, `vars`, unguarded `exec_module`, or missing local-tool gate).
- For Formie, include whether front-end editing is enabled, the affected Formie major version, and the unauthorized submission ID overwrite path.

## August 25 follow-up: PraisonAI SSRF/origin/auth fail-open wave, mcp-shell allowlist bypasses, and Chainlit MCP stdio command injection

A second, larger PraisonAI wave plus two adjacent agent-runtime/MCP families landed on 2026-08-25. They reinforce the same boundary classes as this page but add three new, durable patterns: **SSRF patch-bypass via redirect/DNS-rebinding**, **origin/auth allowlist fail-open**, and **MCP command-tool allowlist bypass**.

### PraisonAI / praisonaiagents (19 GHSAs, published 2026-08-25)

- **SSRF protection is validated-once-then-fetched — bypass it two ways.** `web_crawl` (and the Jobs `webhook_url` validator) resolves the host *once*, blocks private/loopback literals, then fetches with `httpx.Client(follow_redirects=True)` (or a fresh `httpx.AsyncClient` for webhooks) with **no re-validation of the redirect target**. Two independent bypasses: (a) a public URL that `302`-redirects to `169.254.169.254` / `127.0.0.1`, and (b) **DNS rebinding** (TTL=1s host that resolves public at validation, private at fetch). `spider_tools._host_is_blocked()` is worse — it never does DNS resolution at all, so `127.0.0.1.nip.io` reaches loopback directly. The `except socket.gaierror: pass` in the webhook validator is a **fail-open on DNS error** plus a validate-then-fetch TOCTOU. See [GHSA-5r34-2g38-6569](https://github.com/advisories/GHSA-5r34-2g38-6569), [GHSA-8hjw-25cg-g52h](https://github.com/advisories/GHSA-8hjw-25cg-g52h), [GHSA-vg6p-v9vm-6fgj](https://github.com/advisories/GHSA-vg6p-v9vm-6fgj), [GHSA-x44h-65qv-cw74](https://github.com/advisories/GHSA-x44h-65qv-cw74), [GHSA-rg5q-pp8p-f7jm](https://github.com/advisories/GHSA-rg5q-pp8p-f7jm), [GHSA-hmfx-4v44-9qw9](https://github.com/advisories/GHSA-hmfx-4v44-9qw9).
- **Origin allowlists that use `startswith` or unanchored regex are bypassable.** `http://localhost.evil.example` passes a `startswith("http://localhost")` origin check; the WebSocket Chrome-extension origin regex `re.match(r"chrome-extension://[a-z0-9]{32}")` is unanchored at the end, so any longer origin passes. Both enable browser-mediated unauthenticated MCP `tools/call` / WebSocket `start_session` against a local agent runtime. See [GHSA-pvph-5j39-v8qc](https://github.com/advisories/GHSA-pvph-5j39-v8qc), [GHSA-wj6g-v78p-6fx3](https://github.com/advisories/GHSA-wj6g-v78p-6fx3), [GHSA-6g6r-q6gw-w8fg](https://github.com/advisories/GHSA-6g6r-q6gw-w8fg).
- **Auth fail-open and ignored `--api-key`.** `praisonai serve` / `serve agents` parse `--api-key` but never wire it into the FastAPI app, so `POST /agents` runs unauthenticated even with a key set. The Recipe server fail-opens when `auth: api-key|jwt` is set but no secret exists (`if not expected_key: return await call_next(request)`). The async Jobs API (`/api/v1/runs`) ships with no auth at all. See [GHSA-pvxx-r596-f5qj](https://github.com/advisories/GHSA-pvxx-r596-f5qj), [GHSA-7ww9-85pg-cv4x](https://github.com/advisories/GHSA-7ww9-85pg-cv4x), [GHSA-r7v3-x45f-g7hp](https://github.com/advisories/GHSA-r7v3-x45f-g7hp), [GHSA-gfq8-hmph-9gjv](https://github.com/advisories/GHSA-gfq8-hmph-9gjv), [GHSA-2jgc-f764-c5r2](https://github.com/advisories/GHSA-2jgc-f764-c5r2).
- **Workspace containment that keys on `abspath` not `realpath`.** `praisonai.code` tools call `is_path_within_directory()` with `os.path.abspath()`, so a symlink *inside* the workspace whose target is *outside* passes the check while `open()` follows it; `list_files()` never calls the containment helper at all. `FileMemory.__init__` builds paths from an unsanitized `user_id`, enabling `../` file writes. `ast_grep_rewrite` rewrites arbitrary files without the `@require_approval` gate every sibling mutation tool has. See [GHSA-ch89-h4r2-c8f8](https://github.com/advisories/GHSA-ch89-h4r2-c8f8), [GHSA-gxmw-5f7x-6g22](https://github.com/advisories/GHSA-gxmw-5f7x-6g22), [GHSA-cfxv-8fw8-rwpv](https://github.com/advisories/GHSA-cfxv-8fw8-rwpv).
- **Workflow include executes an included recipe's `tools.py` module-level code** even when the documented autoload opt-in is unset, reachable through `praisonai.recipe.run()` without a network service. See [GHSA-hxmv-c4g6-5fqc](https://github.com/advisories/GHSA-hxmv-c4g6-5fqc).
- Unauthenticated unbounded MCP session accumulation (DoS) via `initialize` with no TTL enforcement. See [GHSA-wv94-5qcp-6m36](https://github.com/advisories/GHSA-wv94-5qcp-6m36).

### mcp-shell allowlist bypasses (3 GHSAs)

`mcp-shell` "secure mode" restricts `shell_exec` to an allowlist, but the default config and validator are bypassable:

- **Git shell-alias injection.** The metacharacter blocklist omits `!`, so `/usr/bin/git -c alias.pwn=!<cmd>` runs arbitrary OS commands as the process user. Default Docker image runs as `mcpuser` (UID 1000) with Git installed and secure mode on — exploitable out of the box. See [GHSA-74hp-mggr-hv58](https://github.com/advisories/GHSA-74hp-mggr-hv58).
- **Default `/bin/bash` in the allowlist.** The validator only checks the *first token*, so `/bin/bash -c <cmd>` runs anything in the container. See [GHSA-3x77-wg38-92r3](https://github.com/advisories/GHSA-3x77-wg38-92r3).
- **Security disabled by default** in the bare-binary deploy path (`Security.Enabled: false` unless `MCP_SHELL_SEC_CONFIG_FILE` is set). See [GHSA-f5pj-2738-996m](https://github.com/advisories/GHSA-f5pj-2738-996m).

### Chainlit MCP stdio command injection (CVE-2026-45018)

With `features.mcp.enabled = true` (MCP is disabled by default since v2.7.0), `POST /mcp` for `stdio` transport accepts a user-controlled `fullCommand`. `validate_mcp_command()` checks only the executable name against an allowlist and does not restrict arguments, so `npx -y -c '<arbitrary command>'` executes arbitrary shell commands as the Chainlit process, unauthenticated. Patched in 2.12.0. See [GHSA-w3fx-mc44-mf6j](https://github.com/advisories/GHSA-w3fx-mc44-mf6j). The durable pattern: **an allowlist that validates the command token but not its arguments/flags** is not a command-execution boundary.

### Operator triage for the August 25 wave

1. **Treat every "validate the URL/origin/auth then use it" sink as two separate checks.** Redirect-following and DNS re-resolution invalidate a one-time host check. Probe with an owned no-content peer that 302-redirects to loopback/metadata and with a TTL=1 rebind host; stop at the callback/marker, never at real internal data.
2. **Search allowlists for `startswith`, unanchored `re.match`, and "first-token-only" logic.** Origin/host/executable allowlists that compare prefixes or only the argv[0] are the bypass class.
3. **Assume `--api-key`/`auth` flags may be no-ops.** Confirm the flag is actually read by the middleware, not just parsed by the CLI.
4. **For workspace containment, key on `realpath`/`resolve`, not `abspath`.** Symlinks and `../` are the two escapes; check that *every* sibling tool (not just the patched one) enforces the boundary and the approval gate.
5. **For MCP command tools, prove the argument boundary.** Show an allowlisted executable whose `-c`/`alias.!`/`-y -c` flag reaches arbitrary execution; keep the marker inert (`id`/`pwd`/marker file) and lab-only.

## Notes on skipped items from this scan

- Bazaar `bzr+ssh` dash-prefixed hostname command execution was updated in GitHub Advisories but is an old 2017 issue; it remains useful supply-chain history, not fresh Skillz Wiki content.
- PraisonAI activity-log disclosure and several narrower dependency/label/member-management advisories were folded into the broader platform tenant-isolation/role-escalation workflow instead of each receiving a standalone page.
- Stigmem items updated around the same window were configuration-obvious, defensive-hardening, or already reviewed in the prior scan.
- CISA KEV stayed catalog `2026.05.29` with PAN-OS CVE-2026-0257 already reflected. PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits `/feed.xml`, and Disclosed had no separate promotable deltas in this pass.

## October 7 follow-up: AgentMail webhook mode accepts forged unsigned `message.received` events — attacker-chosen sender invokes the agent (CVE-2026-61428 + CVE-2026-61436 / [GHSA-qj9c-59p6-8cgx](https://github.com/advisories/GHSA-qj9c-59p6-8cgx), [GHSA-7c92-x8vg-4258](https://github.com/advisories/GHSA-7c92-x8vg-4258), high)

PraisonAI's AgentMail **webhook mode** (`AgentMailBot(mode="webhook")` / `BotConfig.mode=webhook`) binds an aiohttp receiver to `0.0.0.0` and `_handle_email_webhook()` trusts the parsed JSON body directly: it reads `body["type"] == "message.received"`, schedules `_process_webhook_payload()`, and returns 200 — with **zero verification of the `svix-id` / `svix-timestamp` / `svix-signature` headers AgentMail documents**, and the secret returned by `webhooks.create()` is never even stored. The forged payload builds a `BotMessage` from attacker-controlled `data.from`, `data.subject`, `data.extracted_text`, `data.thread_id`, and dispatches it through `_handle_message()` — firing message hooks, running the configured agent session with the injected text, and replying to the attacker-chosen sender address.

Durable axes for agent/email-gateway platforms:

1. **Alternate ingress mode = alternate authz surface — the signature only ever lives on the provider path.** PraisonAI's polling and WebSocket paths receive SDK-typed, provider-verified events; only the webhook receiver parses raw JSON. Same product, same handler, three transports, one unauthenticated door. Audit rule for any bot/agent platform with a `mode=` switch: test *every* mode's ingress independently with a forged event; the default mode's auth guarantee does not transfer. (Sibling of this wiki's REST-vs-MCP entry-point parity rule.)
2. **The handler's own accepted field names fingerprint the forgery.** The provider's *verified* payload uses `event_type`; PraisonAI's handler accepts `type` + `data`. When probing any webhook receiver for signature-skip, don't copy the provider's documented schema — grep the handler (or fuzz both shapes) for the field names *it* reads. An endpoint returning 200 to a wrong-shape-but-handler-correct body while the provider's own test ping gets ignored is the tell.
3. **Sender-spoofed agent invocation is a prompt-injection trigger leg with a reply channel.** Forged `data.from` + injected `extracted_text` = attacker picks both the prompt and, via hooks/tools, potentially an outbound channel. Frame findings as *unauthenticated → agent tool invocation*, not just "missing signature": prove in a lab bot with an inert tool (echo/marker), check whether tools/approval gates fire, and whether the auto-reply path sends agent output back to the spoofed address. Never drive a production email agent; owned test inboxes only.
4. Deploy fingerprint: webhook mode is opt-in (`mode=webhook`, binds a configured port on all interfaces) — externally, an open port that answers `POST <configured webhook path>` with 200 to `{"type":"message.received","data":{}}` while never requiring `svix-signature` is the test. GitHub's July 2026 advisories GHSA-4mp6-8448-9vgv / GHSA-m64w-vfg6-36ph were withdrawn as duplicates of these — same advisory, do not double-report.
