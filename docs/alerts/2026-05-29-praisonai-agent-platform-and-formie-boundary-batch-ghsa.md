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

## Notes on skipped items from this scan

- Bazaar `bzr+ssh` dash-prefixed hostname command execution was updated in GitHub Advisories but is an old 2017 issue; it remains useful supply-chain history, not fresh Skillz Wiki content.
- PraisonAI activity-log disclosure and several narrower dependency/label/member-management advisories were folded into the broader platform tenant-isolation/role-escalation workflow instead of each receiving a standalone page.
- Stigmem items updated around the same window were configuration-obvious, defensive-hardening, or already reviewed in the prior scan.
- CISA KEV stayed catalog `2026.05.29` with PAN-OS CVE-2026-0257 already reflected. PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits `/feed.xml`, and Disclosed had no separate promotable deltas in this pass.
