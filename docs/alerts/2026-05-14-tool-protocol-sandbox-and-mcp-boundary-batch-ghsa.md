# Tool protocol, sandbox, and MCP boundary batch

**Signal:** The **2026-05-14 21:15 UTC** advisory scan surfaced a tight cluster around agent/tool protocols: sandbox escapes, CLI argument substitution, environment leakage into subprocesses, OpenAPI-driven SSRF, MCP identity spoofing, and prototype pollution in deep object helpers.

## Advisory cluster

- **vm2 async-generator sandbox breakout** — [GHSA-248r-7h7q-cr24](https://github.com/advisories/GHSA-248r-7h7q-cr24): `vm2` allowed sandbox breakout through async-generator behavior. Treat any remaining `vm2` exposure as high-risk code execution, not just template evaluation.
- **`utcp-cli` argument-substitution command injection** — [GHSA-33p6-5jxp-p3x4](https://github.com/advisories/GHSA-33p6-5jxp-p3x4): UTCP CLI command templates could cross from protocol data into shell/argv execution when attacker-controlled arguments were substituted unsafely.
- **`python-utcp` subprocess environment leakage / command injection** — [GHSA-5v57-8rxj-3p2r](https://github.com/advisories/GHSA-5v57-8rxj-3p2r): CLI subprocess handling exposed the full process environment, turning tool invocation into secret disclosure when commands or arguments are attacker-influenced.
- **`@utcp/http` OpenAPI server URL SSRF** — [GHSA-r8j5-8747-88cm](https://github.com/advisories/GHSA-r8j5-8747-88cm): attacker-controlled `servers[0].url` entries in OpenAPI documents could steer the HTTP transport toward unintended networks.
- **`@samanhappy/mcphub` SSE username impersonation** — [GHSA-wf8q-wvv8-p8jf](https://github.com/advisories/GHSA-wf8q-wvv8-p8jf): an SSE endpoint accepted arbitrary usernames from the URL path without authentication, allowing identity spoofing at the MCP session boundary.
- **`@ranfdev/deepobj` prototype pollution** — [GHSA-x7q7-fchv-8h2j](https://github.com/advisories/GHSA-x7q7-fchv-8h2j): deep object mutation accepted prototype-modifying keys, letting untrusted data alter shared JavaScript object behavior.

## Why this matters

Agent and tool stacks often treat protocol descriptors as configuration, but they are attacker-controlled input whenever they come from a repository, remote OpenAPI document, chat/tool result, or user-provided MCP server. The dangerous boundary is not just “can this execute code?” It is also “can this choose argv, choose environment, choose identity, choose a URL, or modify object prototypes?”

## Triage

1. Remove or isolate `vm2` use. If it cannot be removed immediately, run it behind a separate OS process/container with no secrets, no write access, tight CPU/memory/time limits, and no ambient network.
2. For UTCP clients and servers, audit every place protocol data becomes argv, shell text, environment, OpenAPI server URL, or HTTP target. Prefer typed allowlists over template substitution.
3. Strip secrets from subprocess environments by default. Pass only the minimal variables required for the invoked tool, and log the resulting environment allowlist during tests.
4. Treat MCP usernames, session IDs, and tool-call principals as authenticated claims, never URL path metadata. Bind SSE/WebSocket sessions to an authenticated account or signed token.
5. Block `__proto__`, `prototype`, and `constructor` keys in merge/deep-set helpers, and add regression tests that assert prototype objects stay unchanged after parsing untrusted payloads.

## Durable controls

- Tool protocols need a schema-enforced boundary before execution: typed parameters in, constructed argv arrays out, no shell interpolation unless explicitly reviewed.
- Descriptor-driven URL fetches need SSRF controls after redirects and DNS resolution: private ranges, link-local, localhost, metadata IPs, and rebinding must be denied at connect time.
- Agent subprocesses should run with environment allowlists, disposable working directories, and redacted telemetry/log sinks.
- Identity in MCP/SSE/WebSocket flows must be derived from the authenticated transport, not from path, query, or client-supplied display names.
- JavaScript deep merge utilities are security-sensitive: prototype-pollution tests belong in CI for every parser/merge helper that handles user input.
