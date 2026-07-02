# OpenClaw approval/tooling and MCP memory document-boundary checks

Source: hourly offensive-security scan, 2026-07-02. Primary entries: GitHub Advisory Database [GHSA-hw9r-h9mr-4jff](https://github.com/advisories/GHSA-hw9r-h9mr-4jff), [GHSA-mhq8-78pj-5j79](https://github.com/advisories/GHSA-mhq8-78pj-5j79), [GHSA-mgq6-vr84-7m2j](https://github.com/advisories/GHSA-mgq6-vr84-7m2j), [GHSA-6fvr-66p3-3qj4](https://github.com/advisories/GHSA-6fvr-66p3-3qj4) / CVE-2026-53814, [GHSA-chr9-m4q2-76hw](https://github.com/advisories/GHSA-chr9-m4q2-76hw) / CVE-2026-53817, [GHSA-rggc-m335-3wvj](https://github.com/advisories/GHSA-rggc-m335-3wvj), [GHSA-v6r2-jh58-xx6w](https://github.com/advisories/GHSA-v6r2-jh58-xx6w) / CVE-2026-53810, [GHSA-2hfg-4fh4-qp7f](https://github.com/advisories/GHSA-2hfg-4fh4-qp7f) / CVE-2026-53812, [GHSA-2j8v-hwgc-x698](https://github.com/advisories/GHSA-2j8v-hwgc-x698), [GHSA-qh2f-99mv-mrcf](https://github.com/advisories/GHSA-qh2f-99mv-mrcf), [GHSA-xww8-gqvh-92x9](https://github.com/advisories/GHSA-xww8-gqvh-92x9), [GHSA-q7q8-3mgw-q67r](https://github.com/advisories/GHSA-q7q8-3mgw-q67r) / CVE-2026-53815, and [GHSA-84hp-mqvj-3p8h](https://github.com/advisories/GHSA-84hp-mqvj-3p8h) / CVE-2026-50027.

These advisories are durable for operators because they repeat the same agent-platform boundary failures across different surfaces: a displayed or scoped action diverges from the action that actually executes, channel/tool allowlists are not consistently applied to alternate routes, browser or hook automation crosses into private-network or owner-only authority, and memory/document APIs skip authentication on adjacent route families. Keep validation to owned labs, disposable profiles, fake memories, inert commands, canary channels, and synthetic node files only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-hw9r-h9mr-4jff](https://github.com/advisories/GHSA-hw9r-h9mr-4jff) | OpenClaw `chat.send` routed sessions | lower `operator.write` Gateway scope could reach commands intended for `operator.approvals` or `operator.admin` through inherited external routes | Check whether alternate delivery routes preserve command-family scope checks. |
| [GHSA-mhq8-78pj-5j79](https://github.com/advisories/GHSA-mhq8-78pj-5j79) | OpenClaw POSIX `system.run` safe-bin policy | approval/allowlist evaluated one shell-expanded shape while execution could treat expanded words as file operands | Validate command policies after shell expansion and argv finalization, not on presentation strings. |
| [GHSA-mgq6-vr84-7m2j](https://github.com/advisories/GHSA-mgq6-vr84-7m2j) | OpenClaw QQBot native approval buttons | button callback resolved approvals without enforcing the configured approver identity | Treat chat-native approval widgets as separate auth paths from text commands. |
| [GHSA-6fvr-66p3-3qj4](https://github.com/advisories/GHSA-6fvr-66p3-3qj4) / CVE-2026-53814 | OpenClaw hook-triggered CLI runs | hook-token automation could select a bundled CLI backend with owner-scoped MCP loopback authority | Test whether webhook/hook ingress can inherit owner-only MCP tools. |
| [GHSA-chr9-m4q2-76hw](https://github.com/advisories/GHSA-chr9-m4q2-76hw) / CVE-2026-53817 | OpenClaw Control UI pairing | spoofed locality signals could mint a durable admin-capable device token in LAN/shared-token deployments | Check whether temporary/local UI access can become persistent admin pairing. |
| [GHSA-rggc-m335-3wvj](https://github.com/advisories/GHSA-rggc-m335-3wvj) | OpenClaw trusted-proxy mode | same-host caller could supply identity headers normally reserved for the trusted proxy | Validate direct-to-backend reachability and proxy-only identity headers. |
| [GHSA-v6r2-jh58-xx6w](https://github.com/advisories/GHSA-v6r2-jh58-xx6w) / CVE-2026-53810 | OpenClaw marketplace runtime extensions | extension metadata could point runtime loading at unscanned package content | Review package metadata-to-runtime-code pivots, not only visible entry points. |
| [GHSA-2hfg-4fh4-qp7f](https://github.com/advisories/GHSA-2hfg-4fh4-qp7f) / CVE-2026-53812 | OpenClaw browser control | Playwright `act` interactions could navigate to private-network pages after the initial SSRF check | Browser-automation SSRF tests must include click/action-triggered navigation, not only direct `goto`. |
| [GHSA-2j8v-hwgc-x698](https://github.com/advisories/GHSA-2j8v-hwgc-x698) | OpenClaw shell wrapper execution | approved wrapper argv could be rebuilt differently at execution time | Bind approvals to immutable argv and environment evidence. |
| [GHSA-qh2f-99mv-mrcf](https://github.com/advisories/GHSA-qh2f-99mv-mrcf) | OpenClaw bundled MCP loopback | session-spawn path could miss the exec denylist intended for that MCP entry point | Compare every MCP transport and spawn path against the same denylist. |
| [GHSA-xww8-gqvh-92x9](https://github.com/advisories/GHSA-xww8-gqvh-92x9) | OpenClaw exec approval UI | truncation hid a suffix that remained part of the executed command | Capture full command evidence and reject approval UIs that do not faithfully render the executable payload. |
| [GHSA-q7q8-3mgw-q67r](https://github.com/advisories/GHSA-q7q8-3mgw-q67r) / CVE-2026-53815 | OpenClaw message read actions | message reads could skip normal channel allowlist checks | Test read-side APIs separately from delivery-side allowlists. |
| [GHSA-84hp-mqvj-3p8h](https://github.com/advisories/GHSA-84hp-mqvj-3p8h) / CVE-2026-50027 | `mcp-memory-service` `/api/documents/*` | document upload/search/delete routes lacked auth even when `/api/memories` enforced API-key or OAuth checks | Check adjacent MCP memory route families for inconsistent auth dependencies. |

### July 2 follow-up wave: identity, pairing, loopback, and workspace-state drift

Adjacent OpenClaw advisories published later on July 2 continue the same operator pattern: mutable chat metadata, stale chat tokens, provider aliases, package-root discovery, workspace `.env`, Control UI WebSockets, node lifecycle messages, browser tab reuse, and skill-workshop approval state can all become alternate authority paths. Treat these as follow-up checks on this page instead of separate alerts.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-7hxm-f538-3xp6](https://github.com/advisories/GHSA-7hxm-f538-3xp6) / CVE-2026-53811 and [GHSA-c29c-2q9c-pc86](https://github.com/advisories/GHSA-c29c-2q9c-pc86) | Matrix and Slack `allowFrom` | mutable display names could satisfy allowlist entries intended for stable user identities | Test chat allowlists with stable platform IDs, not display/profile names. |
| [GHSA-w4v6-g3wm-w36c](https://github.com/advisories/GHSA-w4v6-g3wm-w36c), [GHSA-77pv-3w4q-vrj5](https://github.com/advisories/GHSA-77pv-3w4q-vrj5), [GHSA-gp79-m99v-gjmh](https://github.com/advisories/GHSA-gp79-m99v-gjmh), [GHSA-jvm4-4j77-39p6](https://github.com/advisories/GHSA-jvm4-4j77-39p6), and [GHSA-3wqp-prf6-2m72](https://github.com/advisories/GHSA-3wqp-prf6-2m72) | QQBot, Mattermost, and Feishu command/binding handlers | pre-dispatch, missing channel metadata, wildcard, or dynamic-binding paths could skip `allowFrom`, DM-only, or config-write controls | Exercise every chat adapter's native/slash/streaming path separately from the canonical command path. |
| [GHSA-4m3v-q747-pc6h](https://github.com/advisories/GHSA-4m3v-q747-pc6h) and [GHSA-275c-xpvc-jgfw](https://github.com/advisories/GHSA-275c-xpvc-jgfw) | Mattermost slash tokens, Slack webhooks, and Zalo webhooks | revoked secrets could remain accepted until refresh/reload completed | Include token-revocation windows in chatops boundary tests, using fake tokens only. |
| [GHSA-xr4f-mjxj-w6w5](https://github.com/advisories/GHSA-xr4f-mjxj-w6w5), [GHSA-qjpc-qf9m-xwmr](https://github.com/advisories/GHSA-qjpc-qf9m-xwmr), [GHSA-83w9-h5wv-j9xm](https://github.com/advisories/GHSA-83w9-h5wv-j9xm), and [GHSA-3c6j-hq33-3jv4](https://github.com/advisories/GHSA-3c6j-hq33-3jv4) / CVE-2026-53816 | device pairing, Control UI, and paired node lifecycle events | non-owner chat senders, restricted trusted-proxy clients, reconnecting nodes, or crafted node events could gain or confuse operator/node authority | Validate pairing and node-event state transitions with disposable nodes and explicit scope decision tables. |
| [GHSA-rj6p-xmxr-qj4h](https://github.com/advisories/GHSA-rj6p-xmxr-qj4h) / CVE-2026-53818 and [GHSA-p39j-x9h5-q66m](https://github.com/advisories/GHSA-p39j-x9h5-q66m) / CVE-2026-53809 | MCP loopback and embedded runner provider policy | loopback callers or provider aliases could reach owner-only tools or bundled access outside the canonical policy path | Compare requested identity, canonical provider/tool identity, before-tool-call hooks, and final authority. |
| [GHSA-vxx3-6hc9-7cc3](https://github.com/advisories/GHSA-vxx3-6hc9-7cc3) / CVE-2026-53806 | POSIX shell option parsing | combined shell flags could differ between approval-time revalidation and execution | Re-run exec-policy tests against final parsed shell options, not only command strings. |
| [GHSA-v8cx-933x-r976](https://github.com/advisories/GHSA-v8cx-933x-r976) / CVE-2026-53813 and [GHSA-8wg3-5mcm-fjq8](https://github.com/advisories/GHSA-8wg3-5mcm-fjq8) / CVE-2026-53819 | memory-core artifact loading and skill install helpers | repository/workspace state could influence package-root or Homebrew executable selection | Treat opened repositories and `.env` files as untrusted inputs to agent skill/install helpers. |
| [GHSA-hcm3-8f6r-6xwg](https://github.com/advisories/GHSA-hcm3-8f6r-6xwg) and [GHSA-grc3-2j34-p6gm](https://github.com/advisories/GHSA-grc3-2j34-p6gm) | browser debug/export routes and `message.action` forwarding | already-open blocked tabs or model-supplied loopback URLs could bypass private-network/token-forwarding assumptions | Test browser/export and action-forwarding paths with owned canary tabs, local listeners, and fake Gateway tokens. |
| [GHSA-6c4r-g249-wv3c](https://github.com/advisories/GHSA-6c4r-g249-wv3c) | sandboxed child session spawn | child prompts could receive real workspace path/context from a sandboxed parent | Capture prompt/context disclosure only with synthetic path markers. |
| [GHSA-cqwv-9qjx-vxw2](https://github.com/advisories/GHSA-cqwv-9qjx-vxw2) | Skill Workshop apply flow | tool calls could apply workshop changes despite a pending approval policy | Bind generated skill changes to immutable approval state before applying. |

## Operator triage

1. **Draw the agent authority graph.** Inventory every way an action can enter the platform: Gateway API, chat bridge, native approval widget, hook endpoint, browser action, MCP loopback, proxy-facing port, marketplace install path, and memory API.
2. **Compare intent, display, approval, and execution.** For command execution, preserve the original request, displayed approval text, post-expansion argv, environment, working directory, and final process invocation. A mismatch is the finding.
3. **Test alternate routes with lower-trust identities.** Use a scoped Gateway token, non-approver chat identity, hook token, same-host local caller, or unauthenticated document client only in a lab. Confirm whether each path reaches the same guard as the primary path.
4. **Keep canaries inert.** Prefer `printf`/`id`-free marker commands, fake MCP tools, disposable memory documents, synthetic channels, and local files containing only marker text. Do not read real prompts, chat history, credentials, notebooks, node configs, or production memories.
5. **Separate auth bypass from trusted-operator behavior.** Many OpenClaw surfaces intentionally execute privileged local actions for trusted operators. Report only where a lower-trust route crosses a documented approval, scope, allowlist, locality, proxy, or authentication boundary.
6. **Treat repo-local state as an agent input.** For skill install, memory-core loading, child sessions, and embedded runners, record whether workspace `.env`, package roots, provider aliases, or prompt context influence privileged helper behavior.

## Replayable validation boundaries

### OpenClaw scope and channel-route drift

- Preconditions: disposable OpenClaw lab, affected version, one scoped Gateway client with only the documented lower privilege, synthetic chat/session routes, and a harmless admin-like canary action such as writing a marker key in a throwaway config namespace.
- Send the same command through the normal path and through the inherited external route or message-read action under test.
- Positive evidence: the lower-scoped caller resolves approval/admin behavior or reads a disallowed channel through the alternate path while the normal path rejects it.
- Negative controls: fixed OpenClaw version, a client lacking `operator.write`, and a session without inherited external delivery routes.
- Do not test with real operator channels, production plugin/config state, or real user messages.

### Approval integrity and argv-finalization checks

- Preconditions: disposable POSIX node or local runner, affected version, exec approval enabled, and commands constrained to inert marker operations.
- Capture four artifacts for each candidate command: requested string, approval UI rendering, policy decision input, and final argv/process trace.
- Exercise long-command truncation, shell-wrapper rebuilds, and safe-bin arguments containing shell-expanded values in a temp directory with marker-only files.
- Positive evidence: the command that runs differs materially from the command shown or checked, or an allowlisted command gains an unintended file operand after expansion.
- Negative controls: fixed version, commands below truncation thresholds, explicit approval with full immutable argv, and policy evaluation after expansion.
- Never hide destructive suffixes, read sensitive files, or execute payloads beyond marker creation in a temp directory.

### Chat-native approval callback checks

- Preconditions: lab QQBot integration, native approval buttons enabled, one configured approver, one non-approver account that can see a synthetic approval message, and a harmless pending action.
- Confirm text-command approval rejects the non-approver.
- Attempt the native button callback from the non-approver account.
- Positive evidence: the native button resolves the approval while the text path rejects the same identity.
- Negative controls: fixed version, approval message visible only to the configured approver, and a pending action that is already expired or canceled.
- Do not place approval buttons for real exec/plugin actions in shared chats.

### Hook, MCP loopback, and memory API boundary checks

- Preconditions: disposable OpenClaw or `mcp-memory-service` lab, fake API keys/tokens, and test-only MCP tools/documents.
- For OpenClaw hooks, trigger a run with a hook token and select the bundled CLI backend under test; record which MCP tools are visible compared with an owner session and a restricted session.
- For bundled MCP loopback, attempt session spawn through each transport/path and compare the effective exec denylist with the expected denylist.
- For `mcp-memory-service`, call `/api/memories` and `/api/documents/*` with and without credentials using marker-only documents. Test upload, history/search, and delete in an empty store.
- Positive evidence: hook-triggered or loopback sessions gain owner-only tools/exec capabilities, or unauthenticated document routes can write/read/delete while the corresponding memory routes require auth.
- Negative controls: patched OpenClaw or `mcp-memory-service`, hooks disabled, no bundled CLI backend, denylist enforced at spawn, and document routes returning authentication failures.
- Never expose real memory stores, collect user memories, trigger production cron/tool actions, or delete non-test documents.

### Browser action and trusted-proxy locality checks

- Preconditions: lab browser-control instance, owned redirect/canary page, synthetic private web service, and a proxy/topology you control.
- Browser control: verify direct navigation to a private-network canary is blocked; then load an allowed page where a click/action causes navigation to the same private canary. Evaluate only a marker string from the canary page.
- Trusted proxy: verify the Gateway backend port cannot be reached directly except from the actual proxy; if same-host direct access is intentionally possible, send fake identity headers and compare the resolved operator identity.
- Control UI pairing: from a temporary/shared-token client, test whether spoofed locality signals can create a durable paired device; record only device IDs and role decisions from the lab.
- Positive evidence: action-triggered navigation bypasses the private-network guard, direct same-host headers are trusted as proxy identity, or temporary UI access persists as admin pairing.
- Negative controls: patched version, backend bound only to the proxy interface, explicit proxy header stripping, and pairing that requires cryptographic device proof rather than locality alone.
- Do not browse internal production services, capture pages with secrets, or mint durable tokens outside an owned lab.

### Marketplace extension metadata checks

- Preconditions: isolated OpenClaw marketplace/plugin lab, inert extension package, and a marker payload that only logs or writes inside a temp directory.
- Build a package where visible metadata points to reviewed content while runtime metadata attempts to load a hidden or alternate entry point.
- Positive evidence: installation or runtime loading executes the alternate content that the scanner/review path did not inspect.
- Negative controls: fixed version, package allowlist requiring immutable digests, scanner resolving the same metadata as runtime, and runtime refusing out-of-manifest paths.
- Do not install untrusted marketplace packages on production gateways or run payloads beyond marker-only code.

## Reporting notes

- Lead with the crossed boundary: **scoped route to admin command**, **approval display to hidden execution**, **hook token to owner MCP tools**, **native approval widget to approver identity**, **browser action to private-network read**, **proxy/locality signal to operator identity**, or **unauthenticated documents route to memory read/write/delete**.
- Include version, feature flags, identity used, exact route/transport, positive/negative decision table, and sanitized canary values.
- Avoid broad claims such as “agent takeover” unless the tested deployment proves a lower-trust principal can reach a real high-impact tool or state transition.
