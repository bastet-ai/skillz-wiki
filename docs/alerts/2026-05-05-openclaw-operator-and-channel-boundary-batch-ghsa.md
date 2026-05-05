# OpenClaw operator, browser, and channel boundary batch (GHSA)

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-05** OpenClaw batch of refreshed advisories where approval binding, plugin provenance, browser/network policy, media handling, channel callbacks, runtime configuration, and sandbox routing all required final trust-boundary checks.

## Advisories in this batch

- **Explicit approval authorization:** empty approver lists could authorize approvals instead of denying by default. Reference: <https://github.com/advisories/GHSA-49cg-279w-m73x>.
- **Existing-session browser SSRF:** existing-session browser interaction routes bypassed SSRF policy enforcement. Reference: <https://github.com/advisories/GHSA-527m-976r-jf79>.
- **Teams SSO sender authorization:** Microsoft Teams SSO invoke handling missed sender authorization checks. Reference: <https://github.com/advisories/GHSA-gc9r-867r-j85f>.
- **Plugin provenance during channel setup:** channel setup catalog lookups could include untrusted workspace plugin shadows. Reference: <https://github.com/advisories/GHSA-82qx-6vj7-p8m2>.
- **Workspace provider auth choices:** workspace provider auth choices could auto-enable untrusted provider plugins. Reference: <https://github.com/advisories/GHSA-939r-rj45-g2rj>.
- **Operator-write config persistence:** memory dreaming and Matrix profile config persistence were reachable from operator/message write paths. References: <https://github.com/advisories/GHSA-5gjc-grvm-m88j>, <https://github.com/advisories/GHSA-7jp6-r74r-995q>.
- **Workspace-only filesystem guard:** `screen_record` output paths and host media attachment reads could bypass intended filesystem/sender boundaries. References: <https://github.com/advisories/GHSA-jf25-7968-h2h5>, <https://github.com/advisories/GHSA-jhpv-5j76-m56h>.
- **Untrusted event ownership:** heartbeat webhook wakes, collect-mode queue batches, and agent hooks could carry or reuse trusted authorization context. References: <https://github.com/advisories/GHSA-g2hm-779g-vm32>, <https://github.com/advisories/GHSA-jwrq-8g5x-5fhm>, <https://github.com/advisories/GHSA-7g8c-cfr3-vqqr>.
- **Media and SSRF sinks:** QQBot media tags, QQBot reply media URLs, Discord event cover images, and browser tab/snapshot/screenshot routes needed final sandbox, SSRF, and content-exposure checks. References: <https://github.com/advisories/GHSA-66r7-m7xm-v49h>, <https://github.com/advisories/GHSA-2767-2q9v-9326>, <https://github.com/advisories/GHSA-c9h3-5p7r-mrjh>, <https://github.com/advisories/GHSA-rj2p-j66c-mgqh>, <https://github.com/advisories/GHSA-c4qm-58hj-j6pj>, <https://github.com/advisories/GHSA-53vx-pmqw-863c>.
- **Runtime and command trust:** workspace `.env` runtime-control injection, busybox/toybox applet execution, exec preflight TOCTOU, env-argv assignment injection, and sandbox `host=node` overrides weakened approval or sandbox guarantees. References: <https://github.com/advisories/GHSA-7wv4-cc7p-jhxc>, <https://github.com/advisories/GHSA-2cq5-mf3v-mx44>, <https://github.com/advisories/GHSA-gj9q-8w99-mp8j>, <https://github.com/advisories/GHSA-j6c7-3h5x-99g9>, <https://github.com/advisories/GHSA-736r-jwj6-4w23>.
- **Config redaction and realtime resource limits:** config aliases bypassed redaction, and voice-call realtime WebSocket accepted oversized frames. References: <https://github.com/advisories/GHSA-8372-7vhw-cm6q>, <https://github.com/advisories/GHSA-vw3h-q6xq-jjm5>.

## Why this is durable

Agent systems mix user-controlled workspaces, operator-owned configuration, browser/session state, channel messages, local files, and helper processes. The common failure mode is assuming an earlier policy decision still applies after routing through queues, plugins, browser tabs, media normalizers, filesystem helpers, or command wrappers. Durable defense means every privileged sink re-verifies **who asked, from where, under which policy, and for which exact resource**.

## Immediate triage

1. **Upgrade OpenClaw** to a release containing the May 2026 boundary fixes, prioritizing deployments with browser automation, channel bots, voice, ACP/subagents, operator.write surfaces, or workspace plugins enabled.
2. **Review trust-bearing queues and callbacks:** heartbeat webhook wakes, collect-mode batches, Teams SSO invokes, agent-hook events, and channel setup flows should preserve sender identity and downgrade untrusted input before enqueueing.
3. **Audit browser and media egress:** look for private-network browser navigation, existing-session browser actions, tab close/select operations, QQBot/Discord media fetches, and screenshots/snapshots taken after navigation to internal pages.
4. **Inspect workspace-controlled config:** search `.env`, provider/auth choices, plugin catalogs, and operator-write-accessible settings for attempts to redirect runtime controls, providers, memory dreaming, Matrix profiles, or connector-like behavior.
5. **Recheck command/sandbox logs:** flag busybox/toybox applet execution, env-argv assignments, preflighted scripts modified between approval and execution, and any sandboxed task that supplied `host=node`.

## Hunt ideas

- Query Gateway/browser logs for navigation to RFC1918, loopback, link-local, metadata, or internal DNS names from existing-session browser routes.
- Diff channel-event sender IDs against the authorization context used when queue batches, hooks, or callbacks were processed.
- Search media fetch logs for `file:`, loopback, internal hostnames, unusually large uploads, or re-uploaded bytes from reply text / event cover URLs.
- Grep workspaces for `OPENCLAW_`, provider, runtime, browser, gateway, connector, Matrix, memory, or plugin variables in `.env` and generated dotenv files.
- Compare approval prompts to executed argv after shell wrapper, applet, and env-assignment normalization.

## Durable controls

- Deny empty allow/approver lists by default; never let missing policy mean “everyone.”
- Keep operator-owned configuration and plugin provenance separate from workspace-controlled files.
- Apply SSRF policy at each URL-consuming sink, including existing browser sessions, tab operations, media downloads, and screenshots/snapshots.
- Bind queued work to immutable sender, channel, owner, and policy context; downgrade untrusted webhooks before they can create trusted system events.
- Normalize commands to final argv before approval and again before execution; reject wrappers, applets, env assignments, and TOCTOU changes that alter the approved operation.
- Cap realtime frame sizes and redact config through a single canonical path rather than alias-specific filters.

## Operator lesson

For agent runtimes, every convenience bridge is a trust-boundary bridge. Treat browser sessions, channel media, `.env`, plugin catalogs, queued events, and shell wrappers as attacker-controlled until the final privileged sink proves otherwise.
