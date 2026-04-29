# Agent Runtime Trust Boundaries Need Final Guards

**Date**: 2026-04-29  
**Status**: Durable guidance

Agent runtimes have more than one trust boundary: model-visible tools, workspace configuration, per-channel callbacks, browser profiles, paired devices, MCP/LSP helpers, and operator-only gateway settings. A single early policy pass is not enough if later merge steps, config loaders, or callback adapters can reintroduce privileged behavior.

This guidance distills a cluster of OpenClaw advisories published for the 2026.4.20 release. The reusable lesson is broader than one product: every path that turns untrusted workspace state or model-influenced input into runtime authority needs a final guard at the point of effect.

## Risk pattern

- **Policy bypass after filtering**: bundled MCP/LSP tools or helper capabilities are appended after the normal allow/deny pipeline.
- **Workspace-to-runtime escalation**: `.env` files or workspace config override host/runtime-control variables, API hosts, loader hooks, or child-process startup behavior.
- **Model-to-operator config drift**: agent-accessible config mutation paths can persist changes to sandboxing, auth/TLS, plugin enablement, SSRF policy, MCP servers, hooks, or filesystem hardening.
- **Callback trust confusion**: channel card actions, paired-device sessions, or cron awareness events are reclassified as a more trusted context than the caller actually has.
- **Strict-mode SSRF gaps**: profile creation or media-upload paths normalize URLs but skip the same SSRF checks enforced by later or alternate paths.

## Defensive rules

- Run a **final effective tool-policy pass** after all dynamic tools, bundled MCP/LSP helpers, compaction tools, and per-agent overrides are merged.
- Reserve runtime-control namespaces such as `OPENCLAW_*`, loader hooks, and API host overrides from workspace dotenv/config injection.
- Filter child-process environments through a denylist for startup-sensitive variables like `NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_*`, `BASH_ENV`, and language-specific preload hooks.
- Treat sandbox policy, auth/TLS, plugin enablement, hook routing, SSRF policy, MCP server config, and filesystem hardening as **operator-trusted settings** that model-driven config mutation cannot change.
- Resolve channel context from authoritative metadata before dispatching callbacks; never infer DM/group policy from a replayable card payload alone.
- Preserve untrusted labels when isolated automation emits awareness/system events into a user session.
- Apply SSRF validation at **creation time and use time** for browser profiles, media uploads, webhook destinations, and configured base URLs.

## Validation checklist

- Can a workspace `.env` alter runtime behavior, update flow paths, API destinations, or process startup code?
- Does every tool source pass through the same final allow/deny/profile policy after dynamic expansion?
- Are operator-trusted config paths blocked for model-driven patch/apply operations, including arrays and per-agent overrides?
- Do paired-device and channel-callback actions prove caller scope before operating on global state?
- Are untrusted automation outputs visibly labeled as untrusted when surfaced in another session?
- Do strict SSRF rules run before a URL is stored, not only before it is fetched?

## References

- GitHub advisory: <https://github.com/advisories/GHSA-7jm2-g593-4qrc>
- GitHub advisory: <https://github.com/advisories/GHSA-qrp5-gfw2-gxv4>
- GitHub advisory: <https://github.com/advisories/GHSA-h2vw-ph2c-jvwf>
- GitHub advisory: <https://github.com/advisories/GHSA-mj59-h3q9-ghfh>
- GitHub advisory: <https://github.com/advisories/GHSA-hxvm-xjvf-93f3>
- GitHub advisory: <https://github.com/advisories/GHSA-72q8-jcmc-97wx>
- GitHub advisory: <https://github.com/advisories/GHSA-j4c5-89f5-f3pm>
- GitHub advisory: <https://github.com/advisories/GHSA-xrq9-jm7v-g9h7>
- GitHub advisory: <https://github.com/advisories/GHSA-c4qg-j8jg-42q5>
- GitHub advisory: <https://github.com/advisories/GHSA-57r2-h2wj-g887>
