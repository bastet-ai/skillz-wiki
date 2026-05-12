# OpenClaude sandbox and OpenClaw media-replay policy boundaries

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because both advisories involve agent/runtime control-plane state crossing from model-controlled or queued data into privileged execution or tool-policy decisions.

## Advisories covered

- **OpenClaude sandbox bypass through model-controlled `dangerouslyDisableSandbox`** — [GHSA-m77w-p5jj-xmhg](https://github.com/advisories/GHSA-m77w-p5jj-xmhg): vulnerable `openclaude <0.5.1` let sandbox-disabling configuration be influenced by untrusted/model-controlled input. The safe boundary is that sandbox posture must be operator-owned policy, not request/model payload data.
- **OpenClaw delivery queue recovery could lose group tool-policy context for media replay** — [GHSA-r77c-2cmr-7p47](https://github.com/advisories/GHSA-r77c-2cmr-7p47): `openclaw >=2026.4.10,<2026.4.14` could replay queued media without the original group policy context after recovery. [GHSA-82rm-qcfx-2v78](https://github.com/advisories/GHSA-82rm-qcfx-2v78) is a withdrawn duplicate.

## Operator triage

1. Upgrade OpenClaude to `0.5.1` or later and OpenClaw to `2026.4.14` or later where either is deployed.
2. Treat any model/session that could set sandbox options as potentially untrusted; review recent runs for commands, file writes, network calls, or tool invocations that would only be possible with sandbox disabled.
3. For OpenClaw group deployments, inspect delivery/replay logs for queued media handled after crashes, restarts, or reconnects; confirm each replay used the original chat/group policy and not a default/private-chat policy.
4. Rotate secrets touched by agent runs if logs show unexpected filesystem, browser, MCP, shell, or media-processing access.

## Durable controls

- Sandbox mode, network access, writable roots, and tool allowlists must be loaded from signed/configured operator policy and treated as immutable during a model turn.
- Never accept policy-relaxing fields from prompts, generated JSON, tool outputs, MCP responses, or recovered queue payloads.
- Persist the full authorization context with queued work: channel ID, group ID, requester, tool policy revision, media policy, and replay reason.
- On recovery, fail closed when policy context is absent, stale, or no longer matches the current channel membership/policy revision.
- Add regression tests where hostile model output attempts to toggle sandbox flags and where replayed media tries to cross from group policy into more permissive defaults.
