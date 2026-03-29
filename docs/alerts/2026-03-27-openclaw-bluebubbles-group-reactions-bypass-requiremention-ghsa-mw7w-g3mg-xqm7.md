# 2026-03-27 — OpenClaw BlueBubbles group reactions bypass `requireMention` (GHSA-mw7w-g3mg-xqm7)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** BlueBubbles group reaction events bypassed `requireMention` and could still enqueue agent-visible system events in groups that were supposed to stay mention-gated.

## Why this matters
Reaction handling should obey the same authorization and mention policy as normal messages. If a side path skips policy checks, group chat traffic can become an unintended control channel.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.25** or later.
- **Enforce one policy path:** make reactions, replies, verification notices, and message ingestion all pass through the same mention/auth gate.
- **Audit group event handlers:** verify no side-channel event type bypasses mention requirements.
- **Minimize group exposure:** disable or restrict group features where they are not required.

## Detection / hunting ideas
- Review logs for reaction events that generated system output without a qualifying mention.
- Search for any code paths that call message processing helpers directly from reaction handlers.
- Add regression tests for group reactions in non-mentioned contexts.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-mw7w-g3mg-xqm7>
