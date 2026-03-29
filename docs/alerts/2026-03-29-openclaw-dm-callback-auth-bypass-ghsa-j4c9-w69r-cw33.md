# 2026-03-29 — OpenClaw Telegram DM-scoped callback authorization bypass (GHSA-j4c9-w69r-cw33)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** Telegram callback queries from direct messages could mutate session state without satisfying the normal DM pairing check.

## Why this matters
Callback handlers are privileged state-transition endpoints. If a callback can be accepted on weaker authorization than the initiating message path, a user or bot interaction can bypass the intended pairing and move state in ways the UI never authorized.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.28** or later.
- **Authorize callbacks with the same policy as the initiating channel:** do not trust callback-only context.
- **Bind state transitions to the original session/user:** verify the callback belongs to the same DM pairing and conversation context.
- **Add regression tests for callback authorization:** include direct-message and cross-thread cases.

## Detection / hunting ideas
- Inspect callback handlers for authorization checks weaker than the corresponding message handlers.
- Add tests that replay callbacks from unrelated DM sessions and ensure they fail.
- Review any code that stores session state and mutates it from interactive UI elements.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-j4c9-w69r-cw33>
