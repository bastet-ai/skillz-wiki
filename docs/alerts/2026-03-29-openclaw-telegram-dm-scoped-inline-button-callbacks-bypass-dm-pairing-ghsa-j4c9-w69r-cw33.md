# 2026-03-29 — OpenClaw Telegram DM-scoped inline button callbacks bypass DM pairing and mutate session state (GHSA-j4c9-w69r-cw33)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** Telegram callback queries from direct messages could mutate session state without satisfying the normal DM pairing check.

## Why this matters
Callback handlers are privileged state-transition endpoints. If callbacks are accepted under weaker auth than the initiating message path, the UI and the backend can disagree about who is allowed to act.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.28** or later.
- **Authorize callbacks with the same policy as message sends**.
- **Bind state transitions to the original user/session**.
- **Add regression tests** for unrelated DM sessions and cross-thread callbacks.

## Detection / hunting ideas
- Inspect callback handlers for auth checks weaker than the message path.
- Add tests that replay callbacks from unrelated sessions and ensure they fail.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-j4c9-w69r-cw33>
