# 2026-03-29 — OpenClaw Feishu raw card send surface can mint legacy card callbacks that bypass DM pairing (GHSA-77w2-crqv-cmv3)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** A Feishu raw-card send path could mint legacy card callbacks that bypassed DM pairing.

## Why this matters
Generating callback-capable objects is equivalent to minting authority. If a raw send path can produce callbacks that bypass the normal pairing model, the message layer has become an authorization bypass.

## Recommended actions
- **Patch/upgrade** to the fixed OpenClaw release.
- **Apply pairing checks to both send and callback paths**.
- **Treat callback minting as a privileged action**.
- **Add regression tests** for raw-card and legacy-callback behavior.

## Detection / hunting ideas
- Search for card sends that generate callbacks without a valid pairing context.
- Verify that legacy callback paths are not accepted from unpaired sessions.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-77w2-crqv-cmv3>
