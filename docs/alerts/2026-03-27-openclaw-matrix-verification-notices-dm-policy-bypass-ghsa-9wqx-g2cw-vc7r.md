# 2026-03-27 — OpenClaw Matrix verification notices bypass DM policy (GHSA-9wqx-g2cw-vc7r)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** Matrix verification notices previously bypassed DM access checks and could reply to peers that were unpaired or otherwise outside the allowed DM policy.

## Why this matters
Verification and onboarding flows often look low-risk, but they still emit messages and can leak information. Any notice path that skips DM authorization can become an unintended communication channel.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.25** or later.
- **Gate verification flows:** ensure verification notices and onboarding replies enforce the same DM access policy as normal private messages.
- **Add policy tests:** cover unpaired peers, blocked peers, and restricted rooms.
- **Review logs:** look for verification notices sent to targets that should have been denied.

## Detection / hunting ideas
- Search for verification notices delivered to unpaired DMs or blocked peers.
- Audit any helper that sends “informational” replies outside the primary DM send path.
- Add tests that prove the verification path fails closed when DM policy rejects the target.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-9wqx-g2cw-vc7r>
