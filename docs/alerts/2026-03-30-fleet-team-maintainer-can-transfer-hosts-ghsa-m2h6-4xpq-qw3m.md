# 2026-03-30 — Fleet team maintainer can transfer hosts from any team via missing source team authorization (GHSA-m2h6-4xpq-qw3m)

**Product:** **Fleet**

**Impact (per advisory):** A maintainer could transfer hosts out of a team they should not control because the source-team authorization check was missing.

## Why this matters
Cross-team transfer and ownership actions are high-risk state changes. If the server only checks the destination or the caller’s general role, an attacker can move managed assets across trust boundaries.

## Recommended actions
- **Patch/upgrade** Fleet to the fixed release.
- **Authorize on both sides** of any transfer:
  - caller’s role in the source team
  - caller’s role in the destination team
  - object ownership and team membership
- **Log and alert** on host transfers, especially between teams.
- **Review adjacent actions** for similar missing source-context checks.

## Detection / hunting ideas
- Search audit logs for team-to-team transfers by maintainers who lacked source-team admin rights.
- Add regression tests that attempt transfers from unauthorized source teams.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-m2h6-4xpq-qw3m>
