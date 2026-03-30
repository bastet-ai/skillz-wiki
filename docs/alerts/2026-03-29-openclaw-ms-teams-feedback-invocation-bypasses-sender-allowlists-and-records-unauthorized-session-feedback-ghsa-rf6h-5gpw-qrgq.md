# 2026-03-29 — OpenClaw MS Teams feedback invocation bypasses sender allowlists and records unauthorized session feedback (GHSA-rf6h-5gpw-qrgq)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** A Microsoft Teams feedback invocation path bypassed sender allowlists and could record feedback from unauthorized sources.

## Why this matters
Allowlists are only useful if every entry point uses them. If a side-path skips sender validation, an attacker can inject state or feedback into a workflow they should not control.

## Recommended actions
- **Patch/upgrade:** update to the fixed OpenClaw release.
- **Centralize sender validation** so all Teams entry points use the same allowlist.
- **Treat feedback actions as privileged writes**.
- **Add regression tests** for unauthorized senders and cross-channel feedback.

## Detection / hunting ideas
- Review logs for feedback events from disallowed senders.
- Search for any helper that bypasses the primary authorization gate.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-rf6h-5gpw-qrgq>
