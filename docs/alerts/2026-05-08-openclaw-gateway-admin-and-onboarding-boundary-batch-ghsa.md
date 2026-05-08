# OpenClaw gateway admin and onboarding boundary batch

**Signal:** The **2026-05-08 18:15 UTC** advisory scan surfaced three OpenClaw authorization/provenance advisories that reinforce an existing durable lesson: write-scoped automation must not be able to persist admin-class state, and remote onboarding must pin an explicitly trusted gateway.

## Advisories covered

- **`operator.write` to persisted verbose defaults** — [GHSA-5h2w-qmfp-ggp6](https://github.com/advisories/GHSA-5h2w-qmfp-ggp6) / CVE-2026-41344: `openclaw <= 2026.3.24`; patch to `2026.3.28+`.
- **Unauthenticated remote discovery endpoint persisted during onboarding** — [GHSA-3cw3-5vxw-g2h3](https://github.com/advisories/GHSA-3cw3-5vxw-g2h3) / CVE-2026-41342: `openclaw <= 2026.3.24`; patch to `2026.3.28+`.
- **`operator.write` reaching admin-class Telegram config and cron persistence through send** — [GHSA-767m-xrhc-fxm7](https://github.com/advisories/GHSA-767m-xrhc-fxm7) / CVE-2026-41359: `openclaw <= 2026.3.24`; patch to `2026.3.28+`.

## Why this is durable

These are not just individual route bugs. They are **capability-boundary bugs**: a lower-privilege path reached persistence knobs that change future execution, observability, channel configuration, cron behavior, or gateway trust roots. Any agent platform with chat-driven directives, setup helpers, or gateway writes needs one final policy gate at the durable-state mutation, not only at the UI or command parser.

## Immediate triage

1. Upgrade OpenClaw to `2026.3.28+`; prefer the current stable release.
2. Inventory gateway API keys and operator scopes that had `operator.write` against affected versions.
3. Review persisted session verbosity/defaults, Telegram/channel configuration, and cron definitions for unexpected changes made by non-admin actors.
4. Re-run remote onboarding only after confirming the displayed gateway URL, certificate/TLS expectations, and ownership out-of-band.
5. Rotate gateway credentials if a remote discovery endpoint was accepted without explicit trust confirmation.

## Durable controls

- Enforce admin authorization at the storage layer for any mutation that persists across sessions, restarts, channels, cron, or gateway trust configuration.
- Treat chat directives as user input, not authorization decisions; parse intent separately from privilege checks.
- Require explicit trust confirmation before saving discovered remote endpoints, and pin the final endpoint identity in config.
- Add regression tests where every write-scoped API attempts to mutate admin-only persisted fields and must fail.
- Log durable-state writes with caller scope, channel, old/new value class, and whether the request originated from chat, CLI, API, or setup flow.
