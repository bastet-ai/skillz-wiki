# netfoil seccomp flag not applied and domain allowlist bypass (GHSA-vjgj-42f6-7997 / GHSA-84g5-x8j3-7235)

**Signal:** GitHub Security Advisories published **2026-04-29**. netfoil fixed a defense-in-depth sandboxing failure and an off-by-one domain-filter bypass.

## What it is
`GHSA-vjgj-42f6-7997` reports that the optional `--filter-system-calls` seccomp sandbox flag was not applied even when specified. `GHSA-84g5-x8j3-7235` reports an off-by-one suffix-trie bug where an allowlist entry such as `example.com` could be bypassed with a different first character such as `fxample.com`.

Affected package: Go `github.com/tinfoil-factory/netfoil` `< 0.2.1`. Fixed version: `0.2.1`.

References: <https://github.com/advisories/GHSA-vjgj-42f6-7997>, <https://github.com/advisories/GHSA-84g5-x8j3-7235>

## Triage
1. Inventory netfoil deployments using DNS/domain filtering or relying on `--filter-system-calls`.
2. Review allowlist policy for high-value domains and whether bypassable lookalikes could reach sensitive destinations.
3. Confirm whether systemd, container, or kernel-level sandboxing exists outside the netfoil optional flag.

## Mitigation
- Upgrade netfoil to `0.2.1` or later.
- Treat DNS filtering as one layer only; pair it with egress firewalling and destination IP controls.
- Enforce seccomp/systemd sandboxing outside the application where possible.

## Detection ideas
- Review DNS and connection logs for one-character variants of allowlisted domains.
- Check process startup logs/configs where `--filter-system-calls` was expected to harden the binary.

## Durable lesson
Allowlists and optional sandboxes need negative tests. A control that silently fails closed only in documentation is not a control in production.
