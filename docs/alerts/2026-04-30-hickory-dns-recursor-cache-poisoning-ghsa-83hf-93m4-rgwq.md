# Hickory DNS recursor sibling-zone cache poisoning (GHSA-83hf-93m4-rgwq)

**Signal:** GitHub Security Advisories published **2026-04-30**. Hickory DNS fixed an experimental recursive resolver cache issue that allowed authority-section NS records from one child zone to poison a sibling zone.

## What it is
The experimental `hickory-recursor` record cache inserted records keyed by each returned record's `(name, type)` while applying a bailiwick check based on the parent NS-pool context. A malicious nameserver for `attacker.poc.` could include an `AUTHORITY` record like `victim.poc. NS ns.evil.poc.`. Because `victim.poc.` is still under parent `poc.`, the record could pass and be cached for the sibling zone, steering later `victim.poc.` lookups to the attacker's nameserver.

Affected package: Rust `hickory-recursor` `0.24.0` through `0.25.2` and legacy `0.1`. Fixed path: migrate to `hickory-resolver` `0.26.0+` with the non-default `recursor` feature. The standalone `hickory-recursor` crate will not receive further updates.

Reference: <https://github.com/advisories/GHSA-83hf-93m4-rgwq>

## Triage
1. Inventory Hickory DNS deployments using the opt-in recursive resolver / `recursor` feature.
2. Confirm whether they resolve untrusted domains and cache authority/additional-section records.
3. Inspect resolver logs for sibling-zone NS changes after queries to attacker-controlled or newly delegated zones.

## Mitigation
- Upgrade/migrate to `hickory-resolver >= 0.26.0` with `recursor` if recursive service is required.
- Flush resolver caches after upgrading.
- Prefer response-level cache keys tied to the original query, not arbitrary returned RRsets, for recursive resolver code.

## Detection ideas
- Compare cached NS RRsets for internal or high-value zones against authoritative answers.
- Alert on recursive resolvers sending all traffic for a legitimate sibling zone to newly observed nameservers.

## Durable lesson
DNS bailiwick checks must be tied to the queried name and delegation path, not just a broad parent-zone context. Authority-section records are attacker-controlled input until proven relevant to the exact lookup.
