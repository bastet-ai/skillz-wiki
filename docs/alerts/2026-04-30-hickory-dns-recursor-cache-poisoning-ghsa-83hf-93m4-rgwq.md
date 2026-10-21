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

## October 21 follow-up: Unbound trust-decision downgrades and a source-port oracle (5-leg wave, ≤1.26.1)

A five-advisory Unbound wave published 2026-10-21T09:30Z gives recursor-side operators a replayable validation/probing battery — all four security legs turn **response content the validator should only *verify* into input that changes the *trust level* of a zone**:

- **Island-of-security downgrade via forged NSEC** ([CVE-2026-35501 / GHSA-mh74-9w87-h7vx](https://github.com/advisories/GHSA-mh74-9w87-h7vx), low, 1.0.1–1.26.1): with a manually configured `trust-anchor:` for an island zone whose parent is provably insecure under the root chain, an NSEC reply with the **SOA bit cleared** is accepted and cached as *insecure* — the configured trust island silently drops to DNSSEC-unaware treatment. **Forged NXDOMAIN variant** ([CVE-2026-50106 / GHSA-pj55-6fvm-845h](https://github.com/advisories/GHSA-pj55-6fvm-845h), medium): one NXDOMAIN for a name inside the island with the NSEC/SOA RRSIG `SignerName` set to the *insecure parent* tricks the validator into using the root anchor for the island's proofs → responses accepted without the island's own anchor. Operator battery for any validating resolver: craft negative responses that vary (SOA bit, SignerName, proof type) against zones with manually configured anchors and watch for validation-state flips in `+cdflag`/`dig +doesna` style comparisons or resolver logs.
- **Source-port oracle → cache poisoning chain** ([CVE-2026-109125 / GHSA-66rc-377g-m4m4](https://github.com/advisories/GHSA-66rc-377g-m4m4), medium, non-default `unwanted-reply-threshold > 0`): UDP datagrams aimed at the current upstream source port with a non-matching TXID are counted as unwanted replies; hitting the threshold **clears the worker's caches without killing the pending query** — an observer can then test candidate ports by checking whether a known cached item disappeared, filter the port, and follow with birthday-style TXID guessing. Reusable invariant beyond Unbound: **any rate/abuse counter whose trigger action is observable state destruction (cache clear, session flush, throttle page) is a side channel into whatever random value the counter's arrival correlates with.** For resolver engagements, check `unwanted-reply-threshold` shapes in exposed configs; the two-step (port filter, then TXID race) replaces flat Kaminsky fan-out on hardened targets.
- **DoQ lifetime UAF** ([CVE-2026-97206 / GHSA-jc7q-6h55-rr57](https://github.com/advisories/GHSA-jc7q-6h55-rr57), high, 1.22.0–1.26.1): remote DoQ client triggering QUIC **path migration** enters stream cleanup while a mesh reply still holds the stream pointer → stale-pointer crash. Transport-mid-lifecycle teardown race — same audit shape as every "connection event frees an object an in-flight async task still references" leg on this wiki; DoQ path migration is a cheap, scriptable trigger distinct from reconnect.
- Compression-pointer CPU DoS ([CVE-2026-96405 / GHSA-r7j4-9v27-x32x](https://github.com/advisories/GHSA-r7j4-9v27-x32x)) tracked without promotion: per-operation traversal limits with **no aggregate decompression-work budget** is the reusable line — bound work per *message*, not per *operation*.

Durable rule for validating resolvers (DNSSEC or not): negative/authority answers must be validated **against the anchor actually configured for the name's chain**, and trust-level transitions (secure→insecure) must require proof the zone is genuinely unsigned — never a field the answer itself carries.
