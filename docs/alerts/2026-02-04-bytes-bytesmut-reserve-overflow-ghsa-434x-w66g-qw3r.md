# 2026-02-04 — Rust `bytes` integer overflow in `BytesMut::reserve` (GHSA-434x-w66g-qw3r / RUSTSEC-2026-0007)

**Signal:** GitHub Security Advisory updated 2026-02-04.

**Impact (per advisory):** An unchecked integer addition in a unique reclaim path of `BytesMut::reserve` can corrupt internal capacity tracking, leading to potential **out-of-bounds slices** and **undefined behavior** in release builds where overflow wraps.

**Component:** Rust crate `bytes`

## Why this matters
Memory-safety issues in foundational crates can become high-impact when reachable from untrusted input paths (network parsing, protocol stacks). Even when exploitation is difficult, UB is a serious correctness and security risk.

## Fix
Upgrade `bytes` to **1.11.1** or later.

## Notes / triage guidance
- The advisory notes this is observable in **release** builds (wrapping overflow); debug builds panic.
- Prioritize upgrades in services that ingest attacker-controlled payloads and use `BytesMut` heavily (e.g., network servers, proxies).

## References
- Advisory:
  - <https://github.com/tokio-rs/bytes/security/advisories/GHSA-434x-w66g-qw3r>
- RustSec:
  - <https://rustsec.org/advisories/RUSTSEC-2026-0007.html>
- GitHub advisory database mirror:
  - <https://github.com/advisories/GHSA-434x-w66g-qw3r>
