# 2026-02-06 — Rust `time` crate RFC 2822 parsing stack exhaustion DoS (GHSA-r6v5-fh4h-64xc)

**Upstream advisory:** https://github.com/advisories/GHSA-r6v5-fh4h-64xc

## What happened
The Rust `time` crate had a parsing edge case for **RFC 2822** date-time strings that could trigger **unbounded recursion**, causing **stack exhaustion** (DoS).

## Who is affected
Projects that:
- accept **user-controlled** RFC 2822 date-time strings, and
- parse them via `time` versions `>= 0.3.6, < 0.3.47`.

## Defender guidance
- **Upgrade** `time` to `0.3.47` or later.
- Treat parsers as a DoS surface:
  - **limit input length** for any user-controlled datetime/header fields
  - apply request-level limits (body size, header size, timeouts)

## Durable lesson
Even “standards-compliant” parsers can be weaponized via **pathological inputs**.
For any parser reachable by attacker input:
- cap input sizes
- add recursion/depth limits
- fuzz with adversarial grammars

## References
- GHSA: https://github.com/advisories/GHSA-r6v5-fh4h-64xc
- RustSec: https://rustsec.org/advisories/RUSTSEC-2026-0009.html
