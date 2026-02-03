# 2026-02-03 — Rust `bytes` integer overflow in `BytesMut::reserve` (GHSA-434x-w66g-qw3r)

**What happened:** The Rust `bytes` crate had an integer overflow in `BytesMut::reserve`.

**Why it matters:** Memory safety in Rust depends on library correctness. Overflows in capacity/length math can lead to:
- panics (DoS)
- memory corruption in unsafe code paths

## Durable guidance (defensive)

1. **Upgrade dependencies promptly**
   - Especially core crates used in network parsing and message framing.

2. **Treat lengths from the network as hostile**
   - Cap maximum frame/message sizes before reserving.

3. **Fuzz critical parsers**
   - Add fuzzing for any code that computes buffer sizes from untrusted inputs.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-434x-w66g-qw3r>
