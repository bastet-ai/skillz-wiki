# Go: Make integer overflows crashable for fuzzing (go-panikint)

## Problem
Go integer overflows on standard integer types are **silent** (wraparound). That means fuzzing often won’t “see” a reachable overflow as a failure, even when it produces security-relevant logic bugs.

## Approach
Use a compiler/tooling mode that turns overflow into a **panic**, so fuzzers can reliably detect and minimize test cases.

## Practical workflow
1) Add/identify a fuzz harness (`go test -fuzz=...`).
2) Compile/run fuzzing with an overflow-panicking toolchain (e.g., `go-panikint`).
3) Triage panics as security findings:
   - Is it reachable from attacker-controlled inputs?
   - Does it cause auth/limit bypass, empty/incorrect results, or resource exhaustion?
4) Add suppression/allowlist only for *intentional* overflows.

## CI pattern
- Run a nightly/weekly fuzz job with the overflow-panicking compiler.
- Keep suppressions explicit (comment-based or path-based) so you don’t silently lose coverage.

## Why it’s valuable
This closes a major blind spot: it turns “silent arithmetic bugs” into **deterministic, reportable crashes**.

## References
- Trail of Bits: "Detect Go’s silent arithmetic bugs with go-panikint" (2025-12-31)
