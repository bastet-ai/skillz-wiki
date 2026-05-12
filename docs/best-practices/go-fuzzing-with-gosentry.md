# Go fuzzing: keep `testing.F`, upgrade the engine with gosentry

**Date**: 2026-05-12  
**Source**: Trail of Bits, *Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.*  
**Status**: Durable guidance

---

## Core lesson

Go's native fuzzing interface is useful, but the default engine can miss security-relevant behaviors that do not naturally crash: hard path constraints, structured parsers, integer wraparound, goroutine leaks, races, and timeout-driven denial of service.

For Go audits, treat a normal `go test -fuzz` campaign as a baseline, not as complete evidence. When the target has parsers, protocol state, consensus logic, arithmetic, or concurrency boundaries, rerun the same harnesses under a stronger engine such as Trail of Bits' `gosentry` toolchain.

---

## Why this matters for security work

Many Go vulnerabilities are semantic rather than simple memory crashes:

- parser or protocol disagreement between implementations
- arithmetic wraparound that changes limits, lengths, balances, or authorization decisions
- goroutine leaks or infinite loops that become resource exhaustion
- data races that corrupt state only under schedule pressure
- structured input formats where random byte mutation stalls before meaningful branches
- critical `log.Fatal`/error paths that should become findings but do not panic in a normal fuzz run

`gosentry` preserves the familiar `testing.F` harness API while routing `go test -fuzz` through LibAFL, adding options for grammar-aware and struct-aware input generation, race/leak detection, timeout handling, coverage reporting, and integrations such as go-panikint-style overflow checks.

---

## Practical workflow

Use this when reviewing Go code with non-trivial input or state boundaries.

1. **Start with the existing harness**
   - Keep `testing.F`, `f.Add`, and `f.Fuzz` unchanged where possible.
   - Seed the corpus with realistic protocol messages, serialized objects, or edge-case states.

2. **Run the baseline campaign**
   - Record the stock Go version, command line, corpus location, duration, and coverage growth.
   - Do not treat "no crash" as strong evidence until the harness reaches meaningful branches.

3. **Rerun under gosentry**
   - Point the package at the gosentry `go` binary and use the same `-fuzz` target.
   - Enable detectors that match the target class, for example race detection for shared state and leak detection for request/session lifecycles.
   - Generate coverage reports from the same campaign state so reviewers can compare reachability, not just crashes.

4. **Add structured input where byte mutation stalls**
   - Use struct-aware fuzzing for typed inputs instead of inventing ad hoc binary encodings.
   - Use grammar-based fuzzing for JSON, wire protocols, expression languages, config formats, and consensus/state-transition inputs.

5. **Turn security-significant bad states into failures**
   - Make integer overflow, critical logs, invariant violations, panics, races, leaks, and timeouts fail the campaign.
   - Add explicit allowlists only for intentional wraparound or expected long-running states.

---

## Operator checklist

Before accepting a negative fuzzing result in a Go assessment:

- [ ] The harness has realistic seed corpus entries.
- [ ] Coverage grows past parsing and validation gates.
- [ ] Structured formats use grammar-aware or struct-aware generation when plain bytes stall.
- [ ] Integer overflow/truncation paths are crashable or otherwise asserted.
- [ ] Race and goroutine-leak detectors are enabled for concurrent code.
- [ ] Timeouts are treated as findings for parser/protocol/resource-boundary targets.
- [ ] Critical logging/error paths can fail the harness, not just print and continue.
- [ ] Campaign coverage and minimized crashers are preserved for replay.

---

## Assessment pattern

For high-value Go targets, include both commands in the evidence bundle:

```text
# Baseline: stock toolchain behavior
go test ./... -run=^$ -fuzz=FuzzTarget -fuzztime=...

# Stronger campaign: same harness, stronger engine/detectors
/path/to/gosentry/bin/go test ./... -run=^$ -fuzz=FuzzTarget \
  --focus-on-new-code=false \
  --catch-races=true \
  --catch-leaks=true
```

Adjust flags to the installed gosentry version and target risk. The important habit is to make the engine choice explicit and reproducible.

---

## Takeaway

A Go fuzz harness is portable evidence, but the engine decides what becomes visible. Keep the `testing.F` workflow developers already know, then upgrade the campaign when security depends on structured inputs, concurrency, arithmetic, or protocol-state exploration.

## References

- Trail of Bits: "Go fuzzing was missing half the toolkit. We forked the toolchain to fix it." (2026-05-12)
- Trail of Bits: "Detect Go's silent arithmetic bugs with go-panikint" (2025-12-31)
