# Dimensional annotations (units of measure) for safer code

Many “logic” vulnerabilities are really **unit/dimension bugs**:

- mixing milliseconds vs seconds
- bytes vs characters
- “count” vs “amount” (shares vs assets, cents vs dollars)
- fixed‑point scale mismatches (1e18 vs 1e27)

A simple rule catches a surprising amount of this class:

- **You can only add/subtract like-with-like.**
- **Both sides of an equation must have the same dimension.**

This is standard in physics (“dimensional analysis”), but the same discipline works in software and security reviews.

## What to do (practical guidance)

### 1) Make dimensions explicit in the codebase
Pick a convention and apply it everywhere:

- variable naming: `*_ms`, `*_secs`, `*_bytes`, `*_chars`, `*_cents`, `*_usd`, `*_shares`, `*_assets`
- comment tags for more complex systems: `{bytes}`, `{ms}`, `{UoA/tok}`, `{requests/sec}`
- wrapper types / newtypes where possible (best):
  - Rust: `struct Millis(u64);`
  - Go: `time.Duration` (prefer it over raw `int`)
  - TypeScript: branded types (e.g. `type Millis = number & {__brand: 'ms'}`)

### 2) Document *scale* together with dimension
A lot of security-impacting bugs come from *scale* mismatches, not only dimensions.

Examples:

- fixed-point: `D18`, `D27`
- percentages: `0–1` vs `0–100` vs `0–10000` (basis points)
- money: cents vs dollars

Rule of thumb:

- If a value can be “the same concept” but represented at multiple scales, **encode/annotate the scale**.

### 3) Put unit annotations at API boundaries
Unit bugs often originate at boundaries:

- request parsing / deserialization
- database reads/writes
- inter-service calls
- SDK wrappers
- smart contract ↔ off-chain interfaces

At each boundary, ensure you can answer:

- *What dimension is this value?*
- *What scale/precision is it in?*
- *What invariants must hold?* (non-negative, max, monotonic, etc.)

### 4) Enforce with automation (where feasible)
Pick the strongest enforcement your stack can support:

- **Compiler/type system** (best): newtypes / opaque types / units-of-measure features.
- **Lints**: ban raw `int` for time, money, sizes in sensitive code.
- **Property tests**: assertions like “this result should be within [min,max]” and “unit conversions are reversible”.
- **Review checklist**: require unit tags for arithmetic-heavy code paths.

### 5) Treat “dimension mismatches” as security smells
If a reviewer can’t explain the units of a value in a privileged path (auth, billing, rate-limits, crypto, permissions), treat it like a potential vuln.

Common security outcomes:

- authz bypass via incorrect limit computations
- rate-limit bypass / DoS via time unit confusion
- money/credit inflation/deflation
- incorrect signature verification due to preimage length/encoding confusion

## Quick review checklist

- [ ] Are time values represented as `Duration`/`Instant` (or equivalent) instead of raw integers?
- [ ] Do money values use integer minor-units (cents) with clear currency tagging?
- [ ] Are bytes vs characters clearly distinguished in encoding-sensitive paths?
- [ ] Are fixed-point scales documented (and consistent) across functions/modules?
- [ ] Do arithmetic operations only combine values of the same dimension?
- [ ] Do conversions happen in one place with tests?

## References

- Trail of Bits: *Spotting issues in DeFi with dimensional analysis* (dimension mismatches as bug-finding technique)
  - https://blog.trailofbits.com/2026/03/24/spotting-issues-in-defi-with-dimensional-analysis/
- Trail of Bits: *Try our new dimensional analysis Claude plugin* (mechanizing annotation + mismatch detection)
  - https://blog.trailofbits.com/2026/03/25/try-our-new-dimensional-analysis-claude-plugin/
