# Rust security testing workflow for audit targets

Source: [Trail of Bits: Rust-proof your code with our new Testing Handbook chapter](https://blog.trailofbits.com/2026/07/13/rust-proof-your-code-with-our-new-testing-handbook-chapter/) and its linked Testing Handbook update, published 2026-07-13.

Use this page when an authorized assessment includes Rust crates, services, parsers, CLIs, wallets, cryptographic helpers, or infrastructure components where source-assisted validation is in scope. The durable operator value is not a single CVE: it is a repeatable testing ladder that turns Rust-specific assumptions into evidence using unit tests, dynamic analysis, property tests, coverage, mutation testing, model checking, and dependency review.

!!! warning "Authorized validation only"
    Run these checks in a local clone, CI fork, or customer-approved lab. Do not fuzz shared production services, publish crashing inputs for live targets, or run untrusted build scripts outside a sandbox. Treat generated corpora, crash reproducers, and coverage reports as potentially sensitive source-derived artifacts.

## Testing ladder

| Layer | What it proves | Operator use |
| --- | --- | --- |
| Baseline unit/integration tests | Expected behavior and regression boundaries are reproducible | Establish a clean starting point before adding security fixtures. |
| Dynamic analysis with Miri-style undefined-behavior checks | Unsafe-code assumptions, aliasing, and memory-model issues are exercised in tests | Prioritize crates using `unsafe`, FFI, custom allocators, or parser internals. |
| Property testing with proptest-style generators | Invariants hold across broad structured input spaces | Convert bug-hunting hypotheses into reusable generators and shrinking reproducers. |
| Coverage measurement | Harnesses reach the parser/state-machine/security checks you care about | Avoid false confidence from fuzzers or tests that never hit the sink. |
| Mutation testing | Tests fail when security-relevant checks are removed or inverted | Prove that authorization, bounds, validation, and error-handling assertions are meaningful. |
| Model checking with Kani-style proofs | Small concurrent/stateful/unsafe invariants hold under bounded exploration | Use for compact components where exhaustive path exploration beats random search. |
| Supply-chain review | Dependency and build-script trust assumptions are explicit | Catch risky crates, vulnerable versions, feature flags, and build-time execution paths. |

## Replayable workflow

1. **Map the trust boundary.** Identify externally influenced inputs: network frames, file formats, CLI args, environment variables, plugin manifests, serialized messages, database rows, or FFI buffers.
2. **Locate the sink.** Mark where the input reaches parsing, indexing, allocation, path construction, command execution, authorization decisions, crypto verification, or unsafe blocks.
3. **Run the existing tests first.** Record the Rust toolchain, crate features, OS, and baseline pass/fail state. Do not start by changing code or cargo features.
4. **Add minimal canary fixtures.** Create one test per boundary with harmless markers: malformed lengths, invalid enum states, oversized-but-bounded inputs, traversal-looking path strings, wrong-tenant IDs, or fake signatures.
5. **Use property generators for shape, not chaos.** Generate valid-enough structures that pass early parsing and reach the security decision. Keep maximum sizes bounded so failures are triageable.
6. **Measure reachability.** Confirm the harness executes the exact module/function that enforces the boundary. If coverage misses the sink, redesign the fixture before reporting a negative result.
7. **Mutate the guard.** In a local branch, temporarily invert or remove the suspected validation check. The test should fail. If it still passes, the evidence is weak.
8. **Escalate to Miri or model checking where appropriate.** Use these for `unsafe` code, compact state machines, arithmetic invariants, and FFI-adjacent memory assumptions.
9. **Review dependencies and features.** Record risky build scripts, optional parser/crypto features, stale advisories, and dependency paths that activate only under production features.
10. **Package proof safely.** Submit the smallest reproducer, expected vs observed behavior, toolchain details, and patched negative control. Avoid full corpora dumps unless the program requests them.

## Evidence to capture

- Crate name, commit, Rust version, enabled features, and OS/architecture.
- The exact trust-boundary diagram: source, transformation, sink, expected invariant, observed failure.
- Test or harness names and the command used to run them.
- Coverage or trace evidence that the target boundary was reached.
- For mutation testing, the local diff that should break the check and the failing test output.
- For crashes, a minimized input and stack trace with secrets, proprietary corpus data, and local paths redacted.

## Report framing

Lead with the violated invariant, not with the tool:

- **Parser input -> unchecked length/index -> panic or memory-safety boundary.**
- **Repository-controlled manifest -> build-time script/dependency feature -> execution or trust expansion.**
- **Tenant/user ID in serialized state -> missing ownership check -> cross-scope action.**
- **Signature/key material -> insufficient verification invariant -> forged acceptance in a bounded harness.**

Mark speculation clearly. A Miri finding, coverage gap, or mutation-surviving test is a strong audit lead, but it becomes a vulnerability report only when tied to a reachable security boundary and a concrete impact in the authorized target.
