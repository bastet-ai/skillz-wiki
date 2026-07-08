# Mutation Testing Beats Coverage Theater

**Date**: 2026-04-02  
**Source**: Trail of Bits, *Mutation testing for the agentic era*; *Mutation testing comes to DAML*  
**Status**: Durable guidance

---

## Core lesson

Code coverage is not proof that security-relevant behavior is tested. It only tells you that code executed, not that the test suite actually verified the right properties.

Mutation testing is the stronger signal: introduce small bugs on purpose and see whether tests fail. If the mutant survives, the suite missed a meaningful check.

---

## Why this matters for security work

High coverage can hide real gaps:

- access control paths may execute without asserting authorization outcomes
- input validation code may run without checking the dangerous edge case
- parsing or normalization logic may be exercised while the security invariant remains untested
- regression tests may pass while nearby logic remains brittle

For security reviews, coverage is a comfort metric. Mutation testing is closer to a trust metric.

---

## Practical guidance

Use mutation testing when you need to know whether tests enforce the security property you care about.

### Good targets

- authorization branches
- input validation and sanitization
- parsing and normalization logic
- risky state transitions
- regression tests for past vulnerabilities

### What to look for

- mutants that survive in security-sensitive branches
- entire classes of logic that never cause a test failure
- repeated survivors that show the suite is asserting the wrong thing
- tests that check execution path instead of observable security outcome

---

## Agentic workflow notes

Trail of Bits’ update is also a reminder that agents can help here if the workflow is structured:

- generate mutants systematically
- prioritize the ones most likely to expose missing security checks
- store results in a persistent format so campaigns can resume
- review survivors as evidence of weak assertions, not just noisy test failures

The agent’s job is not to make coverage high. It is to expose the places where the test suite lies.

---

## DAML / Canton authorization checks

Trail of Bits' DAML support in Mewt is a useful pattern for smart-contract and ledger application reviews: target authorization semantics directly, not just line or choice coverage.

DAML coverage can report that every template and choice executed while the tests never prove that the right parties must authorize the action. Treat controller mutations as a way to ask: if a required signer was swapped or removed, would the suite fail?

### What to mutate

- `controller` party lists on high-value choices
- `signatory` / observer assumptions that define who can see or act
- comparisons and branch conditions inside transfer, release, settlement, cancellation, or admin choices
- consuming vs non-consuming choice behavior when it changes asset or obligation lifetime

### Minimal campaign pattern

Use this only in a disposable clone or CI job built for authorized review.

```toml
# mewt.toml
files = ["daml/**/*.daml"]
test = "dpm test --show-coverage --coverage-ignore-choice Archive"
```

```bash
mewt run
```

For each surviving mutant, capture the diff and write the missing assertion as an abuse case:

- "seller can release funds without buyer confirmation"
- "operator can cancel a contract without the counterparty"
- "admin-only choice still succeeds when the controller is swapped"
- "coverage stays green after a required party is removed"

### Evidence boundaries

- Use synthetic parties, ledgers, contracts, and amounts.
- Do not run mutation campaigns against production ledgers or customer data.
- Do not treat every survivor as a vulnerability; first rule out equivalent mutants and unreachable guarded paths.
- Report the invariant the suite failed to enforce, not just the mutation score.

---

## Operational rule

If you are using code coverage as your main confidence signal for a security-critical system, treat that as a red flag.

Prefer:

- security property tests
- mutation testing
- regression tests tied to actual abuse cases
- review of surviving mutants in high-risk code paths

---

## Takeaway

Coverage says the code ran.

Mutation testing asks whether your tests would notice if it were broken.

For security work, that second question is the one that matters.
