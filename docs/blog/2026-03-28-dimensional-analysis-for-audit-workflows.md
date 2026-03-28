---
title: Dimensional Analysis for Audit Workflows
---

# Dimensional Analysis for Audit Workflows

Trail of Bits released a Claude plugin that treats numeric reasoning as something you can annotate and verify mechanically instead of trusting an LLM’s judgment alone.

## Durable takeaway

For security reviews of arithmetic-heavy code, don’t rely only on natural-language findings. Build a small, explicit unit vocabulary and carry it through the codebase so mismatches become obvious.

## Practical pattern

- identify the base units used by the system
- annotate state, arguments, and arithmetic with those units
- propagate annotations across callers and callees
- flag mismatches for triage before human review

## Why it matters

This is especially useful for protocol math, pricing logic, vault accounting, and other code where a correct-looking expression can still be dimensionally wrong.

## Operational lesson

If your audit pipeline uses an LLM to review numeric logic, pair it with a validation layer that checks invariants mechanically. Use the model to help classify and annotate; use code to decide whether the math actually lines up.
