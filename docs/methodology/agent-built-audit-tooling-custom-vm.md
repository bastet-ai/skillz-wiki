# Agent-built audit tooling for custom VMs and DSLs

**Date**: 2026-09-18

**Sources**: Trail of Bits, [*Auditing in the age of (good enough) AI*](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/) (Miden zkVM core-library review write-up)

**Status**: Durable offensive operator workflow (authorized source review / exploit research)

---

## Core lesson

When a target is a **custom instruction set, DSL, or VM with no existing tooling**, the highest-leverage prep work is to have coding agents *build the missing tools* — LSP, decompiler, static analyzer, formal model — before hand-review starts. The ToB Miden engagement spent six months of agent-driven side-project time and it produced the finding: an unvalidated prover-supplied input in `mod_12289` that let a malicious prover forge Falcon signatures and drain Miden accounts, plus 400+ reachable type-validation gaps and two subtle arithmetic bugs the unit tests never caught.

The economics changed: a failed tooling side project now costs tokens, not billable months. For an authorized review of novel bytecode/assembly (zkVMs, smart-contract VMs, eBPF dialects, embedded DSLs, game/script VMs, proprietary bytecode formats), treat "no IDE, no linter, no decompiler" as a signal that **tool-building will out-pay blind reading**.

---

## Why stack machines are hard to review (and worth tooling)

The Miden VM is a stack machine in a custom assembly (MASM):

- Instruction inputs/outputs are implicit stack slots — data flow is invisible to the reader.
- Procedures have no declared signatures; input/output counts must be inferred from context.
- No stable calling convention; net stack effect of a call is statically undecidable in general.
- `while` loops need not be stack-neutral (loop condition can occupy a different slot each iteration), and branches can have different stack effects.

Every one of those is a reason manual review misses a missing validation, and a reason a **partial but correct decompiler over a well-defined subset** is still valuable: the reusable asset is the intermediate representation and analysis framework, not the full decompilation coverage.

---

## The tooling ladder (agent-executable)

1. **LSP server + editor extension first.** Syntax highlighting, goto-definition, references, hover docstrings, and *inline stack effects / instruction docs* remove the context-switch cost that kills stack-machine review. A working prototype was agent-built in days.
2. **Decompiler to an IR.** Accept partial coverage; focus on correctly decompiling a well-defined subset. Add regression tests by having agents decompile randomized real-world procedures and diff against source. The IR (instruction inputs/outputs as expressions) is what unlocks step 3.
3. **Abstract-interpretation engine over the IR.** Track per-stack-slot value types ("u32", "bool", "unknown") to fixpoint, then write targeted analysis passes:
   - Are **untrusted, externally supplied witness/advice values validated**?
   - Are declared type constraints (32-bit limb, boolean) actually enforced at every use?
   - Are locals initialized on every execution path?
   Expose the analyzer and a linter as **CLIs** so agent-driven code-review harnesses can call them too.
4. **Formal model as a bug oracle.** Build a minimal executor in a proof assistant (Lean), auto-translate procedures to specs of the form "stack `[x1..xn,...]` + procedure `P` ⇒ terminates, stack `[P(x1..xn),...]`", then run agents in parallel proving correctness. The proof assistant kernel validates proofs, so humans only audit the **theorem statements**. Two high-value byproducts:
   - A proof that **won't go through** exposes a missing precondition that is often a real edge-case bug (Miden `rotr` misbehaves on inputs > the Goldilocks prime when shift is a multiple of 32; the needed `shift mod 32 ≠ 0` assumption *was* the bug).
   - Proving the spec reveals contract violations invisible to unit tests (`wrapping_mul` dropped caller-owned stack values).
5. **Alternate dev/review agents.** Use one agent to build, a second to review each feature; every decompiler/analysis regression found becomes a test the first agent must fix.

---

## The reusable vuln pattern: paired witnesses constrained only by reconstruction

`mod_12289` takes prover-supplied advice values (quotient, remainder). The **quotient** was range-checked as two valid u32 limbs; the **remainder** was never validated before being consumed by `u32overflowing_sub`. Because the only binding constraint ties the pair together through the subtraction/reconstruction equation, an attacker can vary quotient and remainder together — staying inside the joint constraint — and make the gadget **return a value that is not the correct remainder**. Chained up, a malicious prover forges Falcon signatures and drains any account controlled by a Falcon key pair.

Generalized audit rule:

> **Every operand an untrusted party supplies must be range/width-validated against its own declared domain — not implicitly via the equation that couples it to a validated partner.** A single joint constraint (checksum, reconstruction identity, length+body hash, key+IV pairing, offset+size span) lets the supplier trade slack between the coupled fields.

Sweep this anywhere witnesses cross a verify boundary: zkVM advice/aux stacks, proof-system gadgets, client-supplied (length, checksum) or (offset, size) pairs, file-format header fields cross-validated only against each other, distributed-computation verifiers. In the Miden case the analyzer's "is this advice value validated?" pass located it; 400+ improvement sites were all reachable from the public API because nearly every core procedure was callable by third-party code — treat **public-API-reachability of under-validated primitive procedures** as its own finding class.

---

## Operational notes

- Authorized targets only: your own codebases, authorized reviews, labs, or open source. For zk/chain targets, prove impact on testnets or synthetic deployments with throwaway key pairs — never forge live signatures, drain real accounts, or touch mainnet state.
- Keep every artifact replayable: agent commits, IR dumps, analysis pass configs, failing-proof records with the missing assumption, minimized reproducers.
- The proof-assistant route pays best on small instruction sets with mostly side-effect-free operations (Miden was explicitly amenable); skip it for targets with heavy external state.
- Separate confirmed behavior from inference: ToB reports the high-severity prover-forge path and the two formal-model bugs; the 400+ sites were "type validation could be improved," not proven vulns.

---

## See also

- [Agent-guided fuzzing campaigns](agent-guided-fuzzing-campaigns.md) — the dynamic-analysis sibling of this static/formal prep workflow.
- [Agentic DAST benchmark validation](agentic-dast-benchmark-validation.md) — how to judge agent-run campaigns honestly.
- [Replayable target environment design](target-environment-harness-design.md) — harness discipline the same evidence rules apply to.
