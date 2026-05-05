# C/C++ Review Must Model API Footguns and Type Contracts

**Date**: 2026-05-05  
**Source**: Trail of Bits, *C/C++ checklist challenges, solved*  
**Status**: Durable guidance

---

## Core lesson

C/C++ security review needs a checklist that includes API-specific traps, not just generic sink searches.

Two patterns from the Trail of Bits challenge are worth keeping in every native-code review:

- parsing APIs may accept inputs that later consumers treat differently
- APIs that write into caller-provided storage may require explicit type and size contracts

If the review only asks “is there validation before the dangerous call?”, it can miss the bug. Ask whether the same representation, lifetime, and type contract survives from validation to use.

---

## Pattern 1: parser/formatter representation drift

Watch for input that is validated in one representation, then used later in another representation.

Examples to explicitly check:

- IPv4 parsing with legacy forms, trailing characters, or undocumented acceptance rules
- normalized address strings returned through static/global buffers
- path or URL parsing where the allowlist check and sink use different decoders
- values compared after a helper call that may overwrite shared static storage

Review prompts:

- Does the parser consume the entire input, or can trailing garbage survive?
- Does the formatter return owned storage, caller-provided storage, or a static buffer?
- Are two compared pointers actually independent strings?
- Is the exact validated value the one passed to the sink?

Safer pattern: parse once, require full consumption, store the canonical value in caller-owned storage, and pass only the canonical value downstream.

---

## Pattern 2: direct writes without type contracts

When an API writes directly into caller-provided memory, the review must prove that the source type and destination size match.

High-risk signs:

- flags that switch an API into “direct” output mode
- output pointers hidden in generic fields such as `void *`, `EntryContext`, or callback contexts
- destination variables on the stack with no explicit size given to the API
- expected type implied by naming instead of enforced by flags or schema
- user-controlled paths, keys, records, or configuration objects that select what gets read

Review prompts:

- Who controls the source object being read?
- Is the expected source type enforced, or only assumed?
- Does the API know the destination buffer size?
- What happens if the source is a wider integer, string, binary blob, or nested object?
- Does platform documentation require an additional type-check flag or mode?

Safer pattern: enforce type checks at the API boundary, validate source location/authorization, and copy into sized structures only after confirming the actual type and length.

---

## Native-code review checklist

Use this as a compact pass when auditing C/C++ code:

1. Map untrusted inputs to parser calls.
2. Check whether parsers allow alternate forms, partial consumption, or trailing data.
3. Track the canonical value, not the original variable name.
4. Flag static/global-buffer return APIs used across multiple calls.
5. Find APIs that write into caller-provided memory.
6. Verify explicit type, length, and ownership contracts for every direct write.
7. For kernel/driver code, treat caller-selected registry, filesystem, object-manager, or device paths as trust-boundary inputs.
8. Build negative tests that vary representation and type, not just length.

---

## Test ideas

For parser drift:

- valid prefix plus trailing junk
- alternate numeric notation
- encoded delimiters
- repeated parser calls before comparison
- canonicalized value differs from original input

For direct-write APIs:

- expected integer replaced with wider integer
- string/blob where scalar is expected
- oversized value with small stack destination
- attacker-controlled source path in a trusted namespace
- missing platform-required type-check flag

Keep tests low-impact and version-pinned. For driver or kernel targets, reproduce in a disposable VM with crash dumps enabled.

---

## References

- Trail of Bits: <https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/>
- Trail of Bits C/C++ Testing Handbook: <https://appsec.guide/docs/native/c-cpp/>
