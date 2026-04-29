# Fuzzing Harnesses Must Initialize Runtime Coverage Before the Driver Starts

**Date**: 2026-04-29  
**Source**: Trail of Bits, *Extending Ruzzy with LibAFL*  
**Status**: Durable guidance

---

## Core lesson

Coverage-guided fuzzing is not only about the harness function. The runtime, linker, sanitizer, and module-load order all decide whether coverage maps exist when the fuzzing driver starts.

If the target code or instrumented extension is loaded lazily inside the test callback, some engines may start with no registered coverage maps. That can turn a valid harness into a false failure or a no-signal fuzzing campaign.

---

## Why this matters for security work

Fuzzing failures often get misread as target instability. In mixed-language targets, interpreter extensions, plugins, and dynamically loaded modules, the bug may instead be in the harness lifecycle:

- the instrumented shared object is loaded after `LLVMFuzzerRunDriver` starts
- coverage initialization hooks have not run yet
- the selected fuzzer runtime is stricter than the previous engine
- linker behavior differs between GNU `ld`, `lld`, and packaged sanitizer archives
- a compatibility layer behaves like libFuzzer at the API boundary but not at runtime

For audits, that means a clean-looking fuzzing setup can silently provide weak evidence unless startup and coverage registration are validated.

---

## Practical guidance

When adapting a harness to a new fuzzing engine, explicitly verify the runtime path before trusting results.

### Check initialization order

Load instrumented modules before invoking the fuzzing driver:

```text
load target / extension / plugin
verify sanitizer coverage maps exist
start fuzzing driver
call target callback from fuzz loop
```

Avoid placing critical `require`, `dlopen`, plugin import, or extension-load steps only inside the fuzz callback unless the engine is known to accept late coverage registration.

### Treat engine swaps as semantic changes

A compatibility layer can preserve the function names while changing assumptions. Re-check:

- coverage-map registration timing
- sanitizer runtime selection
- archive contents such as `.init_array` and `.preinit_array`
- linker selection and flags
- crash output fidelity
- corpus and coverage growth after startup

### Validate with a known bug

Before fuzzing the real target, run the harness against a tiny intentional bug. The campaign should:

- start without runtime panics
- register non-zero coverage
- increase coverage or corpus state as inputs mutate
- find the seeded crash with useful sanitizer output

If it cannot find the toy bug, do not trust negative results from the real target.

---

## Operator checklist

Use this when bringing fuzzing into an authorized assessment or code audit:

- [ ] Build with the intended sanitizer and fuzzer runtime, not a local fallback.
- [ ] Record compiler, linker, sanitizer, runtime, and architecture versions.
- [ ] Confirm instrumented code is loaded before the driver starts.
- [ ] Confirm coverage maps/counters are non-empty at startup.
- [ ] Run a seeded-crash smoke test.
- [ ] Preserve the exact build container or script for replay.
- [ ] Include runtime failures in findings only after ruling out harness lifecycle bugs.

---

## Takeaway

A fuzzer that starts is not necessarily a fuzzer that sees.

For security evidence, prove the harness initializes coverage, exercises the target, and catches a known bug before relying on campaign results.
