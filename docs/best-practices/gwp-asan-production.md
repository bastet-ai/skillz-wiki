# GWP-ASan in Production (Low-overhead memory bug detection)

## When to use this
Use **GWP-ASan / allocation-sampling sanitizers** when you want *production* detection of:
- heap use-after-free
- double free
- heap buffer over/underflow

…without ASan’s heavy overhead.

## Why it helps
Traditional ASan is great in CI but too slow (and can change security properties) for production. GWP-ASan instruments only a **small sampled fraction of allocations**, putting them behind **guard pages**, so rare bugs still get caught at scale.

## Practical deployment patterns
- **Enable by default in canary / staged rollouts**, then expand.
- **Tune sampling** based on crash volume:
  - start low (e.g., 1 per 100k–1M allocations)
  - increase temporarily during incident response or hardening
- **Keep symbolization workable**:
  - ship build IDs / symbols to your crash pipeline
  - ensure stack traces are actionable

## LLVM/Scudo quick-start (example)
- Build with Clang using Scudo:
  - `-fsanitize=scudo` (optionally `-fsanitize=scudo,undefined`)
- Configure at runtime (env var):
  - `SCUDO_OPTIONS="GWP_ASAN_SampleRate=1000000:GWP_ASAN_MaxSimultaneousAllocations=128" ./app`

## Operational notes
- Expect **non-determinism**: a bug only triggers when the allocation is sampled.
  - run in loops / rely on fleet scale
- Treat crashes as **high-signal**: even a single hit can indicate real exploitability.

## References
- Trail of Bits: "Use GWP-ASan to detect exploits in production environments" (2025-12-16)
