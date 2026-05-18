# Avro map allocation resource boundary

Source: [GHSA-mx64-mj3q-7prj](https://github.com/advisories/GHSA-mx64-mj3q-7prj), updated 2026-05-18.

This is durable because the fix is not just a package upgrade. `github.com/iskorotkov/avro/v2` adds `Config.MaxMapAllocSize` in `v2.33.0`, but the default remains unlimited for compatibility. Any service that decodes Avro supplied by users, queues, partners, data lakes, or partially trusted internal producers needs an explicit map-entry budget.

## What changed

- Avro map block counts were attacker-controlled and used to grow destination maps without a per-block or cumulative cap.
- Chunking matters: many small Avro map blocks can bypass a naive per-block limit while still exhausting memory cumulatively.
- The affected paths include both string-keyed maps and maps whose keys implement `encoding.TextUnmarshaler`.
- `github.com/hamba/avro/v2` remains archived; use the maintained fork or isolate decoders when migration is blocked.

## Operator triage

1. Search Go services for `github.com/hamba/avro/v2`, `github.com/iskorotkov/avro/v2`, `NewDecoder`, `DefaultConfig`, and Avro decode paths reachable from external or multi-tenant data.
2. Upgrade to `github.com/iskorotkov/avro/v2 >= v2.33.0` where possible, but treat the upgrade as incomplete until `MaxMapAllocSize` is set.
3. Prefer a frozen, dedicated config for untrusted decode paths instead of mutating global defaults:

```go
cfg := avro.Config{
    MaxByteSliceSize:  102_400,
    MaxSliceAllocSize: 10_000,
    MaxMapAllocSize:   10_000,
}.Freeze()

decoder := cfg.NewDecoder(schema, reader)
```

4. Pick `MaxMapAllocSize` from schema expectations: largest legitimate map plus bounded headroom, not available host memory.
5. If migration is delayed, decode in memory-constrained workers/cgroups and reject untrusted Avro on high-privilege or shared control-plane processes.

## Durable controls

- Budget parser allocations by cumulative logical items, not just bytes or single chunks.
- Regression-test both single oversized blocks and many sub-limit blocks that exceed the cumulative limit.
- Avoid default decoder configs on trust boundaries; make resource caps part of the schema contract.
- Treat archived serialization libraries as migration risks even when forks publish compatibility fixes.
