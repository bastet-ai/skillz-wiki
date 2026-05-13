# P2P decompression resource boundary: Klever-Go MultiDataInterceptor

Source: GitHub Security Advisories updated 2026-05-13.

[Klever-Go GHSA-87m7-qffr-542v](https://github.com/advisories/GHSA-87m7-qffr-542v), CVE-2026-44697, documents a high-severity remote OOM in `github.com/klever-io/klever-go <= 1.7.16`. The issue is durable because it is the classic “compressed size passed the budget, inflated size pays the bill” failure in a public P2P path.

## What changed

`MultiDataInterceptor.ProcessReceivedMessage` can call `Batch.Decompress` on gossip payloads. The gzip decompression path used unbounded `io.ReadAll`, ignored the attacker-controlled `DataSize` hint during decompression, and only reached message-count antiflood checks after the inflated batch had already been allocated and unmarshaled.

The advisory PoC describes payloads in the tens of KiB range causing hundreds of MiB to multiple GiB of heap allocation. A single connected peer on a topic served by the interceptor can therefore OOM-kill validators or other nodes before peer reputation, count limits, or blacklist logic gets a meaningful chance to react.

No patched version was listed by GitHub at scan time; the advisory says a patch is being prepared and should ship with the adjacent `GHSA-74m6-4hjp-7226` fix.

## Operator triage

1. Track the Klever-Go release that supersedes `1.7.16` and includes both decompression-bomb and adjacent throttler-slot-leak fixes; upgrade validators as one coordinated maintenance window.
2. Until a patch lands, assume configuration-only mitigations are weak. Lowering per-peer byte budgets may reduce blast radius but does not stop a single lethal compressed payload on memory-constrained nodes.
3. Add memory alerts for rapid heap growth, OOM kills, process restarts, and gossip-topic spikes. Correlate by peer, topic, and compressed message size.
4. If operating validators, consider temporary peer allowlisting, tighter connection admission, and out-of-band restart playbooks for liveness preservation.
5. For forks or private patches, cap inflated bytes before `io.ReadAll` completes, validate declared/inflated size, cap `len(b.Data)` before slice preallocation, and reject compressed batches that exceed topic-specific limits.

## Durable controls

- Apply resource budgets to post-decompression size, object count, recursion depth, and final in-memory representation — not only to wire bytes.
- Use `io.LimitReader` or equivalent hard ceilings around every decompressor before reading into memory.
- Treat declared size fields as untrusted hints. Verify them against actual decompressed length and fail closed on mismatch.
- Run antiflood and quota checks before expensive parsing whenever possible, then repeat checks after transformations that expand attacker-controlled data.
- Regression tests should include high-ratio gzip bombs, valid-inner-object bombs, count-amplification payloads, and one-packet OOM simulations under realistic heap limits.
