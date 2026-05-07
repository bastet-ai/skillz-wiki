# Zebra consensus and network resource-boundary batch

**Sources:** GHSA-cwfq-rfcr-8hmp, GHSA-gq4h-3grw-2rhv / CVE-2026-44497, GHSA-jv4h-j224-23cc / CVE-2026-44498, GHSA-438q-jx8f-cccv / CVE-2026-44500

## Why this matters

Zebra published a high-signal cluster of Zcash node bugs where small validation differences can become network splits or peer-driven resource exhaustion:

- V5 transparent `SIGHASH_SINGLE` handling accepted a missing-output digest that `zcashd` rejects.
- Invalid sighash-type handling could reuse a stale FFI buffer after a previous valid signature check.
- Block validation undercounted coinbase/P2SH transparent sigops against the 20,000-sigop block limit.
- Inbound deserializers preallocated against broad transport ceilings before enforcing tighter protocol/consensus limits.

The durable lesson: consensus clients need differential tests against the reference implementation for every edge case, and parser allocation must be charged before buffers are allocated.

## Affected surface

- `zebrad` before 4.4.0.
- `zebra-script` before 6.0.0 for the stale-buffer sighash issue.
- `zebra-network` before 6.0.0 and `zebra-chain` before 7.0.0 for allocation amplification paths.
- Miners, RPC `getblocktemplate` users, and infrastructure that trusts Zebra validation/template output without an independent `zcashd` comparison.

## Operator triage

1. Upgrade Zebra nodes and template producers to `zebrad` 4.4.0+ immediately.
2. Upgrade dependent crates (`zebra-script`, `zebra-network`, `zebra-chain`) where embedded or vendored.
3. Pause or cross-check Zebra-derived block templates until upgraded; compare candidate blocks/transactions with `zcashd` validation on a patched reference node.
4. Watch for malformed V5 transparent transactions, undefined sighash hash types, excessive sigops near block limits, and peers sending oversized `headers`, Equihash solution, Sapling spend vector, or coinbase script data.
5. Rate-limit and isolate peers that repeatedly trigger deserialization or validation rejects.

## Hunt prompts

- Zebra mempool entries rejected by `zcashd` for transparent signature or sighash errors.
- `getblocktemplate` outputs containing V5 transparent transactions with fewer outputs than input index requirements.
- Blocks rejected as `bad-blk-sigops` by `zcashd` but accepted or templated by Zebra.
- Peer sessions with high allocation/parse costs before protocol-limit rejection.

## Durable controls

- Maintain consensus-differential test corpora for malformed transactions, invalid flags, boundary counts, and historical bug fixtures.
- Treat FFI callback failure as a typed hard error; never let stale buffers or default values stand in for failed validation.
- Count resource and sigop budgets in exactly the same places as the reference implementation.
- Enforce protocol-specific length ceilings before allocation, not after parse.
- Use independent validation diversity for mining and critical chain infrastructure.
