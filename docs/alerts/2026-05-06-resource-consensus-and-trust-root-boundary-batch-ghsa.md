# Resource, consensus, and trust-root boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced high-impact parser/resource, consensus, and TLS trust-root issues updated on **2026-05-06** across Snappier, Zebra, and Harvester.

## Advisories covered

- **Snappier malformed framed-input infinite loop** — [GHSA-pggp-6c3x-2xmx](https://github.com/advisories/GHSA-pggp-6c3x-2xmx): malformed `SnappyStream` decompression input could trigger an infinite loop. Fixed in 1.3.1.
- **Zebra transparent sighash hash-type consensus divergence** — [GHSA-8m29-fpq5-89jj](https://github.com/advisories/GHSA-8m29-fpq5-89jj): transparent sighash handling could diverge from consensus rules. Fixed in `zebrad` 4.3.1 and `zebra-script` 5.0.2.
- **Harvester SUSE Virtualization Registration Client MITM/DoS** — [GHSA-pgh9-mpwc-8jjf](https://github.com/advisories/GHSA-pgh9-mpwc-8jjf): improper certificate validation exposed registration flows to MITM and denial-of-service risk. Fixed in Harvester 1.8.0.

## Why this is durable

A parser can become a CPU sink, a consensus client can split from the network with one spec mismatch, and a registration client can become attacker-controlled if TLS trust roots are soft. All three are boundary failures around input shape, protocol rules, and identity proof.

## Immediate triage

1. Patch Snappier to **1.3.1+**, Zebra components to **zebrad 4.3.1+ / zebra-script 5.0.2+**, and Harvester to **1.8.0+**.
2. Put decompression endpoints behind size, time, and cancellation budgets; alert on repeated malformed framed-input failures.
3. For Zebra operators, compare node versions, pause risky automation on unfixed validators, and monitor for consensus/reorg anomalies.
4. For Harvester, verify registration endpoints validate certificates against pinned or expected trust roots and fail closed.
5. Add differential tests against authoritative protocol vectors for compression, transaction hashing, and TLS registration flows.

## Durable controls

- Bound parser loops by bytes consumed, output produced, and wall-clock budget.
- Treat consensus-critical parsing as spec-conformance code with cross-implementation test vectors.
- Never let peer-supplied or registration-flow data define the trust root used to validate that same flow.
- Record version and patch provenance for infrastructure clients involved in cluster registration or control-plane enrollment.
