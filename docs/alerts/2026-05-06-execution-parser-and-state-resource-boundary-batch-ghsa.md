# Execution, parser, and state-resource boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced execution, parser, and state-consistency advisories updated on **2026-05-06** across Scramble, Apache Thrift, basic-ftp, and Mezo.

## Advisories covered

- **Scramble validation-rule RCE** — [GHSA-4rm2-28vj-fj39](https://github.com/advisories/GHSA-4rm2-28vj-fj39): user-controlled validation rules could be evaluated as code. Fixed in 0.13.22.
- **Apache Thrift Go TFramedTransport integer overflow** — [GHSA-wf45-q9ch-q8gh](https://github.com/advisories/GHSA-wf45-q9ch-q8gh): framed transport length handling could overflow/wrap. Fixed in 0.23.0.
- **Apache Thrift Node.js uncontrolled recursion** — [GHSA-r67j-r569-jrwp](https://github.com/advisories/GHSA-r67j-r569-jrwp): nested inputs could trigger recursion exhaustion. Fixed in 0.23.0.
- **basic-ftp unbounded multiline response buffering** — [GHSA-rpmf-866q-6p89](https://github.com/advisories/GHSA-rpmf-866q-6p89): a malicious FTP server could exhaust client memory with control-channel responses. Fixed in 5.3.1.
- **Mezo stale StateDB overwrite bridge drain** — [GHSA-6447-269v-g68m](https://github.com/advisories/GHSA-6447-269v-g68m): an ERC-20 bridgeOut burn could be erased by stale state, risking L1 bridge funds. Fixed in 8.0.0.

## Why this is durable

Code generation, RPC framing, protocol clients, and bridge state machines all parse attacker-influenced data into privileged actions. The reusable lesson is to avoid second-phase interpretation without resource budgets and transactional invariants.

## Immediate triage

1. Patch Scramble to 0.13.22, Apache Thrift to 0.23.0, basic-ftp to 5.3.1, and Mezo to 8.0.0 where present.
2. Search for API documentation generation, validation rule parsing, Thrift endpoints, FTP clients, and bridge/accounting components exposed to untrusted peers.
3. Hunt for validation rules containing executable syntax, oversized Thrift frames, deeply nested structs, long FTP multiline control responses, and bridge burn/mint inconsistencies.
4. Run parsers and protocol clients under size, recursion, frame-length, line-length, and total-buffer caps.
5. Reconcile bridge ledgers from independent sources before resuming deposits/withdrawals if stale writes are suspected.

## Durable controls

- Treat validation metadata and schema annotations as data; do not `eval` or execute generated expressions from untrusted projects.
- Parse framed protocols with checked integer arithmetic and fail-closed maximum lengths before allocation.
- Bound recursive decoders and multiline protocol responses by both per-item and aggregate limits.
- For financial state machines, make state transitions idempotent, monotonic, and reconciled before irreversible external settlement.
