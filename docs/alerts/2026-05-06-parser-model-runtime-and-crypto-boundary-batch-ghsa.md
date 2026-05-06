# Parser, model-runtime, and crypto-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-06** batch where parsers, ML model loaders, network transports, and cryptographic helpers failed to enforce resource or side-channel boundaries.

## Advisories covered

- **Netty epoll half-closed TCP DoS** — [GHSA-rwm7-x88c-3g2p](https://github.com/advisories/GHSA-rwm7-x88c-3g2p): RST handling on half-closed connections could terminate service availability.
- **Keras HDF5 shape-bomb DoS** — [GHSA-mgx6-5cf9-rr43](https://github.com/advisories/GHSA-mgx6-5cf9-rr43): malicious `.keras` / HDF5 model metadata could trigger petabyte-scale allocation in `KerasFileEditor`.
- **Nerdbank.MessagePack DateTime stack exhaustion** — [GHSA-2cwq-pwfr-wcw3](https://github.com/advisories/GHSA-2cwq-pwfr-wcw3): attacker-controlled decoding could drive `stackalloc` to a process-terminating `StackOverflowException`.
- **pyquorum timing side-channel** — [GHSA-7r92-3jgr-r65q](https://github.com/advisories/GHSA-7r92-3jgr-r65q): modular multiplication leaked timing information.
- **MediaMTX vulnerable dependency notice** — [GHSA-2ccx-cjjh-r2j8](https://github.com/advisories/GHSA-2ccx-cjjh-r2j8): dependency exposure still needs inventory and upgrade workflow, even when severity is low.

Withdrawn duplicate Keras metadata in this scan was treated as duplicate advisory bookkeeping; the canonical Keras shape-bomb guidance above remains the durable item.

## Why this is durable

Data formats and model files are executable in practice: they choose allocation sizes, recursion depth, parser states, transport state transitions, and sometimes cryptographic operation timing. Treat all attacker-supplied formats as programs constrained by budgets.

## Immediate triage

1. Patch affected libraries and runtime dependencies; prioritize externally supplied model files, message-pack payloads, and public network listeners.
2. Block untrusted `.keras` / HDF5 model inspection in production control planes until resource limits and patch levels are verified.
3. Add parser limits for declared dimensions, allocation size, stack allocation length, nesting depth, and total decode time.
4. Run network DoS regression tests for half-closed sockets, resets, idle connections, and protocol state-machine edges.
5. Review cryptographic helpers for data-dependent timing, especially when secrets or quorum shares influence arithmetic paths.

## Durable controls

- Enforce hard memory, CPU, recursion, and stack budgets at parser entrypoints, not only after object construction.
- Parse ML model metadata in a sandboxed worker with low memory, no secrets, and a killable lifecycle.
- Keep dependency advisories linked to SBOM inventory so low-severity transitive issues are not missed in exposed media services.
- Require constant-time primitives for secret-dependent cryptographic arithmetic and test for timing variance in CI.
