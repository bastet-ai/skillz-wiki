# Protocol, parser, and resource-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because protocol parsers and native/runtime libraries failed at state-machine, bounds, or resource-budget boundaries. The reusable lesson is to treat every peer response, archive/media file, database string literal, and consensus object as hostile even when the surrounding application is authenticated.

## Advisories covered

- **net-imap protocol state/resource issues** — [GHSA-vcgp-9326-pqcp](https://github.com/advisories/GHSA-vcgp-9326-pqcp), [GHSA-hm49-wcqc-g2xg](https://github.com/advisories/GHSA-hm49-wcqc-g2xg), [GHSA-75xq-5h9v-w6px](https://github.com/advisories/GHSA-75xq-5h9v-w6px), [GHSA-87pf-fpwv-p7m7](https://github.com/advisories/GHSA-87pf-fpwv-p7m7), [GHSA-q2mw-fvj9-vvcw](https://github.com/advisories/GHSA-q2mw-fvj9-vvcw): STARTTLS stripping, CRLF/command injection, expensive SCRAM iteration DoS, and quadratic literal parsing. Fixed in the `0.6.4`, `0.5.14`, `0.4.24`, and `0.3.10` lines as applicable.
- **Pillow parser memory-safety/resource issues** — [GHSA-pwv6-vv43-88gr](https://github.com/advisories/GHSA-pwv6-vv43-88gr), [GHSA-r73j-pqj5-w3x7](https://github.com/advisories/GHSA-r73j-pqj5-w3x7), [GHSA-wjx4-4jcj-g98j](https://github.com/advisories/GHSA-wjx4-4jcj-g98j), [GHSA-5xmw-vc9v-4wf2](https://github.com/advisories/GHSA-5xmw-vc9v-4wf2): PSD tile integer overflow/OOB write, PDF trailer infinite loop, font integer overflow, and nested coordinate heap overflow. Fixed in `12.2.0`.
- **russh keyboard-interactive pre-auth DoS** — [GHSA-f5v4-2wr6-hqmg](https://github.com/advisories/GHSA-f5v4-2wr6-hqmg): unbounded allocation before authentication. Fixed in `0.60.1`.
- **OpenMcdf CFB directory-cycle DoS** — [GHSA-jxpf-xq2m-q525](https://github.com/advisories/GHSA-jxpf-xq2m-q525): crafted compound-file directory cycles could loop indefinitely. Fixed in `3.1.3`.
- **liquidjs circular layout DoS** — [GHSA-4rc3-7j7w-m548](https://github.com/advisories/GHSA-4rc3-7j7w-m548): recursive block references could exhaust runtime. Fixed in `10.25.7`.
- **Grid integer overflow** — [GHSA-38c5-483c-4qqp](https://github.com/advisories/GHSA-38c5-483c-4qqp): `expand_rows` overflow could produce safe-API undefined behavior. Fixed in `1.0.1`.
- **Zebra consensus/signature accounting** — [GHSA-gq4h-3grw-2rhv](https://github.com/advisories/GHSA-gq4h-3grw-2rhv), [GHSA-jv4h-j224-23cc](https://github.com/advisories/GHSA-jv4h-j224-23cc): transparent sighash stale-buffer divergence and sigop undercounting. Fixed in `zebrad 4.4.0` / `zebra-script 6.0.0`.
- **pgx placeholder confusion** — [GHSA-j88v-2chj-qfwx](https://github.com/advisories/GHSA-j88v-2chj-qfwx): dollar-quoted string literal placeholder confusion could enable SQL injection. Fixed in `pgx/v5 5.9.2`; older lines need migration/compensating controls.

## Operator triage

1. Patch libraries that parse untrusted email, images, PDFs, Office/CFB files, SSH handshakes, templates, SQL text, and consensus/blockchain data.
2. Add CPU, memory, file-size, recursion-depth, and wall-clock limits around parsing even after patching.
3. For STARTTLS/protocol state issues, verify fail-closed transitions with a malicious peer harness; do not rely only on happy-path integration tests.
4. For consensus clients, upgrade all validators/miners/nodes together enough to avoid network splits and monitor fork/divergence telemetry.

## Durable controls

- Protocol parsers should model state transitions explicitly and reject unexpected responses before mutating security state.
- Resource budgets belong at every parser boundary: bytes read, object count, recursion, iterations, and output expansion ratio.
- Native and “safe language” libraries still need integer-overflow tests around dimensions, offsets, counts, and multiplication.
- Query builders must parse placeholders with the same grammar as the database engine; ad-hoc scanning around comments/strings is not enough.
