# Image, DNS, and policy resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** parser/resource batch across image sampling, DNS message handling, and policy normalization.

## Advisories covered

- **imageproc kernel-size integer overflow** — [GHSA-w5p8-4jcx-2j6r](https://github.com/advisories/GHSA-w5p8-4jcx-2j6r): kernel-size checks could overflow and lead to out-of-bounds reads.
- **imageproc NaN-coordinate sampling issue** — [GHSA-qg8r-f7x3-25f7](https://github.com/advisories/GHSA-qg8r-f7x3-25f7): bilinear/bicubic samplers mishandled NaN coordinates and read outside expected bounds.
- **imageproc fragile image-sampling bounds check** — [GHSA-5qv7-j6w5-fr4m](https://github.com/advisories/GHSA-5qv7-j6w5-fr4m): sampling logic relied on insufficient bounds checks.
- **hickory-proto DNS name-compression CPU exhaustion** — [GHSA-q2qq-hmj6-3wpp](https://github.com/advisories/GHSA-q2qq-hmj6-3wpp): message encoding could degrade to quadratic work.
- **hickory-proto NSEC3 closest-encloser unbounded loop** — [GHSA-3v94-mw7p-v465](https://github.com/advisories/GHSA-3v94-mw7p-v465): cross-zone responses could trigger unbounded proof validation loops.
- **Apache Neethi policy-normalization algorithmic complexity** — [GHSA-g36m-9g3m-2vmp](https://github.com/advisories/GHSA-g36m-9g3m-2vmp): policy normalization could be driven into denial of service.
- **Apache Neethi circular policy references** — [GHSA-2hfh-9h53-qc24](https://github.com/advisories/GHSA-2hfh-9h53-qc24): circular policy definitions were not detected reliably.

## Why this is durable

Parsers fail when they trust input shape instead of enforcing computational budgets. Image coordinates, DNS proofs, compression pointers, and policy graphs all need explicit bounds, cycle checks, and maximum work limits.

## Immediate triage

1. Patch imageproc, hickory-proto, and Apache Neethi where reachable from untrusted media, DNS traffic, policy files, or federation inputs.
2. Add regression tests for integer overflow, NaN/Infinity coordinates, cross-zone NSEC3 proofs, cyclic references, and large nested policies.
3. Put CPU, memory, recursion, and wall-clock limits around image processing, DNS validation, and policy normalization jobs.
4. Watch for spikes in parser errors, request latency, worker restarts, and high-CPU loops after malformed image/DNS/policy inputs.

## Durable controls

- Use checked arithmetic for all derived sizes and reject non-finite numeric values before indexing or sampling.
- Track visited nodes/pointers/references and fail closed on cycles or repeated expansion.
- Bound compression, normalization, and validation work by input size; avoid algorithms that can become quadratic on attacker-controlled structure.
- Isolate expensive parsers in worker pools with per-job deadlines and backpressure.
