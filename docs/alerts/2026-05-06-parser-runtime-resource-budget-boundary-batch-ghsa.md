# Parser, runtime, and resource-budget boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced parser, runtime, dependency, and resource-budget issues updated on **2026-05-06**.

## Advisories covered

- **aiograpi vulnerable orjson dependency** — [GHSA-7mw3-79jq-xc7f](https://github.com/advisories/GHSA-7mw3-79jq-xc7f): dependency pinning carried CVE-2025-67221 exposure through orjson 3.11.4.
- **Grav duplicate and super-admin API advisories** — [GHSA-j7rw-325j-2rmx](https://github.com/advisories/GHSA-j7rw-325j-2rmx), [GHSA-6xx2-m8wv-756h](https://github.com/advisories/GHSA-6xx2-m8wv-756h): track duplicate insecure-deserialization noise and low-privileged API creation of super-admin accounts.
- **python-multipart header DoS** — [GHSA-pp6c-gr5w-3c5g](https://github.com/advisories/GHSA-pp6c-gr5w-3c5g): unbounded multipart part headers could consume resources.
- **rpassword interrupted-input partial reveal** — [GHSA-2p6r-x3vv-xqm2](https://github.com/advisories/GHSA-2p6r-x3vv-xqm2): terminal interruption paths could leak part of a password.
- **vLLM speculative-decoding crash** — [GHSA-83vm-p52w-f9pw](https://github.com/advisories/GHSA-83vm-p52w-f9pw): hidden-state extraction plus penalty parameters could crash the server.
- **Granian response-header and WebSocket panics** — [GHSA-f5p7-9fr5-8jmj](https://github.com/advisories/GHSA-f5p7-9fr5-8jmj), [GHSA-vrg7-482j-p6f6](https://github.com/advisories/GHSA-vrg7-482j-p6f6): malformed WSGI response headers and WebSocket subprotocol headers could trigger unauthenticated denial of service.
- **Rails Active Storage multi-range proxy DoS** — [GHSA-p9fm-f462-ggrg](https://github.com/advisories/GHSA-p9fm-f462-ggrg): proxy mode needed range-count and byte-budget limits.

## Why this is durable

Resource vulnerabilities cluster around code that assumes friendly shape: multipart headers, WebSocket subprotocols, range requests, model parameters, terminal interrupts, and dependency pins. Every parser and runtime bridge needs byte, count, time, and failure-mode budgets.

## Immediate triage

1. Patch affected runtimes and refresh vulnerable transitive dependency pins, especially JSON/parsing dependencies inherited through wrappers.
2. Put upload, range-request, WebSocket, and model-serving endpoints behind request-size, header-count, range-count, concurrency, and wall-clock limits.
3. Add malformed-header and multi-range regression tests to reverse proxies and application servers.
4. For password prompts, clear partial buffers and terminal state on interrupt before printing or returning errors.
5. Treat duplicate advisories as state updates, not new root causes; verify the original Grav deserialization controls remain covered.

## Durable controls

- Budget by structure, not just bytes: number of headers, ranges, parts, tokens, and nested parser states.
- Fail closed and quietly on interrupt/error paths that handle secrets.
- Keep parser dependencies on explicit security-patched floors and monitor transitive advisories.
- Crash-only model-serving failures should still be isolated from shared workers and restarted with abuse-rate signals.
