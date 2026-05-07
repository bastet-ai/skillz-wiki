# Protocol, search, and runtime-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where parser differentials, search authorization, TLS verification, and runtime resource accounting crossed security boundaries.

## Advisories covered

- **Netty protocol parser boundary issues** — [GHSA-m4cv-j2px-7723](https://github.com/advisories/GHSA-m4cv-j2px-7723), [GHSA-cm33-6792-r9fm](https://github.com/advisories/GHSA-cm33-6792-r9fm), [GHSA-45q3-82m4-75jr](https://github.com/advisories/GHSA-45q3-82m4-75jr): request-smuggling, DNS codec validation, and proxy header-injection paths show that protocol parsers need canonical byte accounting and end-to-end validation.
- **OpenSearch TLS and authorization gaps** — [GHSA-x5hg-x4gv-j98m](https://github.com/advisories/GHSA-x5hg-x4gv-j98m), [GHSA-x83w-23jp-g6pw](https://github.com/advisories/GHSA-x83w-23jp-g6pw), [GHSA-22vx-2x23-98w6](https://github.com/advisories/GHSA-22vx-2x23-98w6), [GHSA-83x9-vc3c-hghc](https://github.com/advisories/GHSA-83x9-vc3c-hghc): hostname validation, document-level security, rollover authorization, and malformed-path checks must be enforced at every query and transport boundary.
- **Wasmtime host-address-space allocation panic** — [GHSA-p8xm-42r7-89xg](https://github.com/advisories/GHSA-p8xm-42r7-89xg): guest-controlled table sizing can exceed host assumptions and terminate the process.
- **Hono request and JSX input boundaries** — [GHSA-9vqf-7f2p-gf9v](https://github.com/advisories/GHSA-9vqf-7f2p-gf9v), [GHSA-69xw-7hcm-h432](https://github.com/advisories/GHSA-69xw-7hcm-h432): chunked body accounting and tag-name validation need to happen before dispatch or render.
- **diesel-async temporal padding exposure** — [GHSA-ff9q-rm55-q7qr](https://github.com/advisories/GHSA-ff9q-rm55-q7qr): database wire encoders must not leak uninitialized padding bytes.

## Why this is durable

Parser outputs, search filters, and runtime allocation requests are policy inputs. If different layers disagree about chunk sizes, DNS labels, URL paths, TLS names, or object ownership, attackers can route around the layer that was supposed to enforce the boundary.

## Immediate triage

1. Patch Netty, OpenSearch, Wasmtime, Hono, and diesel-async where present.
2. Place request-smuggling and malformed-path tests in front of every proxy pair that mixes Netty-based and non-Netty parsers.
3. Re-test OpenSearch DLS/FLS, rollover APIs, parent/child queries, and REST authorization with malformed paths and alternate index aliases.
4. Add hard caps and fail-closed behavior for guest/runtime allocation requests and chunked request bodies.
5. Treat renderer tag names, protocol header names, and database encoder structs as untrusted until normalized and bounds-checked.

## Durable controls

- Keep one canonical parser result per request and pass that object to auth, routing, logging, and backend forwarding.
- Enforce search authorization inside query execution and index-management helpers, not only at REST route entry.
- Require TLS verification tests that include hostname mismatch, custom trust roots, and proxy-forwarded cluster traffic.
- Zero-initialize serialized structs and fuzz encode/decode paths with memory-sanitizer builds where possible.
