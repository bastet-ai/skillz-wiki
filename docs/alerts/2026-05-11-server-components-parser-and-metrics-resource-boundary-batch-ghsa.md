# Server Components, parser, and metrics resource-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because it shows the same reliability lesson across frontend frameworks, parsers, exporters, and game-protocol bindings: unauthenticated or low-trust input must hit explicit resource and exception boundaries before it reaches deserializers, formatters, or process-global callbacks.

## Advisories covered

- **React Server Components CPU/OOM denial of service** — [GHSA-rv78-f8rc-xrxh](https://github.com/advisories/GHSA-rv78-f8rc-xrxh): `react-server-dom-webpack`, `react-server-dom-parcel`, and `react-server-dom-turbopack` 19.0.0-19.0.5, 19.1.0-19.1.6, and 19.2.0-19.2.5 can spend excessive CPU or memory deserializing crafted Server Function requests.
- **Next.js App Router Server Components DoS** — [GHSA-8h8q-6873-q5fj](https://github.com/advisories/GHSA-8h8q-6873-q5fj): `next >=13.0.0,<15.5.16` and `>=16.0.0,<16.2.5` inherit the React Server Components Server Function denial-of-service issue.
- **@vitejs/plugin-rsc vendored RSC DoS** — [GHSA-w94c-4vhp-22gx](https://github.com/advisories/GHSA-w94c-4vhp-22gx): `@vitejs/plugin-rsc <=0.5.25` vendors vulnerable `react-server-dom-webpack`; upgrade to `0.5.26` or later.
- **oxidize-pdf public color variants bypass finite-number validation** — [GHSA-88q9-cmp2-c2vq](https://github.com/advisories/GHSA-88q9-cmp2-c2vq): Rust, .NET, and Python `oxidize-pdf` packages allow direct construction of `NaN`/`inf` color values that serialize invalid PDF tokens and cause downstream rejection or denial of service.
- **OpenTelemetry JS Prometheus exporter process crash** — [GHSA-q7rr-3cgh-j5r3](https://github.com/advisories/GHSA-q7rr-3cgh-j5r3): `@opentelemetry/exporter-prometheus <0.217.0`, `@opentelemetry/sdk-node <0.217.0`, and `@opentelemetry/auto-instrumentations-node <0.75.0` can crash on one malformed HTTP request to the built-in metrics server.
- **steamworks P2P auth callback panic** — [GHSA-g588-cjg3-6g78](https://github.com/advisories/GHSA-g588-cjg3-6g78): Rust `steamworks <0.13.1` panics when raw `ValidateAuthTicketResponse_t` carries `k_EAuthSessionResponseAuthTicketNetworkIdentityFailure`.

## Operator triage

1. Prioritize public Next.js App Router and React Server Components Server Function endpoints; patch framework and vendored RSC packages together.
2. Add temporary rate limits and request-body ceilings on Server Function endpoints until all runtimes are fixed.
3. Inventory metrics endpoints exposed on `0.0.0.0:9464` or through sidecar/service discovery; block public access and patch exporter packages.
4. Treat PDF and media-generation APIs as parser/resource sinks: fuzz non-finite numeric values and verify that invalid objects are rejected before serialization.
5. For game servers and other callback-heavy protocol libraries, wrap callbacks so unexpected enum variants fail closed without panicking the process.

## Durable controls

- Deserializers for server-call protocols need depth, size, CPU, and allocation budgets before invoking application logic.
- Framework patching must include transitive vendored packages; a fixed app shell can still be vulnerable through a bundled RSC implementation.
- Public constructors should enforce the same invariants as helper constructors, or serialization must revalidate all public-state fields.
- Metrics and health endpoints are production attack surfaces; parse errors should produce bounded HTTP errors, not uncaught process exceptions.
- Callback bridges to native or platform APIs need exhaustive handling for unknown, rare, and failure-status values.

