# Server Components, parser, and metrics resource-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because it shows the same reliability lesson across frontend frameworks, parsers, exporters, and game-protocol bindings: unauthenticated or low-trust input must hit explicit resource and exception boundaries before it reaches deserializers, formatters, or process-global callbacks.

## Advisories covered

- **React Server Components CPU/OOM denial of service**, [GHSA-rv78-f8rc-xrxh](https://github.com/advisories/GHSA-rv78-f8rc-xrxh): `react-server-dom-webpack`, `react-server-dom-parcel`, and `react-server-dom-turbopack` 19.0.0-19.0.5, 19.1.0-19.1.6, and 19.2.0-19.2.5 can spend excessive CPU or memory deserializing crafted Server Function requests.
- **Next.js App Router Server Components DoS**, [GHSA-8h8q-6873-q5fj](https://github.com/advisories/GHSA-8h8q-6873-q5fj): `next >=13.0.0,<15.5.16` and `>=16.0.0,<16.2.5` inherit the React Server Components Server Function denial-of-service issue.
- **@vitejs/plugin-rsc vendored RSC DoS**, [GHSA-w94c-4vhp-22gx](https://github.com/advisories/GHSA-w94c-4vhp-22gx): `@vitejs/plugin-rsc <=0.5.25` vendors vulnerable `react-server-dom-webpack`; upgrade to `0.5.26` or later.
- **oxidize-pdf public color variants bypass finite-number validation**, [GHSA-88q9-cmp2-c2vq](https://github.com/advisories/GHSA-88q9-cmp2-c2vq): Rust, .NET, and Python `oxidize-pdf` packages allow direct construction of `NaN`/`inf` color values that serialize invalid PDF tokens and cause downstream rejection or denial of service.
- **OpenTelemetry JS Prometheus exporter process crash**, [GHSA-q7rr-3cgh-j5r3](https://github.com/advisories/GHSA-q7rr-3cgh-j5r3): `@opentelemetry/exporter-prometheus <0.217.0`, `@opentelemetry/sdk-node <0.217.0`, and `@opentelemetry/auto-instrumentations-node <0.75.0` can crash on one malformed HTTP request to the built-in metrics server.
- **steamworks P2P auth callback panic**, [GHSA-g588-cjg3-6g78](https://github.com/advisories/GHSA-g588-cjg3-6g78): Rust `steamworks <0.13.1` panics when raw `ValidateAuthTicketResponse_t` carries `k_EAuthSessionResponseAuthTicketNetworkIdentityFailure`.

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

## November 11 follow-up: RSC transport DoS genealogy matures into unauthenticated RCE

The same `react-server-dom-*` transport deserializer that produced this page's May CPU/OOM entry now carries a **critical unauthenticated RCE**: [GHSA-xqc2-xf4c-x3h3 / CVE-2026-126187](https://github.com/advisories/GHSA-xqc2-xf4c-x3h3), affecting `react-server-dom-webpack`, `react-server-dom-parcel`, and `react-server-dom-turbopack` in 19.0.0-19.0.8, 19.1.0-19.1.9, 19.2.0-19.2.8, and 19.3.0; fixed in 19.0.9 / 19.1.10 / 19.2.9 / 19.3.1 via five coordinated PRs (#37842-#37846, "Improve transport protocol" across all four release lines). Vendor framing: crafted payloads targeting RSC-supporting frameworks reach RCE only "in extremely rare cases where responses transport multiple typed arrays and an attacker-controlled value", a precondition-gated bug, not a drive-by.

Operator rules:

- **DoS→RCE genealogy re-sweep:** every deserialization resource-boundary advisory on a transport protocol is a future memory-safety/RCE candidate on the same parser. Re-fuzz the *fixed* transport after each DoS patch, this exact surface went CPU/OOM (May, GHSA-rv78-f8rc-xrxh) to RCE (November) in six months.
- **Four-line fix-band fingerprinting:** four parallel maintenance lines each with its own patched point release means a single version string tells you which line a target runs; probe `/` for RSC flight markers (`$F`, `_$` call payloads, `multipart/form-data` Server Function POSTs) before assuming the transport is even mounted, "if an app does not use a framework/bundler plugin that supports RSC, it is not affected" makes the bundler plugin (`@vitejs/plugin-rsc`, Next, Parcel/Turbopack RSC plugins) the predicate, same as the vendored-package rule above.
- **Precondition-first triage:** "multiple typed arrays + attacker-controlled value in one response" is a response-shape precondition, enumerate endpoints whose Server Function/flight responses embed binary/typed-array payloads (upload previews, diff/patch endpoints, canvas/image pipelines) before investing; the rare-response hunt is the finding, not the generic RSC probe.
- **Fix-PR diff = replayable harness map:** the five PR diffs across release lines show exactly which transport decode paths were reworked; differential-test malformed typed-array framing against unpatched builds in a disposable app only. Keep proofs to local Next/RSC labs; do not target third-party sites without authorization.

