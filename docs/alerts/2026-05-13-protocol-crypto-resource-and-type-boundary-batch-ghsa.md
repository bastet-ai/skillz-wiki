# Protocol, crypto, resource, and type-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because many of the failures are not classic injection bugs. They are missing parser budgets, protocol-state checks, cryptographic downgrade resistance, and type identity validation at boundaries that defenders may not monitor closely.

## Advisories covered

- **Anchor `InterfaceAccount` substitution** — [GHSA-429q-fhh4-r6hj](https://github.com/advisories/GHSA-429q-fhh4-r6hj): `InterfaceAccount` could allow account substitution between unexpected types in `anchor-lang 1.0.0-rc.1`.
- **Anchor `Program<'info, System>` validation gap** — [GHSA-c6rc-8jpp-2fgc](https://github.com/advisories/GHSA-c6rc-8jpp-2fgc): system-program validation was incomplete in `anchor-lang >=1.0.0,<1.0.2`.
- **wger uncontrolled resource consumption** — [GHSA-v25j-wqcw-fvhj](https://github.com/advisories/GHSA-v25j-wqcw-fvhj): affected `wger <=2.5` could consume excessive resources on crafted input.
- **go-billy symlink cycle/resource exhaustion** — [GHSA-m3xc-h892-ggx6](https://github.com/advisories/GHSA-m3xc-h892-ggx6): symlink resolution lacked depth and cycle detection before `go-billy/v5 5.9.0`.
- **ws many-header DoS** — [GHSA-3h5v-q93c-6h6q](https://github.com/advisories/GHSA-3h5v-q93c-6h6q): crafted requests with many HTTP headers could deny service across affected `ws` major versions.
- **HTTP/2 stream cancellation attack** — [GHSA-qppj-fm5r-hxr3](https://github.com/advisories/GHSA-qppj-fm5r-hxr3): repeated stream cancellation can exhaust server work in affected HTTP/2 implementations.
- **Terrapin prefix truncation attack** — [GHSA-45x7-px36-x8w8](https://github.com/advisories/GHSA-45x7-px36-x8w8): SSH implementations using ChaCha20-Poly1305 or Encrypt-then-MAC needed strict-kex style protections.
- **cryptography PKCS12 null-pointer DoS** — [GHSA-9v9h-cgj8-h64p](https://github.com/advisories/GHSA-9v9h-cgj8-h64p): malformed PKCS12 parsing could crash `cryptography` before `42.0.2`.

## Operator triage

1. Patch exposed websocket/HTTP/2 stacks, certificate importers, SSH clients/servers, Git-like filesystem walkers, and Solana Anchor programs.
2. Add or confirm edge budgets for request headers, HTTP/2 reset rates, symlink depth, directory traversal count, certificate parse time, and user-requested export/import sizes.
3. For Anchor programs, review account constraints and system-program checks; do not rely on nominal wrapper types without explicit owner/type validation.
4. Search telemetry for spikes in header count, stream resets, recursive symlink traversal, PKCS12 parse crashes, and failed SSH strict-key-exchange negotiation.

## Durable controls

- Resource limits belong at parse and protocol state boundaries, before expensive allocation or recursive resolution begins.
- Cryptographic protocol fixes require capability negotiation hardening; patching only application code will not stop prefix-truncation class attacks.
- Smart-contract and on-chain frameworks need explicit owner, discriminator, and program-ID checks even when the type system appears to encode the relationship.
- File abstraction layers should track visited inodes/paths plus maximum depth to prevent symlink loops from becoming availability failures.
