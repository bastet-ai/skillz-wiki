# vm2, XML builder, and routing resource-boundary batch

**Signal:** The **2026-05-08 17:15 UTC** advisory scan added another set of sandbox, builder, and routing/resource issues: two vm2 escapes fixed in `3.11.2`, XML comment/attribute filtering bypasses, and GoBGP parser/resource handling flaws.

## Advisories covered

- **vm2 null-prototype exception sandbox breakout** — [GHSA-9vg3-4rfj-wgcm](https://github.com/advisories/GHSA-9vg3-4rfj-wgcm): critical escape affecting `vm2 < 3.11.2`; patch to `3.11.2+`.
- **vm2 internal state exposure** — [GHSA-2cm2-m3w5-gp2f](https://github.com/advisories/GHSA-2cm2-m3w5-gp2f): `vm2 < 3.11.2` exposed `VM2_INTERNAL_STATE_DO_NOT_USE_OR_PROGRAM_WILL_FAIL`; patch to `3.11.2+`.
- **fast-xml-builder attribute quote filtering bypass** — [GHSA-5wm8-gmm8-39j9](https://github.com/advisories/GHSA-5wm8-gmm8-39j9): `fast-xml-builder <= 1.1.6`; patch to `1.1.7+`.
- **fast-xml-builder comment regex bypass** — [GHSA-45c6-75p6-83cc](https://github.com/advisories/GHSA-45c6-75p6-83cc): `fast-xml-builder == 1.1.5`; patch to `1.1.6+` or preferably current fixed versions.
- **GoBGP integer underflow** — [GHSA-hj4w-qr9j-c4cf](https://github.com/advisories/GHSA-hj4w-qr9j-c4cf): `github.com/osrg/gobgp/v4 < 4.4.0`; patch to `4.4.0+`.
- **GoBGP improper resource shutdown/release** — [GHSA-vm3g-8xwv-mxfp](https://github.com/advisories/GHSA-vm3g-8xwv-mxfp): `github.com/osrg/gobgp/v4 < 4.4.0`; patch to `4.4.0+`.

## Why this is durable

The shared theme is **representation smuggling plus missing containment**. JavaScript sandboxes are asked to contain language-level edge cases; XML builders try to filter syntax with regexes; routing daemons parse attacker-influenced protocol data in long-running control-plane processes. When those components fail, the blast radius is controlled by process isolation, output encoding, parser budgets, and control-plane segmentation.

## Immediate triage

1. Search lockfiles for `vm2 < 3.11.2`, `fast-xml-builder <= 1.1.6`, and `github.com/osrg/gobgp/v4 < 4.4.0`.
2. Patch vm2 and assess whether any workload used vm2 as a tenant boundary. If yes, assume escape and review host filesystem, env vars, process launches, and outbound connections.
3. For XML generation, hunt for user-controlled attribute/comment values containing quotes, encoded delimiters, XML comment terminators, namespace tricks, or sanitizer bypass probes.
4. For GoBGP, review BGP peer logs for malformed updates, session churn, unexpected resource growth, and crashes/restarts around the advisory window.
5. Add regression tests that compare builder output as parsed XML/HTML, not just as strings.

## Durable controls

- Replace in-process sandboxes with OS/process isolation for untrusted code; use vm2-style libraries only as defense-in-depth.
- Use XML/HTML builders that perform context-aware escaping by construction; do not rely on regex allow/deny filters for syntax-bearing values.
- Fuzz protocol parsers and builders with canonical malicious corpora, including unterminated comments, nested encodings, integer boundary values, and malformed route attributes.
- Put routing/control-plane components behind peer allowlists, rate limits, memory/CPU budgets, and automatic crash evidence capture.
- Treat generated XML/HTML as a security boundary: parse the generated artifact in tests and assert no unexpected attributes, comments, tags, or processing instructions appear.
