# Parser, cache, identity, and transport-auth boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-08 17:15 UTC** batch where small parser, cache, identity-provider, and transport-auth mistakes crossed security boundaries: encoded path segments bypassing directory policy, unbounded negotiation caches, LDAP filter injection, missing DTLS fingerprint validation, and registry token audience drift.

## Advisories covered

- **fast-uri percent-encoded dot-segment traversal** — [GHSA-q3j6-qgpj-74h6](https://github.com/advisories/GHSA-q3j6-qgpj-74h6): `fast-uri <= 3.1.0` accepted percent-encoded `.` / `..` segments in paths; patch to `3.1.1+`.
- **@fastify/accepts-serializer Accept-header cache DoS** — [GHSA-qxhc-wx3p-2wmg](https://github.com/advisories/GHSA-qxhc-wx3p-2wmg): `@fastify/accepts-serializer <= 6.0.3` could grow negotiation caches without bound; patch to `6.0.4+`.
- **ZITADEL LDAP filter injection in login flow** — [GHSA-rxvx-hhpj-q6px](https://github.com/advisories/GHSA-rxvx-hhpj-q6px): affected `github.com/zitadel/zitadel` 2.71.x, 3.x, and 4.x ranges; patch to the fixed tracks (`3.4.10+` or `4.15.0+` where applicable).
- **ex_webrtc client-role handshake missing DTLS peer-fingerprint validation** — [GHSA-qwfw-ggxw-577c](https://github.com/advisories/GHSA-qwfw-ggxw-577c): patch `ex_webrtc` to `0.15.1+` or `0.16.1+`.
- **MCP Registry OIDC audience replay across deployments** — [GHSA-95c3-6vvw-4mrq](https://github.com/advisories/GHSA-95c3-6vvw-4mrq): `github.com/modelcontextprotocol/registry < 1.7.6` used a shared GitHub OIDC audience; patch to `1.7.6+`.
- **MCP Registry protocol-relative open redirect** — [GHSA-v8vw-gw5j-w7m6](https://github.com/advisories/GHSA-v8vw-gw5j-w7m6): `github.com/modelcontextprotocol/registry >= 1.1.0, < 1.7.5`; patch to `1.7.5+`.

## Why this is durable

These are all **canonicalization and authority-binding bugs**. A path is checked before all encodings collapse; a cache key is attacker-chosen and unbudgeted; an LDAP query treats identity text as syntax; a media transport trusts the handshake role instead of the peer fingerprint; an OIDC token validates issuer but not deployment-specific audience; a redirect normalizes slashes after deciding the destination is local.

## Immediate triage

1. Search SBOMs for `fast-uri <= 3.1.0`, `@fastify/accepts-serializer <= 6.0.3`, affected `zitadel`, `ex_webrtc`, and `github.com/modelcontextprotocol/registry` versions.
2. For URL/path policy code, add tests with `%2e`, `%2e%2e`, mixed case encodings, encoded slash/backslash, double-encoding, and path normalization before allow/deny decisions.
3. For Fastify deployments, review request volume and memory graphs for high-cardinality `Accept` headers, especially unauthenticated routes.
4. For ZITADEL, hunt login attempts with LDAP metacharacters (`*`, `(`, `)`, `\`, NUL escapes) and unexpected directory search breadth.
5. For WebRTC and OIDC, verify logs include validated DTLS fingerprints and deployment-specific token audiences before accepting trust decisions.

## Durable controls

- Decode and normalize once at trust-boundary ingress, then run policy on canonical values; reject ambiguous or lossy encodings instead of repairing them later.
- Put explicit size, cardinality, and TTL limits on attacker-influenced caches; include cache eviction metrics and per-route budgets.
- Build LDAP, SQL, and filter syntax with typed escaping APIs, not string interpolation; log the escaped query class, not raw secrets.
- Bind real-time media sessions to expected peer fingerprints and fail closed when SDP/DTLS material changes mid-flow.
- Scope OIDC audiences per deployment/environment and reject issuer-only validation. Treat redirects as relative-path-only unless the origin is pre-registered.
