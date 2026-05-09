# MCP command and TLS resource-boundary batch

**Signal:** The **2026-05-09 01:15 UTC** scan added one critical MCP command-injection advisory and one Vert.x TLS resource-exhaustion advisory.

## Advisory cluster

- **`@profullstack/mcp-server` OS command injection in `domain_lookup`** — [GHSA-v6wj-c83f-v46x](https://github.com/advisories/GHSA-v6wj-c83f-v46x): `@profullstack/mcp-server <=1.4.12` allowed attacker-controlled input to reach OS command execution in the `domain_lookup` module. GitHub listed severity as critical and no patched version at scan time.
- **Vert.x unbounded SNI `SslContext` cache growth** — [GHSA-3g76-f9xq-8vp6](https://github.com/advisories/GHSA-3g76-f9xq-8vp6): `io.vertx:vertx-core` ranges `4.3.4-4.3.8`, `4.4.0-4.4.9`, `4.5.0-4.5.25`, and `5.0.0-5.0.8` could grow server-side SNI SSL context caches without bound, enabling denial of service. No patched version was listed at scan time.

## Why this matters

MCP servers often bridge natural-language tool calls to shell, DNS, cloud, and repository operations. A single shell-backed lookup tool can become remote command execution if it concatenates arguments. TLS handshakes are also attacker-controlled input; SNI values must be budgeted like request bodies or parser state.

## Triage

1. Remove or firewall `@profullstack/mcp-server` deployments until the `domain_lookup` implementation is patched or replaced with argument-vector APIs and strict domain validation.
2. Rotate credentials available to exposed MCP processes if an untrusted caller could invoke tools.
3. Hunt MCP logs for shell metacharacters, command separators, backticks, `$()`, redirection, unexpected DNS tooling output, and outbound connections spawned by lookup calls.
4. For affected Vert.x services, constrain accepted SNI names to configured tenants/domains and rate-limit handshakes per remote identity.
5. Add heap/cardinality telemetry for TLS context caches and alert on rapid unique-SNI growth.

## Durable controls

- Tool servers should not invoke shells for lookup helpers; use library APIs or `execve`/argument-vector calls with fixed binaries and validated inputs.
- MCP tools need per-tool allowlists, authentication, caller attribution, and explicit dangerous-operation review before exposing network or command capabilities.
- TLS SNI handling should be a bounded map keyed only by canonical, authorized hostnames with eviction and negative caching.
- Resource caches fed by unauthenticated handshakes need max cardinality, TTLs, rate limits, and rejection metrics.
