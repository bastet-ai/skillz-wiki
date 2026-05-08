# HTTP client, cache-key, and SSRF enforcement boundary batch

**Signal:** GitHub Security Advisories updated **2026-05-08**. Three durable issues landed in the same pattern family: security-critical request behavior must be enforced at the boundary that actually performs the network or cache action, not assumed from caller discipline or partial defaults.

## Advisories covered

- **Axios `mergeConfig` denial of service** — [GHSA-43fc-jf86-j433](https://github.com/advisories/GHSA-43fc-jf86-j433): `__proto__` as an own key can make `mergeConfig` resolve `mergeMap['__proto__']` through the prototype chain and crash with `TypeError: merge is not a function`. Affects npm `axios >= 1.0.0, <= 1.13.4` and `<= 0.30.2`; fixed in **1.13.5** and **0.30.3**.
- **Fiber cache middleware query-blind default key** — [GHSA-35hp-hqmv-8qg8](https://github.com/advisories/GHSA-35hp-hqmv-8qg8): default cache keys use only `c.Path()`, so `/?id=1` and `/?id=2` can share a cached response when handlers vary on query parameters. Affects Go `github.com/gofiber/fiber/v3 <= 3.1.0`; fixed in **3.2.0**.
- **Flowise SSRF protection bypass** — [GHSA-qqvm-66q4-vf5c](https://github.com/advisories/GHSA-qqvm-66q4-vf5c): Flowise added centralized HTTP SSRF checks, but multiple tools still call raw `node-fetch` or `axios` directly, bypassing deny-list, IP validation, IP pinning, and loopback blocking. Affects npm `flowise` and `flowise-components <= 3.0.13`; fixed in **3.1.0**.

Related already-covered updates in this scan:

- **Jupyter Server open redirect** — [GHSA-qh7q-6qm3-653w](https://github.com/advisories/GHSA-qh7q-6qm3-653w) remains covered in the Jupyter boundary batch.
- **Nginx-UI cluster proxy SSRF** — [GHSA-wr32-99hh-6f35](https://github.com/advisories/GHSA-wr32-99hh-6f35) remains covered in the Nginx-UI SSRF page.

## Why this is durable

All three issues are examples of **implicit boundary policy failing open**:

- Axios assumed an object-key lookup could safely select a merge function.
- Fiber assumed path-only cache keys were safe defaults even when handlers commonly depend on query parameters.
- Flowise assumed developers would route every outbound request through a wrapper instead of enforcing that policy globally.

The reusable lesson: dangerous defaults and optional wrappers are not controls. The last component before the state change — config merge, cache write/read, or outbound HTTP call — must enforce typed input, complete key material, and egress policy.

## Immediate triage

1. Upgrade Axios to a patched line. Prefer the newest available release in the application’s major line; this also keeps coverage for the broader Axios prototype-pollution and stream-limit batch.
2. Search for attacker-controlled objects passed into Axios request config, `getUri()`, request helpers, or wrapper libraries that merge user JSON into client config.
3. Upgrade Fiber v3 to **3.2.0+**. Until then, set a custom cache `KeyGenerator` that includes the canonical path plus every request component that affects the response: query, method when relevant, auth/tenant identity, content negotiation, locale, and feature flags.
4. Upgrade Flowise / `flowise-components` to **3.1.0+**. Treat any tool that performs URL fetches, web scraping, OpenAPI calls, MCP calls, or document retrieval as SSRF-capable until verified.
5. For Flowise and similar agent/tool platforms, inventory outbound-capable nodes and confirm they cannot reach loopback, link-local metadata, RFC1918 networks, Kubernetes APIs, Docker sockets/proxies, or internal admin panels unless explicitly allowed.

## Hunt ideas

- Axios: look for request failures with `TypeError: merge is not a function`, especially after handling user-supplied JSON containing `__proto__`, `constructor`, or prototype-shaped keys.
- Fiber: compare cache-hit logs where the path is identical but query strings differ; hunt for cross-user, cross-tenant, search-result, pagination, or object-ID response reuse.
- Flowise: review outbound network logs from Flowise containers for requests to internal address space, metadata IPs, localhost, private service names, or destinations not represented in approved tool configuration.
- In all three: add regression tests that encode the boundary mistake directly — own `__proto__` config keys, query-varying cached responses, and direct raw HTTP-client imports in tool code.

## Durable controls

- Normalize and schema-validate client config before merging; ignore inherited properties and reject prototype/meta keys in untrusted objects.
- Build cache keys from explicit response-vary dimensions, not from framework convenience methods alone.
- Put SSRF policy below the tool layer: global HTTP interceptors, egress proxy enforcement, container/network policy, and canonical DNS/IP checks after redirects.
- Make security wrappers hard to bypass: lint or CI-fail direct imports of raw HTTP clients in high-risk packages, and expose only a policy-enforcing fetch interface to plugins/tools.
- Treat cache middleware and HTTP clients as security primitives. They carry authority for data reuse and network reachability, so defaults need the same review as auth middleware.

## Operator lesson

Boundary policy that depends on every caller remembering the safe helper will eventually be bypassed. Enforce dangerous actions at the sink, test the weird keys and cache variants, and backstop outbound HTTP with network-level denial.
