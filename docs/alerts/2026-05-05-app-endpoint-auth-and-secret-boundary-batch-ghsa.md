# App endpoint auth and secret-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because each issue comes from an exposed application endpoint doing more than its boundary contract promised: a diagnostic method path leaking process secrets, API routes missing authorization at method/function dispatch, SAML metadata fetch becoming authenticated SSRF, and MCP HTTP transport exposing privileged tools without authentication.

## Advisories covered

- **Inngest TypeScript SDK `inngest` >= 3.22.0, < 3.54.0** — [GHSA-2jf5-6wwv-vhxx](https://github.com/advisories/GHSA-2jf5-6wwv-vhxx): `serve()` endpoints reachable with unhandled HTTP methods such as `PATCH`, `OPTIONS`, or `DELETE` could return diagnostic data including `process.env`. Fixed in **3.54.0**.
- **CodeChecker <= 6.27.3** — [GHSA-4v9x-cqc5-j645](https://github.com/advisories/GHSA-4v9x-cqc5-j645): unauthenticated calls to selected `Authentication@...` API functions could read or mutate permissions, enabling arbitrary permission assignment to existing users. Patch available in **6.27.4**.
- **edx-enterprise >= 7.0.2, <= 7.0.4** — [GHSA-64cv-vxpr-j6vc](https://github.com/advisories/GHSA-64cv-vxpr-j6vc): Enterprise Admin users could set an arbitrary SAML metadata URL and trigger server-side fetch without scheme/IP filtering or timeout. Fixed in **7.0.5**.
- **Network-AI <= 5.1.2** — [GHSA-fj4g-2p96-q6m3](https://github.com/advisories/GHSA-fj4g-2p96-q6m3): MCP HTTP transport bound to `0.0.0.0` by default and accepted unauthenticated JSON-RPC `tools/call`, allowing privileged tool invocation. Fixed in **5.1.3**.
- **OpenClaw duplicate advisory** — [GHSA-qc5j-2mqx-x83q](https://github.com/advisories/GHSA-qc5j-2mqx-x83q) was withdrawn as a duplicate of GHSA-mr34-9552-qr95. Track the canonical advisory only; the affected range listed was `openclaw` >= 2026.4.7, < 2026.4.15.

## Operator triage

### Inngest secret exposure

1. Inventory public or partner-reachable `serve()` endpoints and confirm `inngest` version.
2. Upgrade to **3.54.0+**.
3. At the edge or framework router, allow only the intended methods (`GET`, `POST`, and `PUT` where required) and return a minimal 405 for everything else.
4. If the endpoint was reachable with `PATCH`, `OPTIONS`, or `DELETE`, assume environment variables may have been exposed. Rotate API keys, webhook secrets, database credentials, cloud tokens, signing keys, and any provider secrets present in the host process.
5. Hunt access logs for nonstandard methods against `/api/inngest`, `/inngest`, or framework-specific function routes.

### CodeChecker permission bypass

1. Upgrade to **6.27.4+** or isolate CodeChecker behind a trusted network boundary until patched.
2. Review logs for anonymous POSTs to `Authentication@getAuthorisedNames`, `Authentication@getPermissionsForUser`, `Authentication@hasPermission`, `Authentication@addPermission`, and `Authentication@removePermission`.
3. Audit current user permissions for unexpected grants, especially superuser-like roles or permissions added near suspicious anonymous requests.
4. Rotate tokens and rebuild trust assumptions for any account whose permissions may have been changed by an attacker.

### SAML metadata SSRF in edx-enterprise

1. Upgrade to **7.0.5+**.
2. Treat SAML metadata URLs as untrusted network input even when supplied by an admin role.
3. Hunt for `sync_provider_data` calls after recent `metadata_source` changes, especially URLs pointing to link-local, RFC1918, loopback, cloud metadata, Unix-socket bridge, or non-HTTPS schemes.
4. Add outbound allowlists for IdP metadata hosts and reject redirects to private or internal address space after DNS resolution.
5. Set tight timeouts and response-size limits for metadata fetches.

### MCP HTTP exposure in Network-AI

1. Upgrade to **5.1.3+** and ensure MCP HTTP endpoints require authentication, session binding, and origin checks.
2. Bind management transports to loopback by default; require an explicit operator decision for `0.0.0.0`.
3. Hunt for unauthenticated `tools/list` or `tools/call` requests, especially tool names related to config mutation, token creation/revocation, budget changes, agent dispatch, or credential access.
4. Rotate tokens or credentials that could have been minted, read, or invalidated through exposed tools.

## Durable controls

- Every HTTP method needs an explicit contract. Unknown methods should fail closed with no diagnostic body.
- Debug and diagnostic paths must never include process environment, headers containing secrets, or serialized runtime state.
- Authorization must be enforced at the final function dispatch point, not only by URL prefix, router group, or UI reachability.
- Treat admin-configurable fetch URLs as SSRF surfaces; apply scheme, host, DNS, redirect, IP-range, timeout, and size controls.
- MCP and agent tool transports are control planes. Default to localhost, authenticate every request, bind sessions to callers, and scope tools by least privilege.
- When duplicate/withdrawn advisories appear, record them as aliases but update guidance from the canonical advisory to avoid double-counting work.
