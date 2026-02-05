# OAuth Misconfig Patterns in MCP / Agent Integrations

As agent ecosystems and “Model Context Protocol” (MCP)-style integrations grow, OAuth is showing up in lots of places written by teams who aren’t OAuth specialists.

This page documents *high-leverage misconfigurations* that lead to one-click account takeover.

## The dangerous combo

The most common catastrophic combo is:

- **Open Dynamic Client Registration (DCR)**
- **Weak redirect URI validation**
- **PKCE not mandatory** (or not validated)

Result: attacker registers a client, sets a redirect URI they control, and hijacks the victim’s OAuth authorization.

## What to look for

### Dynamic Client Registration (DCR)
DCR endpoints are often exposed as:
- `/.well-known/openid-configuration`
- `/oauth/register` / `/connect/register`

**Tests:**
- Can anyone create a client without authentication?
- Can the attacker specify:
  - redirect URIs
  - grant types
  - response types
  - token auth methods

### Redirect URI validation weaknesses
Common mistakes:
- substring matching (`evil.com` contains `vil.com`)
- allowing `http://` in production
- wildcard domains (`*.example.com`) without strict subdomain control
- allowing arbitrary query params that enable secondary redirects

**Tests:**
- Attempt redirect URIs like:
  - `https://trusted.example.com.evil.com/callback`
  - `https://evil.com/?next=https://trusted.example.com/callback`
  - `https://trusted.example.com@evil.com/callback`

### PKCE
PKCE must be:
- required for public clients
- verified server-side (`code_verifier` → `code_challenge`)

**Tests:**
- Can you complete a code exchange without PKCE?
- Is PKCE accepted but not validated (always succeeds)?

## Practical discovery tips

- Look for MCP servers or agent gateways exposing OAuth metadata.
- Check for “dev” deployments with permissive configs.
- Look for documentation or SDK defaults that enable DCR.

## What to recommend

- Disable open DCR unless you explicitly need it.
- If you need DCR, require authenticated registration + policy checks.
- Enforce exact-match redirect URIs.
- Require PKCE, validate `state`, and pin issuer/audience.

## Also watch for: cross-client data leakage in MCP server deployments

Even with “correct” auth, MCP deployments can leak data **between clients** if the server/transport objects are shared incorrectly.

### Misconfiguration pattern
- A single shared `McpServer`/`Server` instance is reused across multiple concurrent client connections.
- In stateless Streamable HTTP mode, this often looks like “create one server globally and call `handleRequest()` for every request”.

### Why it’s dangerous
- JSON-RPC message IDs can collide across clients.
- Responses can be routed to the wrong client connection.
- Result: Client A receives response data intended for Client B (cross-tenant data leak).

### Recommendation
- **Stateless mode:** create a **fresh server + transport per request**.
- **Stateful mode:** create a **fresh server + transport per session**; do not share instances across sessions.
- Upgrade the TypeScript SDK to a patched version that throws loudly on unsafe reuse.

Reference:
- https://github.com/advisories/GHSA-345p-7cg4-v4c7

## Source / inspiration

- Inspired by research on OAuth misconfigurations in MCP-like systems (open DCR + weak redirect + missing PKCE → one-click ATO).
