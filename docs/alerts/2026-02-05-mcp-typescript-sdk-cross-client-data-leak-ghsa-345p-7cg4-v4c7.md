# 2026-02-05 — @modelcontextprotocol/sdk cross-client data leak via shared server/transport reuse (GHSA-345p-7cg4-v4c7)

**Product:** **Model Context Protocol TypeScript SDK** (npm: `@modelcontextprotocol/sdk`)

## Impact (per advisory)
If a deployment **reuses the same server + transport instance across multiple concurrent clients**, JSON-RPC message ID collisions can cause **responses to be routed to the wrong client connection**.

Net effect: **cross-client response data leak** (Client A can receive Client B’s response data).

**Fixed:** **1.26.0**

## Recommended actions
- **Upgrade** to `@modelcontextprotocol/sdk` **1.26.0+**.
- Ensure your architecture creates:
  - **new server + transport per request** (stateless), or
  - **new server + transport per session** (stateful).

## Detection / review
- Grep for patterns where a singleton `McpServer`/`Server` is shared across all requests.
- Load-test with concurrent clients and verify responses cannot cross.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-345p-7cg4-v4c7>
