# 2026-02-04 — `@modelcontextprotocol/sdk` cross-client data leak via shared server instance reuse (GHSA-345p-7cg4-v4c7)

**Product:** `@modelcontextprotocol/sdk` (Model Context Protocol SDK)

**Impact (per advisory):** A server/transport instance reused across multiple clients can cause **cross-client data exposure** (data intended for one client could be received by another).

This matters most when:
- multiple untrusted tenants/users connect to the same MCP server, or
- you multiplex multiple client sessions through a shared transport.

## Recommended actions

- **Upgrade** to a fixed version per the advisory.
- **Do not reuse** a single server/transport instance across clients unless the SDK explicitly guarantees isolation.
- Add a regression test that:
  - creates two clients,
  - sends distinct prompts/requests,
  - asserts that responses/notifications never cross boundaries.
- If you operate an MCP server as a service:
  - treat this as a **data isolation** issue and review logs/telemetry for cross-session leakage.
  - consider adding per-tenant process/container isolation for high-risk deployments.

## References

- GitHub advisory: <https://github.com/advisories/GHSA-345p-7cg4-v4c7>

## Related Bastet Wisdom

- [OAuth Misconfigs (MCP/Agents)](../methodology/oauth-mcp-misconfig.md)
- [Agent + CI Hardening](../best-practices/agent-ci-hardening.md)
