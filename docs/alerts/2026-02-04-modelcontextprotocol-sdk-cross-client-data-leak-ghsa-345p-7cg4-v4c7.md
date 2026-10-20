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

## Related Skillz Wiki

- [OAuth Misconfigs (MCP/Agents)](../methodology/oauth-mcp-misconfig.md)
- [Agent + CI Hardening](../best-practices/agent-ci-hardening.md)

## October 20 follow-up: shared `taskStore` is the second isolation miss — experimental tasks were never tied to the creating session (CVE-2026-111767 / [GHSA-22jm-h49p-29qw](https://github.com/advisories/GHSA-22jm-h49p-29qw), high, 1.24.0–1.31.0, fixed 1.32.0)

The SDK's experimental tasks feature (`taskStore`) stored tasks in a server-wide container with **no session binding**: any client sharing one `InMemoryTaskStore` could list, read, and **cancel** every other client's tasks. The 1.32.0 fix binds each task to its creating session; the 2.x packages were never affected, and the 2026-07-28 spec replaced the feature with a redesigned extension (deprecation is itself a tell).

Durable axes:

1. **Cross-client isolation in this SDK is now a two-generation genealogy** — Feb 2026 shared server/transport reuse, Oct 2026 shared task store. Rule: when a shared-server product fixes one tenant-isolation bug, re-sweep *every* server-side container (stores, caches, registries) for a creator/session key; per the same-product re-sweep rule, the next surface is usually already in the same release train.
2. **Experimental/deprecated feature surfaces carry the fewest isolation checks.** Feature-gated code paths (`tasks`, `sampling`, elicitation, prompts queues) skip the authz middleware that mainline RPC gets. On an authorized MCP-server engagement, enumerate feature flags first: `grep -ri taskstore` (vendor's own affected-test), then probe each gated verb — start in one lab session, list/read/cancel from a second; state-mutating verbs (cancel) are the impact anchor over read-only listing.
3. **Session-identifier presence is not session binding** — same embed-at-create/discard-at-resume grep as the Oct 1 Envoy AI Gateway leg: prove a fresh session can reach the old session's objects, not just guess from field names.

## Consolidation note
<!-- consolidation-note: wiki-redundancy-2026-05-22 -->

This is the canonical page for this topic. During the 2026-05-22 redundancy pass, overlapping pages were reduced to compatibility pointers:

- `alerts/2026-02-05-mcp-typescript-sdk-cross-client-data-leak-ghsa-345p-7cg4-v4c7.md`
