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

## October 20 21:1xZ follow-up: the A2A Java SDK ships the same isolation failure as its own shipped default (CVE-2026-111764 / [GHSA-qw47-mcm5-934w](https://github.com/advisories/GHSA-qw47-mcm5-934w), high, ≤1.2.0)

The sibling agent-protocol (A2A) reference Java SDK's default `InMemoryTaskStore` performs **zero authorization on task reads**: the no-arg constructor sets `authorizationProvider = null` and `get(taskId)` is a bare map lookup regardless of provider. Ownership checks exist only when the app both supplies a `TaskAuthorizationProvider` *and* routes through the CDI-wired `AuthorizationRequestHandlerDecorator` — manual `DefaultRequestHandler.builder().build()` wiring and Spring integrations never reach it. Any caller reads any other caller's task (status, context, message history, artifacts) by ID.

Durable axes:
1. **Isolation-by-default failure has now crossed SDKs on the same evening** — MCP TS SDK taskStore (above, same-day) and A2A Java SDK taskStore are the same defect shape in two independent agent-protocol implementations: the spec's anti-hijacking/authorization guidance lives in a decorator layer the default constructor opts out of. Agent-protocol recon rule: on any A2A/MCP server, the first battery is two synthetic callers + task-ID replay on every read/mutation verb; a cross-caller read with default wiring is the finding, no exploit needed.
2. **DI-framework-routed security is opt-in security.** If the authz check lives in a CDI/proxy decorator rather than the store method, every non-CDI integration path (Spring, manual builders, test harnesses that mirror main()) silently skips it. Fingerprint: grep for `AuthorizationProvider`/decorator classes, then check the no-arg/default constructor's field value — `null` default = fail-open shipped default. Same fixed-but-disabled fingerprint discipline as this page's 46jr/rvq5 legs: do not version-close these; behavior-probe.

## October 20 20:0xZ follow-up: the third isolation wave — JSON-RPC `id` alone routes responses across clients, and this time the fix breaks shared deployments (CVE-2026-111770 / [GHSA-jm63-cq47-j5jp](https://github.com/advisories/GHSA-jm63-cq47-j5jp) high, CVE-2026-111768 / [GHSA-46jr-4wx8-v453](https://github.com/advisories/GHSA-46jr-4wx8-v453) high, CVE-2026-111771 / [GHSA-rvq5-wwqv-78pq](https://github.com/advisories/GHSA-rvq5-wwqv-78pq) medium)

The `@modelcontextprotocol` 2.x server packages shipped three more boundary bugs the same evening, and the first one is the root-cause sibling of this page's Feb 2026 headline:

- **Shared transport/`McpServer` instance delivers one client's responses and notifications to another** (jm63, `@modelcontextprotocol/server` 2.0.0–2.2.0): messages were matched to a connection by **JSON-RPC `id` alone**, and SDK clients number requests from **0** — so ids collide in normal use, not just adversarially. The `@modelcontextprotocol/hono`/`express`/`fastify`/`node` README examples *showed* the shared-at-startup pattern, which means deployed codebases copied the vulnerable shape by design. The fix refuses sharing outright: after upgrading, a second `connect()` rejects with `ALREADY_CONNECTED` and a stateless transport rejects its second request — apps must move to a per-request factory.
- **One request inside the 4 MiB size limit exhausts server memory during validation** (46jr, sdk 1.3.0–1.31.0): no cap on array elements/object keys validated per request; a dense JSON body within the size limit blows the heap (`JavaScript heap out of memory`, uncredentialed unless you auth before the SDK). Byte caps and structural caps are different limits — recursion/density is not bounded by a body-size option.
- **Bearer auth accepts tokens issued for another service** (rvq5, sdk 1.6.0–1.31.0 / server 2.0.0–2.2.0): `requireBearerAuth()`/`verifyBearerToken()` never checked the token audience (`aud`); where one authorization server issues tokens for several services, any sibling-service token unlocks the MCP server.

Durable axes:

1. **Three-generation isolation genealogy in one SDK** — Feb shared server/transport reuse, Oct-morning shared task store, Oct-evening shared transport with id-only routing. The rule from the taskStore note is now proven twice more: after any isolation fix in a shared-server product, re-sweep every server-side container and every message-routing key. New sub-rule from jm63: **routing keys must be session-scoped, not request-scoped** — if the demux key is a per-request counter that restarts at 0 per client, it is not a routing key at all. Probe shape: two lab sessions firing identical low-id requests and observing whether responses/notifications cross; the collision happens honestly without any attacker.
2. **"Upgrading alone changes nothing" is now a two-advisory fingerprint in the same release.** Both 46jr (`maxToolInputElements` off by default) and rvq5 (`expectedResource` off by default) ship fixed-but-disabled. Operator consequence: on an authorized MCP engagement, **do not version-fingerprint these CVEs closed** — a 1.32.0/2.3.0 server is vulnerable until the operator also changed code. Behavior probes instead: dense-array tool-argument request against a within-limit body (heap death = 46jr open), and a valid sibling-audience token from the same issuer (200 vs 401 = rvq5 open). Grep any Node MCP server source for `requireBearerAuth(`/`verifyBearerToken(` and check whether `verifyAccessToken()` returns/validates `aud` — aud-unchecked bearer helpers are a standing audit grep beyond MCP.
3. **README-example code is supply chain.** When vendor docs demonstrate the unsafe construction (shared instance at startup), version-pinning advice is worthless because the pattern predates any pin. On MCP server recon, check for per-request `new McpServer(...)`/`createMcpHandler(factory)` shape in behavior: send two concurrent sessions the same low-id request and compare delivered bodies. Lab-bounded: own two sessions, synthetic payloads, never a third tenant's traffic.

## Consolidation note
<!-- consolidation-note: wiki-redundancy-2026-05-22 -->

This is the canonical page for this topic. During the 2026-05-22 redundancy pass, overlapping pages were reduced to compatibility pointers:

- `alerts/2026-02-05-mcp-typescript-sdk-cross-client-data-leak-ghsa-345p-7cg4-v4c7.md`
