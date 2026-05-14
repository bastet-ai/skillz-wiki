# AutoMapper recursion resource-boundary crash

Source: GitHub Security Advisory [GHSA-rvv3-g6hj-g44x](https://github.com/advisories/GHSA-rvv3-g6hj-g44x), CVE-2026-32933, updated 2026-05-14.

This item is durable because object mapping is often treated as safe plumbing after request validation. Deep or cyclic object graphs are still attacker-controlled resource input when they can be built from JSON, XML, form binding, message queues, GraphQL, ORM relations, plugin payloads, or tenant-supplied configuration.

## Advisory summary

- **Package:** `AutoMapper` for NuGet.
- **Affected versions:** `< 15.1.1` and `>= 16.0.0, < 16.1.1`.
- **Fixed versions:** `15.1.1` and `16.1.1`.
- **Impact:** deeply nested self-referential object graphs can drive uncontrolled recursive mapping until .NET raises `StackOverflowException`, terminating the whole process rather than only the current request.

## Operator triage

1. Inventory services that accept user-controlled structured input and map it with AutoMapper before authorization, deduplication, graph-depth checks, or business validation.
2. Upgrade affected AutoMapper versions to `15.1.1+` or `16.1.1+` according to the deployed branch.
3. Prioritize internet-facing APIs, webhook receivers, queue consumers, import endpoints, plugin/config upload paths, and GraphQL/JSON API layers that can materialize nested object graphs.
4. Review crash telemetry for `StackOverflowException`, abrupt worker exits, repeated pod restarts, or requests with unusually deep repeated object properties.
5. Add temporary input limits while patching: maximum JSON/XML depth, maximum collection length, maximum request body size, and endpoint-specific DTO shape constraints.

## Durable controls

- Treat mapping as resource-consuming parsing, not harmless assignment. Enforce graph depth, collection size, and cycle policy before invoking general-purpose mappers.
- Keep external request DTOs shallow and explicit; do not map attacker-shaped object graphs directly into rich domain entities with recursive relationships.
- Put process supervisors and load balancers in a mode where one stack-overflow crash drains/restarts a worker without cascading traffic to equally vulnerable peers.
- Add regression tests for pathological graph depth, self-references, repeated child chains, and nested collections in mapper profiles used by exposed endpoints.
- Log input depth/shape rejection counters so resource-boundary probes are visible before they become crash loops.

## Related Wisdom

- [Parser, runtime, and resource-budget boundary batch](2026-05-06-parser-runtime-resource-budget-boundary-batch-ghsa.md)
- [Secret-token and decimal resource-boundary batch](2026-05-12-secret-token-and-decimal-resource-boundary-batch-ghsa.md)
- [Spring AI and framework resource-boundary batch](2026-05-06-spring-ai-and-framework-resource-boundary-batch-ghsa.md)
