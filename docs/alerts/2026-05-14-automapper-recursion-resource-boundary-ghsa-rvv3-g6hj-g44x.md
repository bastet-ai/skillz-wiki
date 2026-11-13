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

## November 13 follow-up: the MaxDepth mitigation itself has four bypass paths, "control is configured" is not "control is applied" (GHSA-gpwp-5797-mjff / CVE-2026-128081 + GHSA-6vhm-j9h7-f9gh / CVE-2026-128082, high, >= 16.0.0 < 16.3.0 and < 15.1.4)

Source: GHSA published 2026-11-13 18:47Z / 19:21Z. Both advisories are **incomplete fixes of this page's own CVE-2026-32933 mitigation**: the default/explicit `MaxDepth` limit does not fire on several mapping paths, so recursion remains unbounded and `StackOverflowException` still kills the process (uncatchable on .NET; a few thousand nesting levels crash a 1 MB default stack).

Bypass paths enumerated by the advisories (your negative-control checklist for any "depth limit configured" claim):

- **Constructor parameters / positional records**: depth was incremented *after* the destination object was created, so constructor-mapped children each recurse before their parent is counted; `MaxDepth(10)` happily mapped a 100-level chain. Fix counts depth *before* destination creation.
- **Derived type maps** (`Include`/`IncludeBase`): do not inherit the base map's `MaxDepth`; the self-referential default only applied to the base map.
- **Runtime-typed members** (`object`/interface): invisible to self-reference detection, so the default limit never applies.
- **Dictionary/dynamic sources** (`Dictionary<string,object>`, `ExpandoObject` from deserialized JSON): recurse with no depth tracking at all, `MaxDepth` has no effect, and there is *no configuration workaround* short of pre-limiting input depth.
- **Recursive `ConvertUsing` converters** that call `context.Mapper.Map`: ignore `MaxDepth`.

Operator takeaways:

- **Mitigation-coverage differential is the audit primitive.** When a CVE is fixed by adding a limit/gate, enumerate every code path that *recurses or dispatches around* the point where the counter is kept. Constructor-vs-property mapping, inheritance, runtime types, and dynamic sources are the four classic "counter lives in the wrong place" shapes, generic well beyond AutoMapper.
- For .NET targets, JSON deserialized into `Dictionary<string,object>` or `ExpandoObject` and then mapped onto typed destinations is the highest-yield probe: the advisory states no config workaround exists, so pre-16.3/15.1.4 apps are vulnerable regardless of profile settings. Nest a few thousand levels of `{"next": {...}}` and watch for worker death.
- Version-fingerprint tell: an app that *believes* it is patched for CVE-2026-32933 (>= 16.1.1) is still crashable until 16.3.0 / 15.1.4. Patch-level claims in reports should quote the exact assembly version, not the earlier fix.
- Validation boundary: disposable console/web app with a synthetic recursive type; crash your own process only.

## Related Wisdom

- [Parser, runtime, and resource-budget boundary batch](2026-05-06-parser-runtime-resource-budget-boundary-batch-ghsa.md)
- [Secret-token and decimal resource-boundary batch](2026-05-12-secret-token-and-decimal-resource-boundary-batch-ghsa.md)
- [Spring AI and framework resource-boundary batch](2026-05-06-spring-ai-and-framework-resource-boundary-batch-ghsa.md)
