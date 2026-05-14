# TanStack server-function deserialization boundary (GHSA-9m65-766c-r333)

Source: GitHub Security Advisories updated 2026-05-14.

GitHub Security Advisories surfaced [GHSA-9m65-766c-r333](https://github.com/advisories/GHSA-9m65-766c-r333) for `@tanstack/start-server-core < 1.167.30`. A seroval type-confusion issue allowed a crafted inbound server-function request body to trigger invocation of a sibling client-referenced server function during deserialization.

The advisory is careful about impact: this is not an authentication bypass or RCE by itself. The sibling server function still runs through its normal middleware, authorization, and input validation, and the practical risk requires a directly client-reachable function that already performs privileged side effects without those controls. That still makes the lesson durable for server-function frameworks: deserialization must be inert, and server functions should not rely on endpoint obscurity or caller intent.

## Operator triage

1. Upgrade `@tanstack/start-server-core` to `1.167.30+`.
2. Inventory client-referenced server functions that perform side effects, especially account, token, billing, email, webhook, storage, or deployment actions.
3. Confirm every side-effecting function has explicit authentication, authorization tied to the target resource, and input validation. Do not rely on “only this UI path calls it.”
4. Review logs for unusual paired server-function calls where one inbound request appears to trigger unexpected sibling side effects.
5. Add regression tests that send malformed serialized payloads to one server function and assert that no other server function executes as a deserialization side effect.

## Durable controls

- Treat deserialization as data loading only; it should never invoke application functions, lazy callbacks, or side-effecting references.
- Keep authorization on the callee function, not the route that normally reaches it.
- Make server-function IDs untrusted routing data. Every function should be safe if called directly by a client that can reach the app.
- Use allowlisted schema decoding at the boundary and reject unexpected function references, constructors, and executable placeholders.
