# Auth before side effects

Security bugs often happen because an application **does the work first** and only later decides whether the request was allowed.

This is especially common in systems with **queues**, **webhooks**, **event buses**, **background workers**, and **federation**.

## Principle
**Do not create side effects until the request is authenticated and authorized.**

Side effects include:

- writing to a database
- enqueueing jobs
- emitting events
- sending emails/notifications
- publishing messages to other services
- mutating caches that influence later decisions

If a request is rejected, it should be rejected **before** any of those happen.

## Failure mode: “return 401/403, but you already did it”
Common patterns that lead to vulnerabilities:

- `enqueue(job)` happens before signature validation / ACL checks.
- object routing happens before verifying the *claimed identity* matches the *signing key*.
- the handler emits an event, then a later middleware rejects the request.

Example real-world case study: Fedify ActivityPub actor impersonation (GHSA-6jcc-xgcr-q3h4 / CVE-2025-54888) where `routeActivity()` ran before `doesActorOwnKey()`.

## Safer patterns
### 1) Preconditions first
Structure handlers so the first part is **pure validation**:

- parse
- validate schema
- authenticate
- authorize
- only then perform side effects

### 2) Verified principal travels with the work
If you enqueue work, the job should contain:

- `principal` (subject/user/service)
- `auth_context` (how it was verified, key id, timestamp)
- `policy_decision` (what was allowed)

Workers must treat missing/invalid context as **fatal**.

### 3) Side-effect “commit point”
Create a single commit point (transaction or explicit step) that cannot be reached unless checks have passed.

### 4) Guardrails
- **Unit tests:** assert side-effect functions are not called when auth fails.
- **Integration tests:** simulate a failing auth check and assert nothing was queued/written.
- **Telemetry:** tag side effects with principal; alert on “unknown principal” side effects.

## Quick audit checklist
Search for code that:

- calls `enqueue`, `publish`, `emit`, `route`, `dispatch` before auth decisions
- returns an error after calling side-effect functions
- performs auth checks in a different layer than the side-effect code

When you find it, ask: *“Can an attacker reach the side effect even if the request is later rejected?”*
