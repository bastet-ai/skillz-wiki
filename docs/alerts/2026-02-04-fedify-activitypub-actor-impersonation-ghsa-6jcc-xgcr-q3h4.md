# 2026-02-04 — Fedify ActivityPub actor impersonation via post-processing auth check (GHSA-6jcc-xgcr-q3h4 / CVE-2025-54888)

**Category:** AuthN/AuthZ logic flaw (order-of-operations)

## What happened
Fedify (an ActivityPub framework) processed inbound activities **before** verifying that the HTTP Signature key belonged to the claimed `actor`. The server returns `401` after the check fails — but the activity may already have been processed or queued.

This enables **unauthenticated actor impersonation** (send activities “as” any actor) across affected Fedify instances.

- Advisory: https://github.com/fedify-dev/fedify/security/advisories/GHSA-6jcc-xgcr-q3h4
- Fix commit: https://github.com/fedify-dev/fedify/commit/14a2f8c6d2c3cbc00c3170a86ad3b7b8555c6847

## Why it matters (durable lesson)
This is a classic **“auth after side effects”** bug:

- The *security decision* (who is allowed) happens **after** the system has already taken an action.
- In async systems (queues, event buses, background workers), “we return 401” is meaningless if you already enqueued the job.

See: [Best practice — Auth before side effects](../best-practices/auth-before-side-effects.md)

## Detection ideas
If you operate Fedify or similar systems, look for:

- Activity processing logs where the signer key / keyId does not match the claimed actor.
- Activities that were accepted into a queue and later rejected (or errors that appear *after* side effects).
- Sudden spikes in `401` responses correlated with delivered/processed activities.

## Mitigation / hardening guidance
1. **Patch/upgrade** Fedify to a fixed version (per vendor guidance).
2. **Enforce preconditions before enqueueing:**
   - Verify signature validity.
   - Bind identity → key (e.g., “actor owns keyId”).
   - Only then call `routeActivity()` / enqueue.
3. **Make queues “auth-aware”:** include verified principal + verification metadata in the job payload; workers should refuse to run if verification context is missing.
4. **Add regression tests** that fail if any side-effect path is reachable with a failing auth check.

## Bug bounty / AppSec notes
When you find this class of issue, demonstrate:

- A side effect that persists (DB write, queue entry, outgoing federation post) despite an error response.
- The precise order-of-operations in code.
- A minimal fix: move authorization checks to the earliest safe point, or make downstream consumers enforce a verified principal.
