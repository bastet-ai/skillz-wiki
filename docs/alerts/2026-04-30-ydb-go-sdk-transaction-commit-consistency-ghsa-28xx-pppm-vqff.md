# ydb-go-sdk transaction commit consistency bug (GHSA-28xx-pppm-vqff)

**Signal:** GitHub Security Advisories published **2026-04-30**. `ydb-go-sdk` could report transaction success while `options.WithCommit()` failed to commit changes in a specific table transaction call path.

## What it is
For `github.com/ydb-platform/ydb-go-sdk/v3`, transactions using `options.WithCommit()` on the final `table.Transaction.Execute` call were not committed as expected in affected versions. Applications could believe a transaction succeeded even though the intended changes were not durable, causing rare data-consistency failures.

Affected package: Go `github.com/ydb-platform/ydb-go-sdk/v3` versions `3.104.6` through `3.134.1`. Fixed version: `3.134.2`.

Reference: <https://github.com/advisories/GHSA-28xx-pppm-vqff>

## Triage
1. Search Go services for `github.com/ydb-platform/ydb-go-sdk/v3` and affected versions.
2. Find transaction code that relies on `options.WithCommit()` on the final `table.Transaction.Execute` call.
3. Prioritize security-sensitive state changes: authorization grants, billing events, account recovery, inventory, audit logs, idempotency records, and queue checkpoints.
4. Review reconciliation logs for operations acknowledged to callers but missing from YDB state.

## Mitigation
- Upgrade `ydb-go-sdk` to `3.134.2` or later.
- Until upgraded, use explicit `table.Transaction.CommitTx(ctx)` or transaction/query helper wrappers recommended by upstream.
- Add post-commit assertions or reconciliation for critical writes where acknowledgement drives external side effects.

## Detection ideas
- Compare API success logs against resulting database rows for affected transaction paths.
- Hunt for repeated retries, missing idempotency keys, or downstream state machines stuck after apparently successful writes.
- Add metrics for commit failures and transaction-finalization paths after the upgrade.

## Durable lesson
Data-integrity bugs can become security bugs when authorization, billing, audit, or recovery workflows depend on write durability. Treat database client transaction semantics as part of the trust boundary and test commit behavior directly.
