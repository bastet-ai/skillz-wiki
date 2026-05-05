# Identity, admin, and session-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because identity transitions and admin affordances keep relying on convenience signals: duplicate detection, OAuth linking, magic headers, UI policy checks, and one-time codes. These are authorization decisions and need server-side invariants.

## Advisories covered

- **PocketBase OAuth2 linking** — [GHSA-pq7p-mc74-g65w](https://github.com/advisories/GHSA-pq7p-mc74-g65w): account pre-hijacking via unverified-to-verified OAuth2 autolinking upgrade.
- **Ethyca Fides privacy requests** — [GHSA-qx5f-ghc2-7g5c](https://github.com/advisories/GHSA-qx5f-ghc2-7g5c): duplicate detection can bypass identity verification for privacy requests.
- **DevGuard** — [GHSA-2g9v-7mr5-fgjg](https://github.com/advisories/GHSA-2g9v-7mr5-fgjg): unauthenticated identity assertion via `X-Admin-Token` header.
- **JupyterHub Extension Manager** — [GHSA-37w4-hwhx-4rc4](https://github.com/advisories/GHSA-37w4-hwhx-4rc4): API/GUI policy discrepancy allows third-party extension install via POST.
- **Nginx-UI** — [GHSA-7jrr-xw9c-mj39](https://github.com/advisories/GHSA-7jrr-xw9c-mj39): authenticated settings disclosure exposes `node.secret`, enabling trusted-node abuse, backup exfiltration, and restore rollback.
- **parse-server MFA SMS** — [GHSA-jpq4-7fmq-q5fj](https://github.com/advisories/GHSA-jpq4-7fmq-q5fj): concurrent login can reuse one-time passwords.
- **Kratos** — [GHSA-jj45-xvq5-rhh9](https://github.com/advisories/GHSA-jj45-xvq5-rhh9): confused-deputy issue.

## Operator triage

1. Review login, account-linking, privacy-request, extension-install, cluster-node, and restore workflows for server-side authorization checks independent of UI state.
2. Search access logs for magic headers such as `X-Admin-Token`, unexpected extension install POSTs, repeated MFA attempts within the same second, and backup/restore reads by non-break-glass users.
3. For OAuth linking, identify accounts that moved from unverified local credentials to verified OAuth identities without a fresh challenge to the existing owner.
4. Rotate exposed node or cluster secrets and invalidate backups if settings disclosure was possible.
5. Re-run privacy-request verification for high-risk duplicates where duplicate detection could have substituted for proof of identity.

## Durable controls

- Account linking must require proof of control over both identities at link time; a later verified OAuth assertion should not automatically bless an earlier unverified account.
- One-time codes need atomic consume-on-success semantics, replay locks, and transaction isolation under concurrent requests.
- UI policy must be duplicated at the API boundary; hidden buttons are not authorization.
- Internal trust headers are safe only when stripped at ingress and bound to a mutually authenticated upstream identity.
- Cluster/node secrets and backups should be treated as credentials: redact by default, scope by role, audit every read, and rotate on disclosure.
