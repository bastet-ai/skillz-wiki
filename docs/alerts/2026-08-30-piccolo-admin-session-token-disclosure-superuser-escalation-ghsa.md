# Piccolo-Admin superuser escalation via session-token disclosure on read-only CRUD routes, operator…

**Date reviewed:** 2026-08-30
**Advisory:** [GHSA-2gh4-jmwq-rr8w](https://github.com/advisories/GHSA-2gh4-jmwq-rr8w), high, CVSS 8.8
**Affected:** `piccolo-admin <= 1.13.0` (pip) and `piccolo-api <= 1.9.x` line; fixed in `piccolo-admin 1.14.0` / `piccolo-api 1.10.0`
**Boundary class:** role-gated CRUD routes where the method allowlist gates write verbs but not reads, and the read response includes a live credential column

## The primitive

`piccolo_admin` gates the **user** and **session** tables behind a `superuser_validators` helper for non-superuser admins. The helper rejects `PUT`, `PATCH`, `DELETE`, and `POST`, but **does not reject `GET`**. Two properties combine into the escalation:

1. The `sessions` table stores **live session tokens in plaintext**, and the token column is not marked `secret=True`, so the token value is included in every `GET` response.
2. Any **non-superuser admin** (a realistic, documented role) can therefore list every other user's live session token with one request: `GET /api/tables/sessions/` (and `GET /api/tables/users/` for the target mapping).

The chain:

1. Non-superuser admin enumerates sessions via the read-only CRUD route.
2. Replay a target user's token as `Cookie: id=<token>` (or the app's auth header) to impersonate that user, including the superuser.
3. With superuser access, set `superuser = true` on the attacker's own row (self-promote), making the privilege permanent.

Reachable on the **documented deployment pattern**: a deployer adds the `Sessions` and `User` tables to `create_admin([...])` so superusers get a UI to monitor and revoke sessions, the feature that makes the tables visible is what makes the tokens readable.

## Why this is durable

The reusable class is **role-gating that lists allowed write verbs but forgets the read verb, on a table whose rows contain live credentials**. Concrete heuristics:

- **Method-allowlist role gates.** Any validator/middleware that blocks `POST/PUT/PATCH/DELETE` for a role: check `GET`, `HEAD`, OPTIONS, and any custom verbs. The gate is only as strong as the verb list.
- **Credential-adjacent tables exposed to admin UIs.** Session tables, API-key tables, refresh-token stores, and MFA/2FA token tables frequently get added to admin panels for "monitoring and revocation." Check whether the read path strips or masks secret columns, or whether the ORM layer marks them `secret`/excluded-from-serialization.
- **Session-token replay semantics.** If the token format is a bare cookie value with no binding (no device fingerprint, no IP pin, no single-use), read-only disclosure of the token column is full account takeover. Confirm the replay works with a synthetic target session in the lab.
- **Self-promotion sink.** After impersonation, check whether the app allows a user to edit their *own* row for privilege fields. `superuser = true` on the self-row is the permanent-escalation primitive.

## Replayable validation (authorized lab only)

Preconditions: a lab deployment of `piccolo-admin <= 1.13.0` (or equivalent role-gated CRUD setup) with a superuser, a non-superuser admin, and the `User`/`Sessions` tables registered in the admin. Disposable accounts only; no production database; no real user sessions.

1. **Recon the CRUD surface.** As the non-superuser admin, enumerate the registered admin tables. Confirm `users` and `sessions` are present.
2. **Method-matrix the gate.** Against `GET`, `POST`, `PUT`, `PATCH`, `DELETE` on `/api/tables/sessions/` (and `/api/tables/users/`), record the status per verb. Positive: `GET` returns 200 with token values in the body while write verbs return 403.
3. **Token disclosure proof.** Capture the shape of a session row (redact the real token). Verify the token column is present and unmasked in the JSON.
4. **Replay proof.** Create a *lab-only* target user, log in through the UI to mint a session, fetch its token from the disclosure step, and replay it in a fresh client. Positive: the session authenticates as the target user without re-login.
5. **Self-promotion proof.** With the replayed superuser session, write `superuser = true` on the attacker's lab row via the admin UI/API. Positive: the attacker's role is now superuser.
6. **Negative control.** Repeat the matrix on `piccolo-admin 1.14.0`+ / `piccolo-api 1.10.0`+ and confirm `GET` on the gated tables is denied.

Stop at "read route returns the live token and the token replays." Do not exfiltrate real tokens, do not target production users, and do not persist real account changes outside the lab.

## Reporting heuristic

- Lead with the **method-allowlist gap → credential disclosure → replay → self-promotion** chain. Name the exact validator (`superuser_validators`), the exact route, the exact column, and the replay cookie/header.
- Include versions of `piccolo-admin` and `piccolo-api`, the admin-table registration, the verb matrix, and a redacted sample of the token-bearing response.
- Distinguish the read-gate gap (the finding) from the replay impact (the proof). Do not claim persistence without the self-promotion step.
- Note the configuration precondition: the tables must be registered in `create_admin([...])`. If they are not registered, the chain does not exist, say so in the report.

## Safe boundaries

- Authorized lab deployment only; disposable accounts; no production database.
- Redact all session tokens and PII in evidence. Do not publish real tokens.
- No impersonation of real users; replay proofs use lab-minted sessions.
- No account changes outside the lab; self-promotion proof is reverted after capture.

## Sources

- [GitHub Advisory Database: piccolo-admin GHSA-2gh4-jmwq-rr8w](https://github.com/advisories/GHSA-2gh4-jmwq-rr8w)
- [Fix: piccolo-api PR #331](https://github.com/piccolo-orm/piccolo_api/pull/331)
- [piccolo-admin 1.14.0 release](https://github.com/piccolo-orm/piccolo_admin/releases/tag/1.14.0)
