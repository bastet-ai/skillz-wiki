# Vikunja principal-type and cross-object authorization checks

Sources: hourly offensive-security scan, 2026-08-02 GitHub Security Advisory feed. Primary entries: [GHSA-9jrx-vmh8-c6xw](https://github.com/advisories/GHSA-9jrx-vmh8-c6xw) / CVE-2026-68581 and [GHSA-p4r4-8cxw-pjx7](https://github.com/advisories/GHSA-p4r4-8cxw-pjx7) / CVE-2026-68582.

These advisories expose two reusable API-testing patterns: numeric IDs from different principal namespaces colliding behind a generic authentication interface, and an authorized parent object being combined with an independently selected child object that is loaded before authorization.

!!! warning "Authorized validation only"
    Use a disposable Vikunja instance, synthetic users, private test projects, canary tasks, and throwaway share links. Never enumerate a public instance, access another customer's projects, retain API tokens, or delete a real user's credentials.

## Confirmed boundaries

| Advisory | Affected versions | Failed binding | Operator value |
| --- | --- | --- | --- |
| [GHSA-9jrx-vmh8-c6xw](https://github.com/advisories/GHSA-9jrx-vmh8-c6xw) | `0.22.0` through `2.3.0` | link-share IDs and user IDs occupy independent numeric sequences, but token-management routes consume a generic numeric principal ID without checking its type | Test every credential-management route with each accepted principal class, especially when IDs can collide. |
| [GHSA-p4r4-8cxw-pjx7](https://github.com/advisories/GHSA-p4r4-8cxw-pjx7) | `0.24.0` through `2.3.0` | task scope remains pinned to the shared project while the path-selected view is loaded from another project without a matching authorization check | Test parent/child route selectors independently and preserve response-shape/existence-oracle evidence. |

## Preconditions and inputs

- A disposable Vikunja deployment and a `2.4.0` patched control.
- Users A and B with synthetic profiles.
- Projects A and B, at least one view and kanban bucket in each, and marker-only tasks.
- One link share for project A. Additional shares may be created only in the lab to construct an intentional numeric-ID collision.
- An HTTP recorder that redacts JWTs and API-token values while preserving route, principal type, numeric ID, selected project/view, status, and response field names.

## Principal-type collision matrix

1. Record user B's numeric ID from the authorized lab user-search path. Do not enumerate unknown users or infer production ID ranges.
2. In project A, create disposable link shares until one share ID equals B's user ID. This sequencing step is acceptable only in the local fixture; do not generate shares against a production service.
3. Authenticate with the colliding link-share JWT and exercise the token route family in ascending impact order: list, create through a recorder/no-op sink, then delete through a recorder. Compare the same calls with user A, user B, a non-colliding share, and an expired share.
4. For token creation, request only a harmless profile/status scope and intercept persistence where possible. Positive evidence is that the resolved token owner is user B even though the authenticated principal is a link share.
5. For deletion, do not remove an actual token. A patched repository, database transaction rollback, or fake token-store recorder is sufficient to show which owner/token row would be selected.
6. Repeat on `2.4.0`, where link-share principals should be rejected from user API-token management regardless of numeric equality.

The report should prove **link-share principal with ID N -> generic principal resolver treats N as user N -> user-token operation selected**. ID equality alone is not an authorization bypass; include the route decision or intercepted side effect.

## Project/view selector matrix

Create project A as the shared project and project B as private to user B. Give each a view and bucket with unique non-sensitive markers.

| Share principal | Path project | Path view | Expected result | Evidence to capture |
| --- | --- | --- | --- | --- |
| share A | A | view A | allowed control | A task/bucket markers only |
| share A | A | view B | denied | status, response field names, no B marker beyond the canary needed for proof |
| share A | B | view B | denied | route and auth decision only |
| share A | A | unknown view | not found control | status/body-shape fingerprint |

1. Request `GET /api/v1/projects/{project}/views/{view}/tasks` for each row and record the path IDs, share-bound project, loaded view owner, and response schema.
2. Confirm task rows remain scoped to A. The advisory's distinct impact is foreign bucket metadata and the full synthetic `created_by` object, not cross-project task content.
3. Compare known foreign, unknown, and unauthorized view IDs to determine whether status or body shape creates an existence oracle. Keep the candidate set to the fixture's known IDs.
4. Repeat as users A and B and on `2.4.0`. A patched result should authorize the view against the same principal/project context before returning bucket or creator fields.

Report **share for project A -> path selects view from project B -> foreign synthetic bucket/creator fields returned**, and report the existence oracle separately as **known versus unknown view -> stable response differential**. Do not inflate the finding into arbitrary task disclosure when the task scope remains constrained.

## Evidence checklist

- [ ] Authenticated principal type and numeric ID are recorded separately.
- [ ] Parent project, child view, resolved owner, and output object types are shown.
- [ ] Token values and JWTs are redacted; only synthetic IDs and marker fields remain.
- [ ] Mutating token operations use a recorder, rollback, or disposable token.
- [ ] Non-colliding, unknown-ID, legitimate-user, and patched-version controls are included.
- [ ] Claims distinguish token-management authority, bucket metadata disclosure, and existence-oracle behavior.

## August 28 follow-up: kanban cross-tenant mass-assignment and incomplete-fix detach

**Advisories (2026-08-28 GitHub wave):** [GHSA-5pg6-m483-7vrg / CVE-2026-55066](https://github.com/advisories/GHSA-5pg6-m483-7vrg) (high), [GHSA-gg93-x632-9ccv / CVE-2026-55065](https://github.com/advisories/GHSA-gg93-x632-9ccv) (high), [GHSA-569v-q83c-3j3g / CVE-2026-55067](https://github.com/advisories/GHSA-569v-q83c-3j3g) (medium), [GHSA-f27p-pw2p-9pr4 / CVE-2026-54766](https://github.com/advisories/GHSA-f27p-pw2p-9pr4) (medium), [GHSA-44v6-7fxq-vgf4 / CVE-2026-55064](https://github.com/advisories/GHSA-44v6-7fxq-vgf4) (medium). All affect `v2.3.0`; the detach incomplete-fix and the kanban items are fixed in `2.4.0`.

The 08-02 boundaries (principal-type collision, parent/child selector) are about *which* object gets loaded. This wave is about the *write path* accepting a caller-controlled foreign-key field that the URL-scoped authorization check never re-validates. The reusable pattern:

> A route authorizes on the object in the **URL path** but `UPDATE`/`DELETE` re-binds a caller-supplied FK from the **request body** (or a cascade that ignores the URL-scoped parent). The permission check passes on the URL object; the mutation lands on a foreign-tenant object.

| Advisory | Endpoint | Unchecked field | Result |
| --- | --- | --- | --- |
| GHSA-5pg6-m483-7vrg | `POST /api/v1/projects/{project}/views/{view}/buckets/{bucket}/tasks` | body `task_id` | Cross-tenant IDOR: victim task loaded in full and, into a "done" bucket, written, task IDs are a global sequential integer space |
| GHSA-gg93-x632-9ccv | `DELETE /api/v1/projects/{project}/views/{view}` | cascading `task_buckets` / `task_positions` deletes filter only on `pv.ID` | Instance-wide destruction of kanban bucket assignments + task ordering in *any* project view; `CanDelete` gates Admin on the URL project but never confirms the URL view belongs to it |
| GHSA-569v-q83c-3j3g | `POST /api/v1/projects/{project}/views/{view}/buckets/{bucket}` | body `project_view_id` | Cross-tenant kanban-bucket relocation: graft the attacker's bucket into any other tenant's kanban view with attacker-controlled title |
| GHSA-f27p-pw2p-9pr4 | project-duplication endpoint | `ParentProjectID` | `CanCreate` calls `parent.CanCreate` ("may I create this project?") instead of `parent.CanWrite` ("may I create children inside this project?"), any read-access user duplicates a project into any parent project |
| GHSA-44v6-7fxq-vgf4 | project update | `parent_project_id: 0` | Incomplete fix for CVE-2026-35595: the Admin gate only fires for `parent_project_id > 0`; a Write-only user on a shared child detaches it to root (`0`), severing the recursive-CTE Admin inheritance |

### Replayable validation (lab only)

Preconditions: disposable Vikunja `2.3.0` plus a `2.4.0` patched control; two synthetic users (attacker/victim) with their own projects, views, kanban buckets, and marker tasks; a redacting HTTP recorder.

1. **Bucket relocation (GHSA-569v-q83c-3j3g).** Attacker creates a bucket in their own project (step 1 in the advisory PoC), then `POST`s an update to that bucket with `project_view_id` set to the victim's view ID. The URL chain is the attacker's, so `Bucket.CanUpdate` passes; the body field writes through. Positive: the bucket row now carries the victim's `project_view_id`. On `2.4.0` the same call must be denied or the field must be ignored.
2. **Cross-tenant task move (GHSA-5pg6-m483-7vrg).** Attacker moves their own task into a bucket in their own project, but with the victim's `task_id` in the body. Positive: the response returns the victim task's full contents and, when the target bucket is "done," the victim task row is mutated. Bound the claim to the exact `task_id` binding, do not enumerate the global ID space against production.
3. **View-delete cascade (GHSA-gg93-x632-9ccv).** With Admin on the attacker's project only, `DELETE` a view whose `view_id` belongs to the victim's project but is addressed through the attacker's URL project. Positive: `task_buckets` / `task_positions` rows for the victim view are deleted. Use marker rows and a rollback/recorder for the mutation evidence; the advisory's two-tenant fixture is sufficient.
4. **Duplicate-into-foreign-parent (GHSA-f27p-pw2p-9pr4).** As a user with read access to the victim project and no write access to the victim's parent, request duplication into that parent. Positive: a new project owned by the attacker appears under the foreign parent. Compare against the normal create path, which enforces `CanWrite`.
5. **Detach-to-root incomplete fix (GHSA-44v6-7fxq-vgf4).** As a Write-only (not Admin) user on a shared child project, send a project update with `parent_project_id: 0`. Positive: the child is detached from its parent and the recursive-CTE Admin inheritance is severed. Then re-run with `parent_project_id: <foreign parent>` to confirm the `> 0` case is gated, establishing the differential. On `2.4.0` both must be denied for a non-Admin.

### Reporting heuristics

- For each item, report **URL-scoped object (authorized) vs body/cascade FK (foreign-tenant)** with the exact model method that re-binds the field (`Bucket.Update`, `ProjectView.Delete`, `ProjectDuplicate.CanCreate`, project-update handler).
- Capture the `2.4.0` negative control for every item, several of these are regression fixes, and the "incomplete fix" framing (GHSA-44v6-7fxq-vgf4) is only provable by showing the `> 0` path is gated while `= 0` is not.
- Distinguish **read oracle** (task contents returned) from **write primitive** (row mutated / rows deleted), the write evidence is what makes this a high, not a medium.
- Kanban/task ordering corruption is a tenant-integrity finding, not just an authorization miss: report the blast radius (all views of one project vs. instance-wide) precisely.

### Safe boundaries

- Disposable instance, synthetic users/projects/tasks only; no real user data, no production ID enumeration.
- Mutations go through marker rows with rollback or a recorder; the `2.4.0` control run must show the denial before any claim is made.
- Redact JWTs/tokens; evidence is route + field + status + resolved owner, not session material.

### Sources

- [GHSA-5pg6-m483-7vrg / CVE-2026-55066](https://github.com/advisories/GHSA-5pg6-m483-7vrg)
- [GHSA-gg93-x632-9ccv / CVE-2026-55065](https://github.com/advisories/GHSA-gg93-x632-9ccv)
- [GHSA-569v-q83c-3j3g / CVE-2026-55067](https://github.com/advisories/GHSA-569v-q83c-3j3g)
- [GHSA-f27p-pw2p-9pr4 / CVE-2026-54766](https://github.com/advisories/GHSA-f27p-pw2p-9pr4)
- [GHSA-44v6-7fxq-vgf4 / CVE-2026-55064](https://github.com/advisories/GHSA-44v6-7fxq-vgf4)
