# Spring AI, MLflow, and Airflow boundary checks

Source: hourly offensive-security scan, 2026-06-30. Primary entries: GitHub Advisory Database [GHSA-cc4m-mp48-x7qg](https://github.com/advisories/GHSA-cc4m-mp48-x7qg) / CVE-2026-41863, [GHSA-8c7q-86fq-vvmh](https://github.com/advisories/GHSA-8c7q-86fq-vvmh) / CVE-2026-2651, [GHSA-g283-w6fp-c4fc](https://github.com/advisories/GHSA-g283-w6fp-c4fc) / CVE-2026-46745, and [GHSA-g9v5-gjwf-9rwx](https://github.com/advisories/GHSA-g9v5-gjwf-9rwx) / CVE-2026-45361.

These advisories are durable because they expose reusable operator workflows: LLM-influenced filenames crossing into filesystem writes, model/artifact upload APIs crossing tenant and supply-chain boundaries, LDAP login fields crossing into directory filters, and workflow-orchestrator SSH helpers crossing a host-key trust boundary. Validate only with disposable workspaces, synthetic model artifacts, lab LDAP entries, and throwaway Compute Engine targets.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-cc4m-mp48-x7qg](https://github.com/advisories/GHSA-cc4m-mp48-x7qg) / CVE-2026-41863 | Spring AI Anthropic Skills API support | LLM-influenced filenames reached `Path.resolve` before writes without path containment | Treat agent/LLM-generated filenames as untrusted file paths; prove only with temp marker writes outside the intended skill-output directory. |
| [GHSA-8c7q-86fq-vvmh](https://github.com/advisories/GHSA-8c7q-86fq-vvmh) / CVE-2026-2651 | MLflow `--serve-artifacts` multipart upload endpoints | `/mlflow-artifacts/mpu/*` authorization missed resource-level ownership checks | Model registries and experiment trackers need cross-user artifact-write tests; evidence should be a synthetic artifact overwritten or created in another lab user's run, not real model poisoning. |
| [GHSA-g283-w6fp-c4fc](https://github.com/advisories/GHSA-g283-w6fp-c4fc) / CVE-2026-46745 | Apache Airflow FAB Auth Manager LDAP authentication | unauthenticated login input crossed into LDAP filter construction | Add LDAP filter metacharacter canaries to Airflow login testing when FAB LDAP auth is enabled; prove with seeded directory canary accounts or filter-decision evidence, not production directory dumps. |
| [GHSA-g9v5-gjwf-9rwx](https://github.com/advisories/GHSA-g9v5-gjwf-9rwx) / CVE-2026-45361 | Apache Airflow Google provider `ComputeEngineSSHHook` | SSH sessions to Compute Engine VMs defaulted to disabled host-key verification | Orchestrator hooks that open SSH from workers should be tested for first-connection trust and in-path credential/session capture with disposable keys only. |

Adjacent updated advisories [GHSA-76v6-f83q-pxvh](https://github.com/advisories/GHSA-76v6-f83q-pxvh), [GHSA-5gmf-x7hg-97wf](https://github.com/advisories/GHSA-5gmf-x7hg-97wf), [GHSA-fgmj-fm8m-jvvx](https://github.com/advisories/GHSA-fgmj-fm8m-jvvx), [GHSA-w6cq-9cf4-gqpg](https://github.com/advisories/GHSA-w6cq-9cf4-gqpg), and [GHSA-jgj7-c8vj-w563](https://github.com/advisories/GHSA-jgj7-c8vj-w563) were processed without promotion because the public impact is duplicate/resource-exhaustion, generic XSS, or weak-hash hygiene without a distinct replayable operator workflow for this wiki.

## Operator triage

1. **Separate generated names from trusted roots.** For Spring AI skill flows, identify every place model output, tool output, or user prompt content can become a filename, attachment name, skill artifact, or cache key.
2. **Treat model artifacts as executable supply chain.** In MLflow, artifact writes can become code execution only when a downstream loader imports, unpickles, executes, or deploys the artifact. Prove the write boundary first; chain loading only inside an approved lab.
3. **Map Airflow authentication mode and worker egress.** LDAP filter injection requires FAB LDAP auth in the tested deployment. Host-key validation issues require an Airflow task path that invokes `ComputeEngineSSHHook` toward a reachable VM.
4. **Use two-principal labs.** MLflow and Airflow authorization bugs are strongest when tested with two disposable users, roles, runs, projects, or directory entries and a clear expected/actual decision matrix.
5. **Do not collect secrets as proof.** Avoid real LDAP attributes, Airflow connections, SSH private keys, model weights, prompts, datasets, cloud metadata, or production artifacts.

## Replayable validation boundaries

### Spring AI LLM-influenced filename write harness

- Preconditions: isolated Spring AI lab using affected `org.springframework.ai:spring-ai-anthropic`, a temporary intended output directory, and a separate disposable outside-root marker directory.
- Exercise the same Skills API path that writes model-suggested files, using a prompt or tool response that requests a harmless filename variant such as `../skillz-spring-ai-marker.txt`.
- Positive evidence is a marker file written or an attempted write logged outside the intended output directory.
- Negative controls: canonicalize and normalize before write, reject absolute paths and `..` segments, bind generated file IDs to server-side names, and verify the final real path remains under the approved root.

### MLflow multipart artifact ownership harness

- Preconditions: MLflow lab in `--serve-artifacts` mode, two disposable users or tokens, two experiments/runs, and synthetic text artifacts only.
- Create a run as user A and record the expected artifact path or multipart upload target.
- As user B, attempt only the MPU initiation/upload/complete flow against user A's run or artifact namespace using a benign marker payload.
- Positive evidence is cross-user artifact creation or overwrite in the lab run namespace. Stop before loading, serving, registering, or executing the artifact unless explicit lab-chain authorization exists.
- Negative controls: patched MLflow version, per-run ownership checks on every MPU route, token scopes tied to experiment/run ownership, and immutable artifact versioning for model promotion.

### Airflow FAB LDAP filter canary

- Preconditions: disposable Airflow deployment with FAB LDAP auth, a lab LDAP directory, and seeded canary users/groups that contain no real organizational data.
- Send paired login attempts with normal usernames and filter metacharacter variants that should never broaden the LDAP search result.
- Positive evidence is an authentication bypass, a broadened search result observable in lab LDAP logs, or filter syntax reaching the directory server with attacker-controlled structure.
- Keep evidence to decision tables and synthetic LDAP entries. Do not dump directory users, group memberships, hashes, or attributes.

### Airflow Compute Engine SSH host-key harness

- Preconditions: disposable Airflow worker, affected `apache-airflow-providers-google`, throwaway SSH keys, a lab Compute Engine VM or mock SSH endpoint, and approved network-position testing.
- Trigger a task that uses `ComputeEngineSSHHook` and record whether the first connection accepts an unknown or substituted host key without pinning.
- Positive evidence is a connection or command attempt against a canary SSH endpoint with a mismatched key. Use inert commands such as writing a temp marker; do not capture real task payloads or credentials.
- Negative controls: provider version with host-key verification enabled, pinned known-hosts material, explicit `RejectPolicy`-style behavior, and per-connection documentation of expected host fingerprints.

## August 10 follow-up: bind secrets-backend fallback to the active team

Three unreviewed records describe the same Airflow multi-team boundary across different provider backends:

- Amazon Systems Manager Parameter Store and Secrets Manager: [GHSA-984p-rgj2-h89x / CVE-2026-68872](https://github.com/advisories/GHSA-984p-rgj2-h89x), with `apache-airflow-providers-amazon 9.34.0` listed as corrected;
- Azure Key Vault: [GHSA-6hj8-q7v2-996c / CVE-2026-68870](https://github.com/advisories/GHSA-6hj8-q7v2-996c), with `apache-airflow-providers-microsoft-azure 14.1.0` listed as corrected; and
- Yandex Lockbox: [GHSA-qmrf-jrpr-rjx6 / CVE-2026-68871](https://github.com/advisories/GHSA-qmrf-jrpr-rjx6), with `apache-airflow-providers-yandex 4.5.1` listed as corrected.

The reported pattern is a scoped-lookup miss followed by a team-agnostic fallback. A caller in team A can supply a Connection or Variable ID that spells team B's namespace; if A's scoped lookup misses, the fallback may resolve B's full secret. Test the namespace resolver and backend request separately from response disclosure.

Use two disposable Airflow teams, fake provider clients, and marker-only Connection/Variable objects. Patch each backend client so it records the canonical secret name and returns only a sentinel object with field names, never credential values. Exercise own-team ID, foreign-team-shaped ID, nonexistent ID, unqualified collision, already-qualified ID, malformed separator, duplicate prefix, and omitted team context.

| Active team | Requested ID | Scoped lookup | Secure fallback behavior |
| --- | --- | --- | --- |
| A | A marker | hit | resolve A control |
| A | unqualified missing marker | miss | generic miss, with no cross-team search |
| A | B-qualified marker | miss | reject before team-agnostic backend lookup |
| A | malformed or duplicate team prefix | miss | reject consistently |
| B | B marker | hit | resolve B control |

Capture authenticated principal, active team, object type, raw ID, parsed team namespace, scoped backend key, fallback key, provider operation, and response projection. A bounded positive is **team A -> B-qualified synthetic ID -> A-scoped lookup misses -> team-agnostic provider recorder selects B's marker**. Prefer stopping there; if a response check is necessary, return only a random sentinel and prove its presence, not a fake password body.

Repeat the same fixture against every configured secrets backend and both Connection and Variable APIs. A corrected Amazon provider does not establish that Azure, Yandex, a custom backend, scheduler parsing, task rendering, UI test-connection, or CLI lookup uses the same resolver. Never query production vaults, enumerate IDs, retrieve credentials, or run a task with the selected Connection.

## September 16 follow-up: Akeyless joins the team-scope fallback family, and two session-invalidation routes survive the earlier fix

Two updates land on axes already on this page:

**Akeyless secrets backend team-scope bypass** — [GHSA-rmjj-53pr-xrwc / CVE-2026-86465](https://github.com/advisories/GHSA-rmjj-53pr-xrwc). The Akeyless provider's team-scope guard can be bypassed with a user-controlled Variable key: after the team-scoped lookup misses, the backend concatenates the unvalidated key (which may contain a path separator) onto the team-agnostic fallback path, so a Dag author scoped to one team resolves another team's secret. The advisory explicitly names this as the same class as the August 10 Azure Key Vault, Yandex Lockbox, and Amazon records above, and adds the reusable detail that the **Execution API Variables route accepts a path-shaped key**, so ordinary Dag code reaches the sink. Repeat the two-team fake-client fixture above against `apache-airflow-providers-akeyless` and the Execution API entry point specifically — UI, CLI, scheduler parse, and Execution API may not share the resolver, so prove each separately.

**FAB provider session-invalidation drift, second and third routes** — [GHSA-gr7m-j34w-7qcm / CVE-2026-82311](https://github.com/advisories/GHSA-gr7m-j34w-7qcm) and [GHSA-5j5v-7fmw-4hvh / CVE-2026-86462](https://github.com/advisories/GHSA-5j5v-7fmw-4hvh). With `[fab] session_backend=database`, a password reset does not delete existing sessions: the cleanup helper compares the string identifier Flask-Login stores against the user's integer database ID, so the comparison never matches and no session is evicted (CVE-2026-82311). A *second independent* route defeats the same goal: the Admin user-edit **PATCH** endpoint never calls the session-invalidation helper at all, so the CVE-2026-82311 fix does not repair it (CVE-2026-86462). The durable lesson is a fix-coverage audit pattern: when a vendor fixes "password change doesn't revoke sessions" in a helper, enumerate **every** mutation route that can change credentials (reset command, admin edit form, admin edit PUT, admin edit PATCH, API variants, CLI) and require each to reach the invalidation sink — helper existence proves nothing about call-site coverage.

Operator harness (disposable Airflow FAB lab, two synthetic users, `[fab] session_backend=database`):

1. Authenticate as user A, retain the session cookie, then trigger each credential-change route separately: user self-reset, admin edit form, admin API PUT, admin API PATCH.
2. After each change, replay the retained cookie against one harmless authenticated endpoint. The finding is the route where the stale cookie still succeeds.
3. Record which code path executed (`reset_password` command, form handler, API expose-layer method) so PUT-vs-PATCH drift is visible in the evidence table.
4. Patched control must fail the replay on **every** route, not just the one named in the first CVE.

Never retain or replay a real user's session cookie, and never test against a deployment whose sessions are live.

## Reporting notes

- Lead with the precise crossed boundary: **LLM filename to filesystem path**, **artifact upload route to another user's model namespace**, **login field to LDAP filter**, **orchestrator SSH hook to unverified host key**, or **team-scoped secret miss to team-agnostic backend lookup**.
- Include package versions, role/token used, lab topology, sanitized request shape, expected decision, actual decision, and patched negative control.
- Keep artifacts synthetic: marker files, dummy model blobs, lab LDAP entries, disposable VM fingerprints, and fake credentials.
