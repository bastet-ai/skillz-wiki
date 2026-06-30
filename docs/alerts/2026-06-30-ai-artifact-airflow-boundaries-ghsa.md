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

## Reporting notes

- Lead with the precise crossed boundary: **LLM filename to filesystem path**, **artifact upload route to another user's model namespace**, **login field to LDAP filter**, or **orchestrator SSH hook to unverified host key**.
- Include package versions, role/token used, lab topology, sanitized request shape, expected decision, actual decision, and patched negative control.
- Keep artifacts synthetic: marker files, dummy model blobs, lab LDAP entries, disposable VM fingerprints, and fake credentials.
