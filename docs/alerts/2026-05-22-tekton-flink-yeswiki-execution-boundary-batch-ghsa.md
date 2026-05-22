# Tekton, Flink, and YesWiki execution-boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-22.

This batch is durable because it turns fresh CI/CD, stream-processing, and CMS advisories into operator checks for policy-match bypass, internal CI path-mount interference, SQL-to-code-generation execution, and unauthenticated SQL data extraction. Use only in authorized lab or scoped assessment environments.

## What changed

- **Tekton VerificationPolicy regex substring bypass** — [GHSA-rmx9-2pp3-xhcr](https://github.com/advisories/GHSA-rmx9-2pp3-xhcr) / CVE-2026-25542: trusted-resource verification compares `refSource.URI` to `spec.resources[].pattern` with Go `regexp.MatchString`, which succeeds on substring matches. Unanchored patterns such as `https://github.com/tektoncd/catalog.git` can match attacker-controlled source strings that merely contain that trusted URL, changing which verification policy, mode, or keys apply.
- **Tekton VolumeMount `/tekton/` path restriction bypass** — [GHSA-rx35-6rhx-7858](https://github.com/advisories/GHSA-rx35-6rhx-7858) / CVE-2026-40923: validation checks `strings.HasPrefix` before normalizing mount paths. A mount such as `/tekton/home/../results` can pass the `/tekton/home` exception but resolve at runtime to `/tekton/results`, creating a path to interfere with internal result, script, or coordination files.
- **Apache Flink SQL code-generation injection** — [GHSA-2f54-v4hm-fx73](https://github.com/advisories/GHSA-2f54-v4hm-fx73) / CVE-2026-35194: authenticated users with query-submission rights can craft SQL that reaches Flink table code generation and injects Java through JSON functions or `LIKE ... ESCAPE` expressions. The impact lands on TaskManagers, so the meaningful boundary is query privilege to worker code execution.
- **YesWiki unauthenticated Bazar import SQL injection** — [GHSA-jwvv-qr7q-cv8j](https://github.com/advisories/GHSA-jwvv-qr7q-cv8j) / CVE-2026-46670: the Bazar form-import path concatenates `bn_id_nature` into an `INSERT` value list. The public advisory demonstrates expression-based extraction through `/?BazaR&vue=formulaire`, then reading computed row IDs from `/?api/forms`, enabling database disclosure including user emails and password hashes on default installs before 4.6.4.

## Operator triage

1. **Tekton:** inventory clusters where tenants can create `Task`, `TaskRun`, `PipelineRun`, or `ResolutionRequest` resources. Collect Pipeline version, trusted-resource VerificationPolicy objects, resolver feature flags, and whether policy patterns are anchored with `^...$`.
2. **Tekton path mounts:** review submitted Tasks/TaskRuns for `volumeMounts.mountPath` values under `/tekton/`, especially paths containing `..`, repeated slashes, or symlink-sensitive components. Capture whether downstream tasks consume task results or scripts as trust signals.
3. **Flink:** identify exposed SQL Gateway, REST, notebook, or application portals that let non-admin users submit SQL to Flink clusters. Record Flink versions, enabled table planner packages, TaskManager execution context, and whether JSON functions or `LIKE ... ESCAPE` are reachable.
4. **YesWiki:** fingerprint internet-facing or intranet YesWiki deployments, version banners, `/?BazaR&vue=formulaire`, `/?api/forms`, and whether unauthenticated visitors can reach Bazar form import flows.
5. Exclude pure availability-only findings from report escalation unless the scope values service-disruption proofs; [GHSA-m2cx-gpqf-qf74](https://github.com/advisories/GHSA-m2cx-gpqf-qf74) is a Tekton HTTP resolver unbounded-body DoS and was tracked but not promoted as a primary Skillz operator page.

## Replayable validation boundaries

- **Tekton policy-match proof:** in a lab namespace, create two VerificationPolicy patterns: one intentionally unanchored trusted pattern and one anchored control. Submit a benign resource URI that embeds the trusted string inside an attacker-controlled URL. Vulnerable result: the unanchored policy matches the embedded substring while the anchored control does not. Do not bypass production signing gates unless explicitly authorized.
- **Tekton mount proof:** submit a disposable TaskRun with a harmless volume mounted at `/tekton/home/../results` and a marker-only step. Vulnerable result: the runtime mount resolves into `/tekton/results` or another internal path despite validation intending to block it. Keep proofs to marker files or controlled task results; do not overwrite real pipeline scripts.
- **Flink code-generation proof:** use an isolated Flink lab cluster and a low-privilege query user. First prove version and feature reachability with harmless JSON and `LIKE ... ESCAPE` queries. If code-generation injection validation is authorized, use a payload that emits a deterministic marker in query output or a lab-only callback from the TaskManager; avoid filesystem, credential, or shell collection.
- **YesWiki SQLi proof:** on an owned instance, submit a Bazar import parameter that computes a database version or marker value with `ASCII(SUBSTRING(...))`, then retrieve only that marker via `/?api/forms`. For scoped bug bounty work, avoid dumping user tables; if impact evidence is required, extract a single non-sensitive row or use a test account inserted by the tester.

## Reporting heuristics

- Frame Tekton VerificationPolicy findings as **pattern semantics drift**: trusted-source policy intent uses regex, but matching is substring-based unless patterns are anchored.
- Frame Tekton VolumeMount findings as **path-normalization order drift**: validation sees an allowed `/tekton/home` prefix, while runtime resolution lands on restricted internal paths.
- Frame Flink findings as **data-plane query privilege crossing into worker code execution**. Include the exact submission interface, user role, Flink version, affected expression family, and TaskManager privilege context.
- Frame YesWiki findings as **unauthenticated form-import expression injection with an API-side exfil channel**. Include reachability of `BazaR`, the vulnerable version, one redacted marker proof, and whether public registration or anonymous edits are enabled.
- Keep all artifacts minimal: policy YAML, redacted TaskRun specs, SQL marker queries, HTTP request/response pairs, version proof, and scoped impact chain. Do not publish live secrets, user hashes, or production data.
