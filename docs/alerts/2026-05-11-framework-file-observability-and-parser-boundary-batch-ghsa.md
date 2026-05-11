# Framework file, observability, and parser-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because it captures defensive patterns for framework file managers, Kubernetes-style operator RBAC, and parser resource budgets: trusted infrastructure components can still turn user-controlled identifiers or metadata into filesystem, cluster-permission, or process-stability failures.

## Advisories covered

- **Apache Wicket folder upload path traversal** — [GHSA-3gmf-p6r4-q8m6 / CVE-2026-43975](https://github.com/advisories/GHSA-3gmf-p6r4-q8m6): `org.apache.wicket:wicket-core` `8.0.0-M1-8.17.0`, `9.0.0-M1-9.22.0`, and `10.0.0-M1-10.8.0`, fixed `10.9.0`, fails to sanitize `uploadFieldId` and `clientFileName` before file path construction.
- **Grafana Tempo Operator TokenReview / SubjectAccessReview information exposure** — [GHSA-28gr-56hr-prp6 / CVE-2025-2786](https://github.com/advisories/GHSA-28gr-56hr-prp6): `tempo-operator <0.16.0`, fixed `0.16.0`, creates service account RBAC that namespace users can leverage to query authorization information.
- **Grafana Tempo Operator cluster-monitoring-view exposure** — [GHSA-5xf3-gmx4-529v / CVE-2025-2842](https://github.com/advisories/GHSA-5xf3-gmx4-529v): `tempo-operator <0.16.0`, fixed `0.16.0`, can create a ClusterRoleBinding for Tempo service accounts when Jaeger UI Monitor Tab functionality is enabled, exposing broader metrics visibility to users with namespace secret access.
- **ParquetSharp stack overflow on large decimal width** — [GHSA-rrjr-v56m-ww88 / CVE-2026-42241](https://github.com/advisories/GHSA-rrjr-v56m-ww88): `ParquetSharp >=18.1.0,<23.0.0.1`, fixed `23.0.0.1`, can stack overflow while reading untrusted Parquet files with unreasonable decimal type width.

## Operator triage

1. Patch framework and parser libraries used in upload, import, report, analytics, and data-processing services before accepting new untrusted files.
2. Hunt for Wicket folder-upload parameters containing traversal markers, encoded separators, absolute paths, or unexpected upload field IDs.
3. In clusters with Tempo Operator, list generated ServiceAccounts, ClusterRoles, and ClusterRoleBindings; check whether namespace-scoped users can read tokens that unlock cross-namespace authorization or metrics information.
4. For Parquet-processing services, enforce file-size, schema-width, row-group, column-count, and worker memory/stack isolation limits even after library patching.
5. Treat parser crashes as security-relevant availability events when the parser is reachable from network uploads, CI artifacts, or tenant-provided datasets.

## Durable controls

- Framework file managers need a single canonical path policy for all user-controlled path components, including field IDs and client-supplied filenames.
- Operators should create the narrowest possible service-account permissions and avoid cluster-wide review or monitoring roles for namespace-created workloads unless explicitly required.
- Namespace admins are not automatically cluster-trusted; secret-read permission inside one namespace can become a bridge to wider metadata exposure when operators bind powerful service accounts.
- Parser code should validate declared widths and counts before stack allocation or recursive processing.
- Data import pipelines should isolate untrusted file parsing in resource-capped workers with crash-only recovery and no ambient credentials.
