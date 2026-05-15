# Budibase, auth, filesystem, and crypto-boundary batch

Sources: GitHub Security Advisories updates on 2026-05-15.

This batch covers newly published or newly updated advisories across low-code datasource control planes, auth rate-limits/OAuth state, filesystem download/ticket stores, task-log secret handling, SSH transport trust, and memory-safety/panic-safety edges. The shared defensive lesson is that user-controlled identifiers, URLs, redirects, filenames, cryptographic protocol bytes, and log destinations must be treated as active boundary inputs, even when they arrive from authenticated users or internal automation.

## Advisories covered

- **Budibase datasource update authorization bypass** — [GHSA-44m2-crh7-f4q2](https://github.com/advisories/GHSA-44m2-crh7-f4q2): `@budibase/server < 3.38.1` protects `PUT /api/datasources/:datasourceId` with `TABLE/READ` instead of builder-level access, allowing authenticated app users to overwrite datasource connection settings such as host, port, and URL. Fixed in `3.38.1`.
- **Budibase REST datasource redirect SSRF bypass** — [GHSA-fgqv-jh4g-pvg2](https://github.com/advisories/GHSA-fgqv-jh4g-pvg2): `@budibase/server < 3.38.1` can validate the initial REST datasource URL but follow attacker-controlled redirects to blocked/internal targets. Fixed in `3.38.1`.
- **Budibase AI Extract File automation SSRF** — [GHSA-rpj4-7x2v-wjrf](https://github.com/advisories/GHSA-rpj4-7x2v-wjrf): `@budibase/server < 3.34.8` misses IP blacklist validation in an automation step that fetches files for AI extraction. Fixed in `3.34.8`.
- **Better Auth IPv6 rate-limit bypass** — [GHSA-p6v2-xcpg-h6xw](https://github.com/advisories/GHSA-p6v2-xcpg-h6xw): `better-auth < 1.4.17` and `>= 1.5.0-beta.1, < 1.5.0-beta.9` key rate limits too narrowly for IPv6, enabling prefix-rotation abuse. Fixed in `1.4.17` and `1.5.0-beta.9`.
- **Better Auth OAuth state mismatch** — [GHSA-wxw3-q3m9-c3jr](https://github.com/advisories/GHSA-wxw3-q3m9-c3jr): `better-auth < 1.6.2` can accept mismatched OAuth callback `state` when cookie-backed state storage is used without PKCE. Fixed in `1.6.2`.
- **SimpleSAMLphp CAS FileSystemTicketStore traversal** — [GHSA-jrrg-99xh-5j2q](https://github.com/advisories/GHSA-jrrg-99xh-5j2q): `simplesamlphp/simplesamlphp-module-casserver <= 7.0.2` allows path traversal in the filesystem ticket store, enabling reads/unserialize outside the intended ticket directory and conditional deletion. Fixed in `7.0.3`.
- **Sharp generic download object authorization bypass** — [GHSA-748w-hm6r-qc7v](https://github.com/advisories/GHSA-748w-hm6r-qc7v): `code16/sharp < 9.22.0` lets authenticated Sharp users download unrelated Laravel Storage objects through the generic download endpoint. Fixed in `9.22.0`.
- **Airflow OpenSearch task-log credential leak** — [GHSA-xccp-97wp-3gjg](https://github.com/advisories/GHSA-xccp-97wp-3gjg): `apache-airflow-providers-opensearch < 1.9.1` can leak credentials embedded in OpenSearch host URLs through task-log handling. Fixed in `1.9.1`.
- **Airflow Elasticsearch task-log credential leak** — [GHSA-g3jr-4jrm-jvqv](https://github.com/advisories/GHSA-g3jr-4jrm-jvqv): `apache-airflow-providers-elasticsearch < 6.5.3` can leak credentials embedded in Elasticsearch host URLs through task-log handling. Fixed in `6.5.3`.
- **goshs SSH host-key verification disabled** — [GHSA-mxg3-432p-mr72](https://github.com/advisories/GHSA-mxg3-432p-mr72): `goshs.de/goshs/v2 <= 2.0.6` disables SSH host-key verification, allowing transparent MITM of tunneled HTTP requests. Fixed in `2.0.7`.
- **rkyv panic-safety arbitrary code execution** — [GHSA-vfvv-c25p-m7mm](https://github.com/advisories/GHSA-vfvv-c25p-m7mm): `rkyv >= 0.8.0, < 0.8.16` has panic-safety bugs in `InlineVec::clear` and `SerVec::clear` that can enable arbitrary code execution. Fixed in `0.8.16`.
- **arnika UDP rotation, PQC, and KMS TLS weaknesses** — [GHSA-rc6v-5rmx-w5mv](https://github.com/advisories/GHSA-rc6v-5rmx-w5mv): `github.com/arnika-project/arnika <= 1.0.0` has medium-severity issues around UDP rotation, post-quantum crypto handling, and KMS TLS. No patched version was listed at publication time.

## Operator triage

1. Upgrade Budibase to at least `3.38.1` and assume any authenticated app user could have changed datasource hosts, ports, URLs, headers, or credentials before the fix. Review datasource history/backups and egress logs for private-IP, metadata-service, localhost, and redirect-following attempts.
2. For SSRF controls, validate the final destination after every redirect and DNS resolution, not only the first URL. Block private, link-local, loopback, metadata, and internal ranges after canonicalization; pin DNS results during connect where possible.
3. Upgrade Better Auth and verify rate-limit keys aggregate IPv6 by a defensible prefix and by stronger identity dimensions such as account, credential, device/session, ASN, and action. Regression-test prefix-rotation attempts.
4. For OAuth/OIDC callbacks, require exact state binding to the initiating browser session and use PKCE by default. Treat cookie-only state storage as insufficient unless callback state, nonce, and issuer/client binding are all verified server-side.
5. Upgrade SimpleSAMLphp casserver and Sharp. Review filesystem ticket directories, Laravel Storage objects, download logs, and any serialized ticket material for unexpected reads/deletes before assuming patching ended exposure.
6. Upgrade Airflow OpenSearch/Elasticsearch providers and rotate credentials that appeared in connection URLs or task logs. Prefer secret backends and scrub URLs before writing logs, exception traces, or rendered task metadata.
7. Upgrade goshs to `2.0.7`; inventory SSH tunnels that carry HTTP requests and enforce pinned/known host keys. Treat prior unauthenticated SSH tunnel use as potentially observable or modifiable by a network-positioned attacker.
8. Upgrade `rkyv` to `0.8.16` and review uses of archive/deserialization code in unsafe or FFI-adjacent contexts. Add panic-in-drop and unwind-safety tests around custom buffers.
9. For arnika deployments, track upstream remediation and compensate by isolating UDP/KMS paths, enforcing strict TLS validation for KMS calls, and monitoring for protocol downgrade or key-handling anomalies.

## Durable controls

- Authenticated low-privilege users are still attackers at control-plane boundaries. Datasource, tunnel, storage, and automation endpoints need builder/admin authorization, object ownership checks, and server-side policy enforcement.
- SSRF defenses must be destination-based and redirect-aware. Run allowlist/denylist checks after URL parsing, redirect resolution, DNS resolution, and IP canonicalization.
- OAuth state is a browser-session boundary, not a convenience token. Bind state to issuer, client, redirect URI, nonce, and PKCE verifier; fail closed on mismatch.
- Logs are a secret sink. Connection URLs, task metadata, exception traces, and rendered logs must redact credentials before persistence and before UI display.
- Filesystem-backed stores and generic download endpoints need containment checks after decoding, normalization, symlink resolution, and storage-driver mapping.
- Cryptographic and transport code should fail closed: unknown SSH host keys, malformed signatures, panic paths, and unpatched crypto protocol weaknesses should never silently degrade into trusted operation.
