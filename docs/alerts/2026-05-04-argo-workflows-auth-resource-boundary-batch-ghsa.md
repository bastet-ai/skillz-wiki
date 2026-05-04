# Argo Workflows auth, resource, and secret-boundary batch (GHSA)

**Signal:** GitHub Security Advisories REST fallback surfaced six Argo Workflows advisories on **2026-05-04**. The durable pattern is control-plane logic that trusted workflow, webhook, SSO, or sync input before enforcing the same authorization, size, and secret-handling invariants everywhere.

## Advisories in this batch

- **Artifact repository credentials logged in plaintext** — Argo Workflows `github.com/argoproj/argo-workflows/v4` `>= 4.0.0, < 4.0.5` logs artifact driver structs during artifact operations, exposing S3, GCS, Azure, Git, and other repository credentials to anyone with workflow pod-log read access. Fixed in **4.0.5**. References: <https://github.com/advisories/GHSA-7vf8-2cr6-54mf>, CVE-2026-42295.
- **Strict/Secure template reference bypass** — Argo Workflows `v3 < 3.7.14` and `v4 >= 4.0.0, < 4.0.5` can still merge attacker-controlled `hostNetwork`, `securityContext`, or `serviceAccountName` fields into pods even when `templateReferencing: Strict/Secure` is intended to enforce hardened templates. Fixed in **3.7.14** and **4.0.5**. References: <https://github.com/advisories/GHSA-3775-99mw-8rp4>, CVE-2026-42296.
- **Unauthenticated webhook body memory exhaustion** — Argo Workflows `v3 < 3.7.14` and `v4 >= 4.0.0, < 4.0.5` read the full `/api/v1/events/` request body before authenticating or verifying signatures, allowing unauthenticated OOM denial of service. Fixed in **3.7.14** and **4.0.5**. References: <https://github.com/advisories/GHSA-jcc8-g2q4-9fxq>, CVE-2026-42294.
- **Sync ConfigMap provider missing authorization** — Argo Workflows `v4 >= 4.0.0, < 4.0.5` allowed authenticated users, including weak/fake bearer-token paths described by the advisory, to create, read, update, or delete synchronization-limit ConfigMaps without `auth.CanI` checks. Fixed in **4.0.5**. References: <https://github.com/advisories/GHSA-xchc-cqwg-g76q>, CVE-2026-42297.
- **SSO RBAC delegation nil-pointer DoS** — Argo Workflows `v4 >= 4.0.0, <= 4.0.4` can panic when namespace-level RBAC matches but SSO-namespace RBAC does not while `SSO_DELEGATE_RBAC_TO_NAMESPACE=true`. Fixed in **4.0.5**. References: <https://github.com/advisories/GHSA-p4gq-3vxj-f4jq>, CVE-2026-42183.

## Why this is durable

Workflow control planes are high-trust systems because they mint pods, mount secrets, read repositories, and broker webhooks. Small inconsistencies become large blast-radius bugs:

- Secret-bearing structs must never be logged whole.
- Template restrictions must filter every field that reaches the pod spec, not only the originally reported bypass field.
- Authentication and request-size limits must happen before body buffering or parsing.
- Authorization must wrap all resource providers, including internal sync/coordination objects.
- Optional auth objects must be treated as hostile input until nil-safe and fully authorized.

## Immediate triage

1. **Inventory Argo lines:** search Go modules, controller images, Helm charts, and cluster manifests for Argo Workflows v3/v4. Prioritize public Argo Servers and multi-tenant clusters.
2. **Patch:** upgrade v3 deployments to **3.7.14+** and v4 deployments to **4.0.5+**.
3. **Rotate leaked artifact credentials:** if affected v4 workflow-executor logs were readable by users or log aggregation systems, rotate artifact repository keys and review access logs for use after workflow execution.
4. **Lock template references:** temporarily restrict workflow creation by untrusted tenants and explicitly deny `hostNetwork`, privileged `securityContext`, and unexpected `serviceAccountName` values in admission policy.
5. **Constrain webhook ingress:** enforce reverse-proxy body limits and authentication/signature checks before requests reach Argo Server.
6. **Audit sync objects:** review ConfigMaps used for synchronization limits for unexpected creates, updates, deletes, or namespace drift.

## Hunt ideas

- Query log stores for artifact credentials, access-key patterns, GCS JSON key fragments, Azure account keys, or Git credentials emitted by workflow executor logs.
- Search workflow specs for `hostNetwork: true`, unexpected `serviceAccountName`, added capabilities, privileged containers, hostPath mounts, and security contexts not present in referenced templates.
- Review Argo Server memory/OOM events around large requests to `/api/v1/events/`.
- Inspect Kubernetes audit logs for Argo service accounts writing sync ConfigMaps outside expected operator workflows.
- Correlate SSO login errors or panics with namespace RBAC delegation rules.

## Durable controls

- Redact by construction: logging helpers should serialize explicit safe fields, not entire driver/client structs.
- Make policy final at the object that causes the side effect: pod admission, credential mount, ConfigMap write, and webhook parse paths all need local guards.
- Add negative regression tests for every field that can flow through template merges, not just the original exploit field.
- Require body-size caps before auth parsing and before app-layer buffering.
- Treat internal providers as API surfaces: every create/read/update/delete path needs authorization, audit events, and tenancy checks.

## Operator lesson

For orchestration platforms, trace from user-controlled YAML or HTTP to the Kubernetes object or secret-bearing client. If any merge, log, or provider write skips the final authorization/redaction step, assume tenants can turn it into lateral movement or credential theft.
