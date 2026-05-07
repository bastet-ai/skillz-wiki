# Tenant, session, cluster, and log boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** identity and control-plane batch where tenants, sessions, logs, or local workloads crossed intended authorization boundaries.

## Advisories covered

- **ShellHub cross-tenant namespace IDOR** — [GHSA-vwx9-7qcf-gg7f](https://github.com/advisories/GHSA-vwx9-7qcf-gg7f): API-key access bypassed membership checks on tenant namespace reads.
- **Daptin session expiration gap after password change** — [GHSA-258c-965c-p3hc](https://github.com/advisories/GHSA-258c-965c-p3hc): existing sessions could survive credential changes.
- **AstrBot hard-coded password** — [GHSA-mq9q-25hm-g4gp](https://github.com/advisories/GHSA-mq9q-25hm-g4gp): static credentials created a shared secret boundary failure.
- **OpenStack Keystone incorrect authorization** — [GHSA-hhq2-3832-xxcv](https://github.com/advisories/GHSA-hhq2-3832-xxcv): identity authorization did not consistently enforce the intended access boundary.
- **OpenStack Ironic Python Agent untrusted control-sphere inclusion** — [GHSA-rmxr-45gj-889w](https://github.com/advisories/GHSA-rmxr-45gj-889w): agent functionality could include behavior from an untrusted control sphere.
- **Talos Linux local privilege escalation from untrusted workloads** — [GHSA-m38g-vww2-mvgx](https://github.com/advisories/GHSA-m38g-vww2-mvgx): workload-local boundaries could be abused to gain higher host privileges.
- **Kubetail cross-site WebSocket hijacking** — [GHSA-v8j7-hp7c-738f](https://github.com/advisories/GHSA-v8j7-hp7c-738f): authenticated users' Kubernetes logs could be read through cross-origin WebSocket abuse.

## Why this is durable

Control planes are only as strong as their second authorization check. API keys, sessions, WebSockets, local workloads, and agent extensions must all re-bind the request to the tenant, principal, origin, and privilege level being accessed.

## Immediate triage

1. Patch affected ShellHub, Daptin, AstrBot, OpenStack, Talos, and Kubetail deployments.
2. Rotate hard-coded or vendor-default secrets, then verify they are no longer accepted anywhere in the fleet.
3. Invalidate active sessions after password resets, role changes, key rotations, and suspected account compromise.
4. Review Kubernetes log viewers and WebSocket endpoints for strict `Origin` checks, CSRF tokens, SameSite cookies, and per-namespace authorization.
5. Hunt for cross-tenant namespace reads, unexpected Keystone policy denials/allows, and workload-to-host privilege transitions.

## Durable controls

- Authorize every object read by tenant membership at the object boundary, not just by possession of an API key.
- Bind sessions to credential version, MFA state, and role version so security changes revoke stale sessions automatically.
- Require per-install generated secrets; fail startup when defaults or static secrets are present.
- Treat local workloads and management agents as mutually hostile; minimize host mounts/capabilities and audit agent-supplied code paths.
- For WebSockets, enforce origin and token checks during handshake and authorize every streamed resource after connection setup.
