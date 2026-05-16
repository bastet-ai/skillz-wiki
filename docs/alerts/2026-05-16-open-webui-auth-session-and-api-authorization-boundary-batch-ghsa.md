# Open WebUI auth, session, and API authorization-boundary batch

Sources: GitHub Security Advisories updates on 2026-05-15.

This batch is durable because it is not one bug class: it is the same authorization mistake repeated across tools, shared chat, background tasks, completions, channels, collaborative documents, folders, LDAP/OAuth bootstrap, Socket.IO sessions, and API-key handling. Client-visible role, read permission, shared-chat state, or endpoint restrictions are not authorization unless each mutation and backend worker enforces the intended subject-object-action tuple.

## Advisories covered

- **Open WebUI: Missing `workspace.tools` Authorization Check on Tool Update Endpoint Allows Privilege Escalation to Code Execution** — [GHSA-p4fx-23fq-jfg6](https://github.com/advisories/GHSA-p4fx-23fq-jfg6) / CVE-2026-45395 (high).
- **Open WebUI: LDAP and OAuth First-User Race Condition Allows Multiple Admin Accounts** — [GHSA-h3ww-q6xx-w7x3](https://github.com/advisories/GHSA-h3ww-q6xx-w7x3) / CVE-2026-45675 (high).
- **Open WebUI: shared-chat branch ignores access_type, allowing unauthorized file deletion** — [GHSA-26g9-27vm-x3q8](https://github.com/advisories/GHSA-26g9-27vm-x3q8) / CVE-2026-45671 (high).
- **Open WebUI: Low-privilege authenticated users can enumerate and stop global background tasks, causing system-wide chat disruption** — [GHSA-8jjp-r2w2-4v22](https://github.com/advisories/GHSA-8jjp-r2w2-4v22) / CVE-2026-45399 (high).
- **Open WebUI has an IDOR vulnerability in the pin_channel_message API endpoint** — [GHSA-5gc6-xhv4-2wg6](https://github.com/advisories/GHSA-5gc6-xhv4-2wg6) / CVE-2026-45386 (medium).
- **Open WebUI has an IDOR vulnerability in the update_message_by_id API endpoint** — [GHSA-wwhq-cx22-f7vv](https://github.com/advisories/GHSA-wwhq-cx22-f7vv) / CVE-2026-45385 (medium).
- **Open WebUI has Broken Access Control for Completions API** — [GHSA-gfm2-xm6c-37qc](https://github.com/advisories/GHSA-gfm2-xm6c-37qc) / CVE-2026-45349 (high).
- **Open WebUI's API key endpoint restrictions bypassed via `x-api-key` header — full message processing on restricted endpoints** — [GHSA-57q6-fvp4-pqmm](https://github.com/advisories/GHSA-57q6-fvp4-pqmm) / CVE-2026-45339 (medium).
- **Open WebUI: Deactivated Channel Members Retain Full Access to Group/DM Channels** — [GHSA-hmgr-67hw-j2cq](https://github.com/advisories/GHSA-hmgr-67hw-j2cq) / CVE-2026-44561 (medium).
- **Read-Only Open WebUI Users Can Modify Collaborative Documents via Socket.IO** — [GHSA-vrfh-rj4q-rmhr](https://github.com/advisories/GHSA-vrfh-rj4q-rmhr) / CVE-2026-44564 (medium).
- **Open WebUI Missing Access Check on Channel Members Endpoint for Standard Channels** — [GHSA-c7wp-3qh5-55pv](https://github.com/advisories/GHSA-c7wp-3qh5-55pv) / CVE-2026-44559 (medium).
- **Open WebUI's Channel Access Grants Bypass filter_allowed_access_grants** — [GHSA-7rjh-px4v-5w55](https://github.com/advisories/GHSA-7rjh-px4v-5w55) / CVE-2026-44558 (medium).
- **Open WebUI's responses passthrough endpoint lacks access control authorization** — [GHSA-hp5m-24vp-vq2q](https://github.com/advisories/GHSA-hp5m-24vp-vq2q) / CVE-2026-44556 (high).
- **Open WebUI: Stale Admin Role in Socket.IO Session Pool Enables Post-Demotion Cross-User Note Access** — [GHSA-45m8-cpm2-3v65](https://github.com/advisories/GHSA-45m8-cpm2-3v65) / CVE-2026-44553 (high).
- **Open WebUI's Mass Assignment via Pydantic extra='allow' Allows Creating Folders in Other Users' Accounts** — [GHSA-hr43-rjmr-7wmm](https://github.com/advisories/GHSA-hr43-rjmr-7wmm) / CVE-2026-44550 (medium).
- **Open WebUI has an LDAP Empty Password Authentication Bypass** — [GHSA-2r4p-jpmg-48f4](https://github.com/advisories/GHSA-2r4p-jpmg-48f4) / CVE-2026-44551 (critical).

## Operator triage

1. Inventory Open WebUI deployments that allow self-service login, LDAP/OAuth bootstrap, API keys, collaborative documents, channel sharing, background task control, tool editing, or shared-chat file operations.
2. Test least-privileged accounts against completions, responses passthrough, tool update, task stop/list, channel member, pin/update message, folder create, and shared-chat deletion paths; confirm demoted/deactivated users lose websocket and channel access immediately.
3. Review auth logs for empty-password LDAP attempts, multiple first-admin creations, unexpected admin/socket sessions after demotion, API-key use on restricted endpoints, and non-owner modifications of channels, folders, tools, or documents.
4. If unauthorized admin/tool/code-execution access is suspected, rotate tool secrets, OAuth/LDAP credentials, API keys, and model/provider tokens; invalidate sessions and websocket pools.

## Durable controls

- Authorization checks must be centralized and action-specific, but enforced at every transport: REST, Socket.IO, background workers, tool update flows, shared-chat branches, and model/completion passthroughs.
- Role changes and deactivation must revoke live websocket/session state, cached role claims, channel grants, and background-worker authority immediately.
- API keys are principals, not bypass tokens. Endpoint restrictions must be checked after all alternate header names, compatibility routes, and proxy/pass-through paths normalize credentials.
- First-user/bootstrap logic needs a transaction or one-time server-side lock; external identity providers do not make race-prone admin creation safe.
- Mass assignment protections should default to reject extra fields and derive owner/workspace from authenticated server context, never from caller JSON.
