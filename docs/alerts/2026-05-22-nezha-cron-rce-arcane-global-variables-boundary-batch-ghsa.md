# Nezha cron RCE and Arcane global-variables boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-23 UTC.

This batch is durable because it turns fresh authorization-boundary advisories into operator checks for low-privilege monitoring-panel command fanout, cross-tenant telemetry exposure, and deployment-control variable poisoning. Use only in authorized lab or scoped assessment environments.

## What changed

- **Nezha Monitoring RoleMember cross-tenant cron RCE** — [GHSA-99gv-2m7h-3hh9](https://github.com/advisories/GHSA-99gv-2m7h-3hh9): `POST /api/v1/cron` and `PATCH /api/v1/cron/:id` are reachable through `commonHandler` by authenticated `RoleMember` users. A cron with `Cover=CronCoverAll` and `Servers=[]` passes the empty-list permission check, then `CronTrigger` fans the attacker-controlled command out to every server in `ServerShared`. With `PushSuccessful=true`, command output can be routed to an attacker-owned notification group.
- **Nezha Monitoring authenticated all-server telemetry WebSocket** — [GHSA-hvv7-hfrh-7gxj](https://github.com/advisories/GHSA-hvv7-hfrh-7gxj): `GET /api/v1/ws/server` uses authenticated-vs-guest state as a full access switch. Any authenticated member can receive unfiltered server IDs, names, host platform details, agent versions, resource state, traffic counters, last-active data, and other inventory from all monitored servers rather than only objects that pass `HasPermission`.
- **Arcane global variables admin-authorization bypass** — [GHSA-jpjh-jm2p-39hh](https://github.com/advisories/GHSA-jpjh-jm2p-39hh): `PUT /api/environments/{id}/templates/variables` accepts bearer/API-key authentication but omits the admin role check used by peer admin-sensitive handlers. Any authenticated non-admin can overwrite `.env.global`, which is merged into every project's compose-variable resolution and container environment. Poisoned keys such as `REGISTRY`, `IMAGE`, `DATABASE_URL`, or `SECRET_KEY` can redirect future deployments, break projects, or steer secrets toward attacker-controlled infrastructure.

## Operator triage

1. **Nezha role model:** confirm whether a scoped non-admin `RoleMember` account exists or can be created through an authorized test path such as admin-provisioned access or explicitly in-scope OAuth self-registration. Record version/commit evidence and whether `/api/v1/cron` and `/api/v1/ws/server` are reachable as that role.
2. **Nezha server inventory exposure:** compare the member's `GET /api/v1/server` results against the WebSocket stream. Vulnerable behavior is a filtered REST list paired with WebSocket entries for servers owned by other users or tenants.
3. **Nezha cron fanout:** in a lab, create a member-owned notification group pointing to an assessment listener, then submit a benign cron using `CoverAll`, empty `Servers`, a short scheduler, and a harmless command such as `id; hostname` or `printf skillz-nezha-cron-canary`. Do not run destructive commands or target production agents without explicit written authorization.
4. **Arcane deployment variable reachability:** identify Arcane instances where non-admin users or API keys are in scope. Check whether the variables UI is hidden from non-admins while the API endpoint still accepts writes.
5. **Arcane compose dependence:** inventory projects that reference global variables in image names, registries, database URLs, webhook endpoints, or secret-like configuration. Prioritize paths where a variable change affects the next deploy without another admin approval gate.

## Replayable validation boundaries

- **Nezha WebSocket proof:** as a scoped member, open `GET /api/v1/ws/server` with the member token and capture a single message. Vulnerable result: the stream includes a server ID/name or host metadata absent from the same user's filtered `GET /api/v1/server` response. Stop at metadata proof; do not continuously monitor tenant telemetry.
- **Nezha cron proof:** in an isolated deployment with two test servers owned by different users, create a member cron with `Servers=[]`, `Cover=1`, `PushSuccessful=true`, and `Command="printf skillz-nezha-cron-canary; hostname"`. Vulnerable result: both agents execute the marker and output reaches the member-owned notification sink.
- **Arcane variables proof:** as a non-admin test user, call `PUT /api/environments/0/templates/variables` with a harmless key such as `SKILLZ_CANARY=owned-by-member`, then trigger or preview a disposable project that references `${SKILLZ_CANARY}`. Vulnerable result: the global file changes and the disposable project resolves the member-written value.
- **Arcane image-redirection proof:** only in a lab, set a global variable used by a disposable compose file's image reference to an assessment-controlled registry namespace. Vulnerable result: the next deploy attempts to pull from the controlled registry. Do not poison shared production variables or run unapproved images.

## Reporting heuristics

- Frame Nezha cron as **role-gated authorization bypass to cross-tenant command fanout**, not as a generic command-injection issue. Include the member role, route, `Cover` / `Servers` values, scheduler, affected agent count, and benign command-output evidence.
- Frame Nezha telemetry as **object-level authorization missing in a WebSocket stream**. Good evidence shows the REST endpoint is correctly filtered while the stream is not, using sanitized server IDs and host metadata.
- Frame Arcane as **admin-only deployment-control plane exposed to authenticated non-admins**. Useful reports tie the endpoint to `.env.global`, then to compose substitution or container environment injection.
- Keep proofs reversible: use canary variables, disposable projects, lab agents, and assessment-owned listeners. Avoid reading secrets, altering real deployment images, or triggering unknown cron tasks unless the program owner explicitly authorizes that escalation.
