# Trigger.dev coordinated wave: friendlyId tenant lookups, shipped default secrets, all-interface MCP server, and query-compiler SQLi (29 GHSAs)

Source: GitHub Security Advisory coordinated dump published 2026-10-21 03:32Z — 29 advisories in under ten minutes, CVE-2026-114065 through CVE-2026-114093, fix bands scattered across `4.5.0`–`4.7.6` for the `@trigger.dev/api`, `worker`, `cli`, and `webapp` packages. Related existing pages: [Oct 2 AI serving/RAG stack wave](2026-10-02-ai-serving-rag-stack-authz-and-path-wave-ghsa.md) (this product's first two Trigger.dev tiers, 19:31Z pair + seven-GHSA second tier), [Sept 17 Graylog/WikiJS/Trigger.dev boundaries](2026-09-17-graylog-redirect-ssrf-wikijs-triggerdev-rundeck-empire-and-attestation-verifier-boundaries-ghsa.md).

## What changed

This is the full-dump tier: the same control plane already covered on the Oct 2 page, swept end-to-end by an outside audit. The durable value is the *shapes* — nearly every leg is a tenant-boundary failure on a self-hosted or multi-tenant deployment, and the shapes generalize to any job-orchestration/agent platform that addresses runs, schedules, and deployments by opaque public IDs.

## Leg inventory by mechanism

### A. FriendlyId-addressed objects resolved without caller scoping (seven legs, one invariant)

| Leg | Route / sink | Cross-tenant effect |
|---|---|---|
| [GHSA-4ggh-4c33-wrjj](https://github.com/advisories/GHSA-4ggh-4c33-wrjj) (`taskruns.$runParam.replay`, fixed 4.5.0) | Dashboard run-replay action handler had **no auth or org check** and looked the run up by `friendlyId` alone | Replay a victim's run into an attacker-chosen environment — read the victim's task payload or re-execute the task **with the victim's secrets** |
| [GHSA-633q-685h-8gxm](https://github.com/advisories/GHSA-633q-685h-8gxm) (`api.v1.runs.$runParam.replay`) | API twin of the same replay route, unscoped lookup | Any tenant's API key + victim friendlyId ⇒ payload disclosure |
| [GHSA-r27f-m68x-3cjm](https://github.com/advisories/GHSA-r27f-m68x-3cjm) | `createDeploymentBackgroundWorkerV4` resolves `WorkerDeployment` by friendlyId, no env/project/org scope | Re-point a victim's in-progress deployment at the attacker's worker (build/run interception) |
| [GHSA-fcjm-vhq5-69j3](https://github.com/advisories/GHSA-fcjm-vhq5-69j3) | `DeleteTaskScheduleService` / `SetActiveOnTaskScheduleService` accept victim schedule friendlyId via attacker's own project route | Delete/disable other orgs' IMPERATIVE cron schedules |
| [GHSA-38r8-4jhq-5h69](https://github.com/advisories/GHSA-38r8-4jhq-5h69) | Batch creation accepts foreign `parentRunId` + `resumeParentOnCompletion` | Indefinitely suspend or error-inject into production/cross-org runs |
| [GHSA-q775-f6f3-5923](https://github.com/advisories/GHSA-q775-f6f3-5923) | Waitpoint token wait accepts victim runId with attacker waitpoint | Block a victim run forever on a waitpoint they cannot complete; inject resume data |
| [GHSA-49rg-27pr-85f9](https://github.com/advisories/GHSA-49rg-27pr-85f9) | `DeploymentService.getDeployment` scopes by `projectId` only | A dev/preview/CI-scoped secret key cancels in-progress **production** deployments in the same project |

Sibling: [GHSA-3p6g-7xq3-87rv](https://github.com/advisories/GHSA-3p6g-7xq3-87rv) — project members complete *another member's* DEVELOPMENT waitpoint (per-user ownership check skipped).

### B. Query compilers concatenate unescaped fragments past the tenant guard

- [GHSA-vmhj-4cqp-m5cj](https://github.com/advisories/GHSA-vmhj-4cqp-m5cj): the TSQL→ClickHouse compiler concatenates **window-function names** into generated SQL with no allowlist/escape. A backtick-quoted identifier in `POST /api/v1/query` injects a raw subquery *outside the per-tenant WHERE guard* — cross-org analytics exfil with any authenticated customer credential.
- [GHSA-29hf-7539-5fj8](https://github.com/advisories/GHSA-29hf-7539-5fj8): `tags` parameter concatenated into the ElectricSQL shape `where` clause defeats the `runtimeEnvironmentId` tenant guard — stream every org's TaskRun records *including payloads and metadata* via `/realtime/v1/runs` with any `read:runs` project key.
- [GHSA-hgfc-cgqx-gchc](https://github.com/advisories/GHSA-hgfc-cgqx-gchc) (fixed 4.7.3): placeholder-table syntax `FROM {database.table}` — including inside subqueries — skips the table allowlist and tenant filters entirely.

### C. Shipped/default secrets and unauthenticated internal planes

- [GHSA-jm68-q9wf-qf39](https://github.com/advisories/GHSA-jm68-q9wf-qf39) (critical): self-hosted Docker Compose deployments using `hosting/docker/.env.example` secrets accept the hardcoded `MAGIC_LINK_SECRET` ⇒ forge magic-link tokens ⇒ **log in as any email**, then reach Postgres/Redis/ClickHouse with default credentials *from runner containers on the infrastructure networks*. Default secrets plus flat infra networking = full tenant compromise without exploiting a code bug.
- [GHSA-j3cj-67wq-q96g](https://github.com/advisories/GHSA-j3cj-67wq-q96g): the `/coordinator` Socket.IO namespace authenticated with the **published** coordinator-secret value; connect, emit `READY_FOR_EXECUTION` to receive decrypted run environment variables, or `TASK_RUN_FAILED_TO_RUN` to tamper with arbitrary runs.
- [GHSA-mjhg-96gj-78w9](https://github.com/advisories/GHSA-mjhg-96gj-78w9) (still open through 4.7.6 in the advisory band): the supervisor workload server authenticates nothing — a valid run/snapshot pair calls `attempts/start` to obtain **resolved environment variables and run JWTs**, or start/complete/suspend other tenants' runs.
- [GHSA-8v2q-27xw-2fjh](https://github.com/advisories/GHSA-8v2q-27xw-2fjh): `trigger dev --mcp` binds **all network interfaces** and serves unauthenticated `/sse` + `/messages` — LAN hosts or malicious web pages invoke `trigger-task`, `cancel-run`, `list-runs`, `get-run-logs` with the developer's stored access token.
- [GHSA-h43q-m2j9-rjvp](https://github.com/advisories/GHSA-h43q-m2j9-rjvp): `POST /realtime/v1/streams/:runId/:streamId` is unauthenticated; predictable run friendlyIds allow injecting arbitrary data into any environment's realtime stream, production included.
- [GHSA-r9qj-p24x-r8fw](https://github.com/advisories/GHSA-r9qj-p24x-r8fw): path traversal in `api/v1/packets`.

### D. Credential uplift and leak surfaces

- [GHSA-8jgj-f949-3f8m](https://github.com/advisories/GHSA-8jgj-f949-3f8m): `GET /api/v1/projects/:projectRef/envvars` returns the environment **root** `TRIGGER_SECRET_KEY` (plus plaintext secrets) to a caller holding only a restricted `read:envvars` key — capability-restricted key ⇒ root key ⇒ admin public JWTs.
- [GHSA-8hxg-26q3-8q8c](https://github.com/advisories/GHSA-8hxg-26q3-8q8c): the dashboard Agent input proxy stores a delegated `userActorToken` in **browser-readable session input records**; a chat's public session token reads `in records`, recovers `payload.metadata.userActorToken`, and replays it for an environment JWT.
- [GHSA-rwgj-7gch-9v4q](https://github.com/advisories/GHSA-rwgj-7gch-9v4q): public-token holders with session-write obtain environment-wide S2 stream credentials — append/fabricate or permanently trim other sessions' run streams.
- [GHSA-4mgf-q8vv-4g8c](https://github.com/advisories/GHSA-4mgf-q8vv-4g8c): `PUT snapshot-url` hands public session tokens presigned S3 **write** URLs — forge the agent's durable conversation history (secret-key-only check missing).
- [GHSA-45vw-83pv-f4m9](https://github.com/advisories/GHSA-45vw-83pv-f4m9): CLI debug deployment logs serialize **unredacted** envVars (`Starting buildWorker` record) — resolved secrets land in terminal transcripts, CI debug logs, and support bundles.
- [GHSA-h43q-265v-xjq4](https://github.com/advisories/GHSA-h43q-265v-xjq4): a read-only user-actor token plus the legacy personal-access-token helper creates alert channels — route future production deployment/error alerts to attacker infrastructure.

### E. Webhook SSRF and special-use-range deny-list miss

- [GHSA-27gg-p82j-765m](https://github.com/advisories/GHSA-27gg-p82j-765m): the SSRF guard's `isUnsafeIPv4` **omits the 198.18.0.0/15 benchmarking range** (RFC 2544) — internally routed services reachable through alert-channel webhooks, blind probing plus limited state-changing POSTs.
- [GHSA-7vxq-646g-jm2r](https://github.com/advisories/GHSA-7vxq-646g-jm2r) / [GHSA-3mx6-67xp-8wvp](https://github.com/advisories/GHSA-3mx6-67xp-8wvp): earlier legs of the same sink — webhook alert-channel URL unvalidated ⇒ loopback/internal/metadata POSTs, IMDSv1 reachable via redirect, HMAC-signed so the internal request looks legitimate (the creation-schema-vs-delivery-sink parity rule from the Oct 2 page, now confirmed by the auditor).

### F. CSRF / OAuth-state legs

- [GHSA-4f8m-hpg5-f5x5](https://github.com/advisories/GHSA-4f8m-hpg5-f5x5): loading `/account/authorization-code/<code>` mints a Personal Access Token with **no consent step**, and `/api/v1/token` exchanges codes without authentication — lure a logged-in user to the code URL ⇒ full account takeover.
- [GHSA-8fgg-399q-2r8f](https://github.com/advisories/GHSA-8fgg-399q-2r8f): org-level Slack OAuth uses the **organization ID as the OAuth `state`** — no session binding; a member opening an unredeemed callback connects an attacker-controlled Slack workspace that then receives the org's operational alerts.
- [GHSA-pfmq-q2wh-m57j](https://github.com/advisories/GHSA-pfmq-q2wh-m57j): GET-based `/logout` forced logout (noted; thin).

## Durable rules for the sweep kit

1. **Public IDs are capabilities when lookups are unscoped.** Every route that accepts a `friendlyId`-style opaque identifier must be probed with *attacker-scoped credentials + victim ID*. On job platforms the ID surface is large (run replay, deployments, schedules, waitpoints, batch parents, packets) — enumerate the handler list first, then run the resolve-and-act decision table per route. Seven legs here share one root cause.
2. **State-machine inputs are tenant boundaries too.** `parentRunId`, waitpoint tokens, and background-worker bindings let a valid low-privilege key *block, suspend, or re-point* other tenants' production runs. Availability-affecting cross-tenant writes deserve the same sweep as reads.
3. **Query compilers are SQLi sinks with a tenant guard attached.** When a platform parses a SQL-like DSL then re-emits SQL (window-function names, tags into a `where` clause, `{placeholder}` table refs), test: backtick-quoted identifiers, boolean appendage, and any placeholder/template syntax the DSL itself documents. The tenant WHERE is only as strong as the most-concatenated token.
4. **SSRF deny-lists miss special-use ranges.** `198.18.0.0/15` (benchmarking) joining the standard battery alongside `100.64.0.0/10`, `fc00::/7`, `::1`, and the already-tested `169.254.169.254` — every webhook/URL-guard egress path gets the full reserved-range matrix.
5. **`.env.example` secrets are public source.** For self-hosted platforms: fingerprint the shipped example files (forge auth with them out-of-band in a lab copy), enumerate Socket.IO/WS namespaces separately from REST auth, and treat runner-container network access to infra datastores as part of the chain.
6. **CLI-embedded dev servers bind 0.0.0.0.** `--mcp` style flags that serve token-bearing tools (here over unauthenticated `/sse`+`/messages`) are browser-pivot and LAN surfaces; on authorized workstation assessments, check bind address + absence of origin checks for every dev-mode server the target platform ships.
7. **Version-band fingerprinting is the engagement step.** Fix bands span 4.5.0→4.7.6 across four packages, and the supervisor plane stays reachable through 4.7.6 — a bare "4.x" banner tells you nothing. Map each package (api/worker/cli/webapp) to its own band before claiming a leg closed.

## Validation boundaries

Lab/self-hosted disposable Trigger.dev only, with synthetic runs and marker payloads. Forge magic links / coordinator events only against your own deployment with throwaway tenant data; SSRF legs to owned callbacks; query-compiler legs to canary rows in a second disposable org — never real customer analytics. No production run cancellation, schedule deletion, or run-blocking on shared instances; the cross-tenant state legs are destructive by nature.

## Sources

- Wave range: CVE-2026-114065–CVE-2026-114093 / [GHSA index](https://github.com/triggerdotdev/trigger.dev/security/advisories) (published 2026-10-21T03:32Z)
- Prior tiers: [Oct 2 AI serving wave — Trigger.dev second tier](2026-10-02-ai-serving-rag-stack-authz-and-path-wave-ghsa.md), [Sept 17 boundaries page](2026-09-17-graylog-redirect-ssrf-wikijs-triggerdev-rundeck-empire-and-attestation-verifier-boundaries-ghsa.md)
- Same-wave tracked no-publish: Snipe-IT webhook-test SSRF single, SvelteKit vite-preview Windows traversal + self-fetch redirect SSRF (known dev-server/HMR-proxy class), Dulwich legs mirroring the Oct 3 four-pack on the July 1 repo-trust page (stash pop, CommitFilter, DOS drive prefix, checkout symlink), Coraza trio restating the Oct 8 WAF-divergence advisories under fresh GHSA IDs (vmwg = JSON dot-flattening collision, 5846 = Content-Type exact-match body-inspection skip, 7xj5 = `filename*` charset decoy — mechanism already covered on the [Oct 6 Coraza page](2026-10-06-coraza-waf-evasion-wave-argument-limit-silent-drop-multipart-truncation-and-audit-log-forgery-ghsa.md)), adm-zip duplicate-entry getEntry-vs-extract divergence + bomb-bypass (same parser-differential class as the July 28 extraction page), uv wheel entry-point PATH-shadowing write (known package-manager file-write class), Mandiant FLARE capa/floss workspace deserialization (known tool-workspace deser class), X2000R boa overflow/cmd-injection batch (same appliance audit as the Oct 20 wave), Chrome 156 memory-safety pack, Mozilla::CA emSign root re-listing
