# Nezha, AstrBot, Beetl, and API-client boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-23 UTC.

This batch is durable because it turns fresh advisories into operator checks for low-privilege monitoring-panel pivots, upload path traversal, template expression execution, and server-supplied API-client URL trust. Use only in authorized lab or scoped assessment environments.

## What changed

- **Nezha Monitoring RoleMember SSRF with full response reflection** — [GHSA-w4g9-mxgg-j532](https://github.com/advisories/GHSA-w4g9-mxgg-j532) / CVE-2026-46717: `POST /api/v1/notification` and `PATCH /api/v1/notification/:id` are reachable through `commonHandler` by `RoleMember` users. The notification test sends a request to a user-controlled URL and reflects the entire non-2xx response body back to the caller, creating an intranet HTTP read primitive from the dashboard hub.
- **Nezha Monitoring cross-user cron task triggering** — [GHSA-rxf6-wjh4-jfj6](https://github.com/advisories/GHSA-rxf6-wjh4-jfj6) / CVE-2026-47120: member-reachable alert-rule and service-monitor writes accept `FailTriggerTasks` and `RecoverTriggerTasks` IDs without checking task ownership. When the alert or service trips, Nezha can execute another user's existing cron task, including admin-created tasks, across its configured server fanout.
- **AstrBot dashboard upload path traversal** — [GHSA-f63h-wc26-pmvc](https://github.com/advisories/GHSA-f63h-wc26-pmvc) / CVE-2026-8754: versions before 4.23.6 allow `filename` manipulation in `astrbot/dashboard/routes/chat.py` `post_file`, enabling remote path traversal through the file-upload handler. The advisory links a public exploit and the fixing commit.
- **Beetl Spring Classic `SpELFunction` expression injection** — [GHSA-fmmw-44rp-jcfp](https://github.com/advisories/GHSA-fmmw-44rp-jcfp) / CVE-2026-8759: `com.ibeetl:beetl-spring-classic` through 3.20.2.RELEASE exposes an expression-language injection risk in `SpELFunction`. Treat reachability as application-specific: the operator value is finding where templates route attacker-controlled arguments into that extension function.
- **Instagram automation client signup-challenge path trust** — [GHSA-ggxf-37hm-9wqf](https://github.com/advisories/GHSA-ggxf-37hm-9wqf) for `instagrapi` before 2.6.9 and [GHSA-jh37-x3fv-4x72](https://github.com/advisories/GHSA-jh37-x3fv-4x72) / CVE-2026-47157 for `aiograpi` before 0.9.10: server-supplied signup challenge paths were used to build request URLs before relative Instagram API path validation. A malicious or tampered challenge payload can move challenge-handling requests outside the intended Instagram host while carrying existing session headers.

Tracked but not promoted as primary operator guidance this pass: [GHSA-38m6-82c8-4xfm](https://github.com/advisories/GHSA-38m6-82c8-4xfm) / Parse Server pre-auth client-version regex backtracking DoS. It is useful for resource-budget hardening but remains availability-only for the current Skillz Wiki taxonomy.

## Operator triage

1. **Nezha exposure:** fingerprint Nezha dashboards where a non-admin `RoleMember` account is in scope. Record version or commit evidence, reachable authenticated API routes, and whether notification and alert/service management routes are member-accessible.
2. **Nezha SSRF path:** test notification creation with a lab listener first, then a harmless internal HTTP canary such as a controlled metadata mock or intranet test endpoint. Confirm whether non-2xx response bodies are reflected in the JSON error path. Avoid targeting real cloud metadata services or sensitive internal systems during discovery.
3. **Nezha cron pivot:** enumerate only task IDs visible or provided in the scoped test plan. In a lab, attach a member-owned alert to a benign admin-owned cron that writes a marker or echoes a fixed string. Do not trigger unknown production cron jobs.
4. **AstrBot upload boundary:** identify dashboard exposure, authentication requirements, and whether chat file upload reaches `post_file`. Test traversal with a reversible marker path inside a disposable lab container or a scoped temp directory; do not overwrite application code or secrets.
5. **Beetl reachability:** search Java/Spring templates and controllers for Beetl `SpELFunction` usage where template parameters, query fields, CMS content, or admin-configured expressions can influence the expression string. Prioritize public render paths and low-privilege content-editing paths.
6. **API-client URL trust:** find internal automation, bot, or scraping services using `instagrapi < 2.6.9` or `aiograpi < 0.9.10`. The key question is whether an attacker can tamper with challenge payloads, proxy responses, DNS/TLS trust, or test fixtures that feed signup challenge paths.

## Replayable validation boundaries

- **Nezha SSRF proof:** as a scoped `RoleMember`, create a notification with `URL` set to an assessment-controlled HTTP listener and `SkipCheck=false`. Return a controlled `500` body such as `skillz-ssrf-canary`. Vulnerable result: the dashboard request reaches the listener and reflects the canary body to the member.
- **Nezha cron proof:** in a lab with one admin-owned benign cron task, submit a member alert-rule or service monitor referencing that task ID in `FailTriggerTasks`. Trip the alert with a controlled condition. Vulnerable result: the admin cron marker runs even though the member does not own the task.
- **AstrBot traversal proof:** upload a harmless file with a traversal-bearing `filename` that attempts to land in a lab-only sibling marker directory. Vulnerable result: the saved file path escapes the intended upload directory. Keep the destination disposable and capture filesystem evidence without reading unrelated files.
- **Beetl expression proof:** in a local vulnerable app that intentionally exposes `SpELFunction`, pass a side-effect-free expression such as arithmetic, string concatenation, or a fixed environment marker allowed by the lab harness. Only attempt command or file primitives if the program owner explicitly authorizes that escalation.
- **API-client path proof:** use a controlled test harness that mocks the Instagram challenge response with an absolute or scheme-relative challenge path pointing to a listener. Vulnerable result: the client sends follow-up challenge handling traffic to the listener with session-associated headers; patched clients reject the path before URL construction.

## Reporting heuristics

- Frame Nezha SSRF as **role-gated server-side fetch plus response-body reflection**, not merely a blind callback. Include the member role, route, request body fields, listener logs, and reflected canary.
- Frame Nezha cron triggering as **object ownership missing on deferred execution IDs**. The evidence should show member control over `FailTriggerTasks` / `RecoverTriggerTasks`, the referenced task owner, and a benign marker execution.
- Frame AstrBot as **upload filename canonicalization failure**. Include affected version, exact upload route, sanitized request/response, and marker path only.
- Frame Beetl as **template extension expression injection** only when an attacker-controlled expression reaches `SpELFunction`; otherwise report dependency exposure as a hardening note, not an exploit path.
- Frame the Instagram client issues as **server-supplied path trust in API automation**. Useful reports explain how the assessment can influence challenge payloads and what sensitive headers or session context leave the intended host.
