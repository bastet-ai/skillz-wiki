---
title: Realtime view-framework state-binding boundaries: djust WebSocket mass-assignment, DEBUG-gated observability endpoints, and OTel macOS PATH hijack
---

# Realtime view-framework state-binding boundaries: djust WebSocket mass-assignment, DEBUG-gated observability endpoints, and OTel macOS PATH hijack

A September 16 late GitHub wave (published 2026-09-16T13:48–13:55Z) adds three durable operator checks on two recurring axes: **client-writable server-side state in realtime/interactive frameworks**, and **security controls that live outside the enforcement path**.

- **djust** (Django LiveView-style library): the default `update_model` WebSocket handler `setattr`s a view attribute whose **name is client-supplied**, gated only by a `_`-prefix reject, a 14-entry framework-internals denylist, `hasattr` existence, and an **opt-in allowlist that defaults to allow-all** — so any public view attribute (authorization flags, ownership IDs, prices) is writable from the client, not just fields actually bound with `dj-model=` in the template (CVSS high, CVE-2026-61598, fixed 1.0.7).
- **djust observability endpoints**: the localhost gate for endpoints exposing live view/session state and a remote method-invocation surface (`eval_handler`) was an **opt-in middleware that the documented setup omits**; the views themselves enforced only `DEBUG` — in the documented configuration a non-localhost client could read live state and invoke handlers remotely (CVSS 7.4, CVE-2026-61590, fixed 1.0.7).
- **OpenTelemetry.Resources.Host** (.NET): the macOS `host.id` detector launched `sh` and `ioreg` by **bare name instead of absolute path**, so a less-privileged local user who can influence `PATH` (or write a `PATH` directory ahead of system dirs) gets code execution in the application's security context (CVSS 7.0, CVE-2026-81192, fixed 1.16.0-beta.2; the Go SDK has the sibling [GHSA-9h8m-3fm2-qjrq](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-9h8m-3fm2-qjrq)).

Sept 16 late-afternoon follow-ups (published 2026-09-16T15:32–15:45Z) add two more djust fail-opens on the same live-transport axis: **multi-tenant isolation enforced only on the HTTP path** (the WebSocket/SSE path leaked every tenant's rows) and **CSRF-free SSE transport** (cross-origin pages could drive a victim-cookie-authenticated LiveView session).

Sources:

- djust mass-assignment: [GHSA-cc7c-9jff-58wj / CVE-2026-61598](https://github.com/advisories/GHSA-cc7c-9jff-58wj) (pip `djust < 1.0.7`)
- djust observability exposure: [GHSA-8g2f-g3gq-5rjv / CVE-2026-61590](https://github.com/advisories/GHSA-8g2f-g3gq-5rjv)
- djust multi-tenant fail-open on WS/SSE: [GHSA-3492-cvg7-9mr2 / CVE-2026-61595](https://github.com/advisories/GHSA-3492-cvg7-9mr2)
- djust SSE transport CSRF: [GHSA-pg97-jvmf-qfvc / CVE-2026-61593](https://github.com/advisories/GHSA-pg97-jvmf-qfvc)
- OpenTelemetry.Resources.Host PATH hijack: [GHSA-v8pv-4842-x354 / CVE-2026-81192](https://github.com/advisories/GHSA-v8pv-4842-x354) (NuGet `< 1.16.0-beta.2`, macOS only), fix PR [dotnet-contrib #4760](https://github.com/open-telemetry/opentelemetry-dotnet-contrib/pull/4760)

!!! warning "Authorized validation only"
    Disposable djust apps with synthetic view state, local lab paths, and throwaway credentials only. For the PATH-hijack class, prove with a marker binary in a disposable PATH directory inside your own lab account — never against shared services, and never persisting an attacker-controlled binary on a shared host.

## djust: WebSocket event handlers are a mass-assignment surface, and denylists miss business state

The shape is the classic mass-assignment bug relocated to the WebSocket layer: `{type:event, event:"update_model", params:{field, value}}` sets **any public, existing view attribute**, with type coercion matching the target (`"true"` → `True`). The controls that exist all fail the fail-closed test:

1. Denylist covers framework plumbing (14 internals), **nothing about developer authz/ownership/business state** (`account_id`, `is_admin`, `total_price` are all settable).
2. The allowlist (`allowed_model_fields`) defaults to `None` = allow all — opt-in security is off-by-default.
3. `hasattr` existence is satisfied precisely because the developer kept the authz value as a view attribute — the normal pattern in this framework style.

Operator checks for any LiveView/Livewire/StimulusReflex-class realtime framework:

1. Enumerate default-on event handlers inherited by every view (the base-class MRO is the attack surface, not just user-defined handlers).
2. For each handler that names a server-side object by client input, build a decision table: bound-in-template field (expected allow) vs. unbound public attribute (should deny). Set an `is_admin`-shaped canary that was never bound and confirm the reject.
3. Check allowlist defaults in the deployed version — read the shipped source for `= None` / `= []` defaults on any authorization-adjacent config.
4. Downstream handlers that act on view state **without re-authorizing** are where state tampering becomes IDOR/authz break; trace one settable attribute to a mutation sink before claiming impact.

## djust observability: a control in an uninstallable middleware is not a control

The durable generalization: **an access restriction implemented as separate, opt-in middleware — and omitted from the documented setup — is a documentation-shaped fail-open.** Any endpoint family (debug panels, live-state inspectors, eval/handler-invocation routes) whose only gate is `DEBUG` plus optional middleware is exposed in exactly the configuration the getting-started guide produces.

1. On authorized targets, enumerate observability/debug route families (`/djust/`-style, dashboard, inspector, eval endpoints) from a non-localhost perspective with the app in its documented default config.
2. Treat `DEBUG=True`-gated endpoints as unauthenticated for recon triage — but validate the actual response; a non-disclosing 404/403 from the fixed in-view check is the negative control.
3. Audit rule for code review engagements: grep enforcement — is the restriction checked **in-view** (fixed shape) or only in optional middleware (broken shape)? Remote-invocation surfaces (`eval_handler` classes) need the strictest gate.

## djust late-wave follow-ups: tenant isolation and CSRF checks that exist only on the HTTP path

Two same-day follow-up advisories (published 15:32–15:45Z, both fixed in 1.0.7) complete the picture: the framework's *other* two security controls were also enforced exclusively on the classic HTTP request path while the live transports bypassed them.

1. **Multi-tenant fail-open on WebSocket/SSE** ([GHSA-3492-cvg7-9mr2 / CVE-2026-61595](https://github.com/advisories/GHSA-3492-cvg7-9mr2)): current-tenant state lived in `threading.local()` set only by an HTTP-only middleware, so on the WS/SSE path the tenant was always `None` — and the tenant-aware manager **failed open** (returned the unfiltered queryset, ignoring `STRICT_MODE`), disclosing every tenant's rows to whoever held the socket. `threading.local` was additionally shared across connections on the `sync_to_async` executor thread. The fix moved tenancy to a `contextvars.ContextVar`, bound it around mount and every dispatch, and made the managers fail closed (`.none()`).
2. **SSE transport CSRF** ([GHSA-pg97-jvmf-qfvc / CVE-2026-61593](https://github.com/advisories/GHSA-pg97-jvmf-qfvc)): the SSE POST endpoints were `@csrf_exempt`, the GET stream endpoint had no Origin check, and the URL `session_id` was client-chosen (UUID-format-validated only), so a cross-origin page could GET the stream (mounting a LiveView **as the victim**) and POST state-changing events with `credentials: include`. A JSON body sent as `text/plain` is a CORS *simple request* — no preflight, no blocking. Fix: Origin validation against `ALLOWED_HOSTS` on all three endpoints plus `Content-Type: application/json` requirement (415 otherwise).

Operator checks these generalize to:

1. **Dual-path enforcement audit.** For any framework with both HTTP and live (WS/SSE) entry points into the same handlers, verify authn, authz, tenancy, and CSRF controls on **both** paths. Enumerate which middlewares are HTTP-only (`Middleware` classes registered in `MIDDLEWARE` never run for ASGI WebSocket/SSE routes). Test with a second-tenant socket, not a second-tenant cookie jar.
2. **Fail-open vs fail-closed on missing context.** When the tenant/user context is absent, does the query layer return everything (fail open) or nothing (fail closed)? A `None` context silently widening scope is the cross-tenant disclosure; probe with a canary row from another tenant and confirm the socket stream never yields it.
3. **Live-transport CSRF shape.** A `session_id` that is client-chosen and merely format-validated is not a CSRF token. Cross-origin GET that *creates server-side state* (mounting a view/session) plus `csrf_exempt` POSTs with `credentials: include` is a full cross-site request forgery chain even with zero CORS. Test from an owned cross-origin page: does the stream mount, do event POSTs fire handlers in the victim's authenticated context?
4. **`text/plain` simple-request awareness.** Any JSON endpoint that `json.loads` a raw body without checking `Content-Type` is reachable cross-origin without preflight. The negative control is a 415 on non-JSON content types.

## OpenTelemetry host detectors: telemetry shelling out to bare-name binaries is a local LPE surface

The macOS `host.id` resource detector has invoked `ioreg`/`sh` by bare name since introduction, so every .NET app using the detector resolves them through `PATH` — a user-writable early `PATH` directory or attacker-influenced environment yields execution in the app's (often higher-privileged) context. Linux and Windows unaffected for this specific detector.

Operator checks for local privilege-escalation recon and internal engagements:

1. Inventory services/agents that load telemetry SDKs (`.NET`/Go contrib detectors are common in auto-instrumented services) running above your token.
2. Check the service's effective `PATH` for directories writable by your principal (`daemon -af`, inherited env, installer-added paths) — this is the same untrusted-search-path primitive (CWE-426) as classic Windows DLL-side issues, but via `PATH`-resolved subprocesses.
3. Prove with a harmless marker binary named `ioreg`/`sh` in the writable path against a lab instance of the service; record the execution context (whoami). Do not plant binaries on shared hosts beyond the authorized scope, and remove markers immediately.
4. Generalize: any detector/instrumentation/library that runs system utilities (`ioreg`, `sysctl`, `scutil`, `wmic`-class) by bare name is a candidate — grep shipped assemblies/binaries for subprocess spawn sites.

## Reporting notes

- For djust-class findings, report the decision table (bound field vs. unbound attribute) plus the traced mutation sink for one attribute; state whether the app actually keeps authz state in public view attributes (severity hinges on it).
- For middleware-omitted exposure, include the documented-setup reproduction (exact config from the vendor docs) — the fail-open is the docs + default combination, not operator error.
- For PATH-hijack checks, report the writable-PATH-directory evidence, the spawn-site reference (bare name vs. absolute path), and the execution-context delta; state the affected OS constraint (macOS-only here).
