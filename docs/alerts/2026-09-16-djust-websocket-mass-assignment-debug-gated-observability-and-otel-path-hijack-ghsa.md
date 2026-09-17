---
title: Realtime view-framework state-binding boundaries: djust WebSocket mass-assignment, DEBUG-gated observability endpoints, and OTel macOS PATH hijack
---

# Realtime view-framework state-binding boundaries: djust WebSocket mass-assignment, DEBUG-gated observability endpoints, and OTel macOS PATH hijack

A September 16 late GitHub wave (published 2026-09-16T13:48–13:55Z) adds three durable operator checks on two recurring axes: **client-writable server-side state in realtime/interactive frameworks**, and **security controls that live outside the enforcement path**.

- **djust** (Django LiveView-style library): the default `update_model` WebSocket handler `setattr`s a view attribute whose **name is client-supplied**, gated only by a `_`-prefix reject, a 14-entry framework-internals denylist, `hasattr` existence, and an **opt-in allowlist that defaults to allow-all** — so any public view attribute (authorization flags, ownership IDs, prices) is writable from the client, not just fields actually bound with `dj-model=` in the template (CVSS high, CVE-2026-61598, fixed 1.0.7).
- **djust observability endpoints**: the localhost gate for endpoints exposing live view/session state and a remote method-invocation surface (`eval_handler`) was an **opt-in middleware that the documented setup omits**; the views themselves enforced only `DEBUG` — in the documented configuration a non-localhost client could read live state and invoke handlers remotely (CVSS 7.4, CVE-2026-61590, fixed 1.0.7).
- **OpenTelemetry.Resources.Host** (.NET): the macOS `host.id` detector launched `sh` and `ioreg` by **bare name instead of absolute path**, so a less-privileged local user who can influence `PATH` (or write a `PATH` directory ahead of system dirs) gets code execution in the application's security context (CVSS 7.0, CVE-2026-81192, fixed 1.16.0-beta.2; the Go SDK has the sibling [GHSA-9h8m-3fm2-qjrq](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-9h8m-3fm2-qjrq)).

Sept 16 late-afternoon follow-ups (published 2026-09-16T15:32–15:45Z) add two more djust fail-opens on the same live-transport axis: **multi-tenant isolation enforced only on the HTTP path** (the WebSocket/SSE path leaked every tenant's rows) and **CSRF-free SSE transport** (cross-origin pages could drive a victim-cookie-authenticated LiveView session).

The late-night completion of the family (published 21:50–22:09Z) lands the strongest primitive: the **mount path imports a client-supplied dotted module path before any authentication or type check**, behind a module allowlist that is **fail-open when unset** — unauthenticated arbitrary-module import with import-time code execution (CVE-2026-61599). The remaining siblings (authorization bypass on the WS/SSE mount path, client-chosen SSE `session_id` as sole authority, unsigned state snapshot restored as trusted view state, Host omitted from reconstructed WS requests breaking subdomain tenant resolution, missing sensitive-field denylist in model serialization, IDOR, and `javascript:` URLs in built-in component template tags — CVE-2026-61594/61592/61591/61589/61588/61596/61597) confirm the same shape across every handler and are covered by the operator checks below.

Sources:

- djust mount-path arbitrary module import: [GHSA-7prp-2623-8g45 / CVE-2026-61599](https://github.com/advisories/GHSA-7prp-2623-8g45) (pip `djust < 1.0.7`)
- djust late-night sibling set (mount authz bypass, SSE session binding, state-snapshot trust, Host omission, serialization denylist, IDOR, `javascript:` template URLs): [GHSA-xhhm-f6hp-2qwj](https://github.com/advisories/GHSA-xhhm-f6hp-2qwj), [GHSA-f795-p5jw-j6g2](https://github.com/advisories/GHSA-f795-p5jw-j6g2), [GHSA-c67v-vqrp-m5wj](https://github.com/advisories/GHSA-c67v-vqrp-m5wj), [GHSA-v9rj-xjfv-xj9r](https://github.com/advisories/GHSA-v9rj-xjfv-xj9r), [GHSA-pvg3-6q9j-mj3x](https://github.com/advisories/GHSA-pvg3-6q9j-mj3x), [GHSA-c7c5-5j6r-q957](https://github.com/advisories/GHSA-c7c5-5j6r-q957), [GHSA-4mf4-73j6-mvrw](https://github.com/advisories/GHSA-4mf4-73j6-mvrw)
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

## djust mount path: client-supplied module import before auth is unauthenticated code-execution-by-proxy

The strongest primitive in the family (published 22:09Z, [GHSA-7prp-2623-8g45 / CVE-2026-61599](https://github.com/advisories/GHSA-7prp-2623-8g45)): the live transport resolves the view to mount from a **client-supplied dotted path** via `__import__(module_path, ...)`, and the import — which runs the module's **top-level code** — happens **before** the resolved object is checked to be a LiveView subclass and before any per-view authentication. The WS handshake itself requires no auth. The `LIVEVIEW_ALLOWED_MODULES` guard is fail-open (`if allowed_modules:` skips enforcement when unset — the framework default) and pre-patch matching was loose `startswith`.

The maintainer's own threat-model entry had previously understated this as LiveView-class probing; the real primitive is arbitrary importable-module import with import-time side effects, independent of whether the target is a LiveView. Lesson for advisory triage: **when a framework doc admits a default-open guard on a dynamic-resolution sink, re-derive the impact yourself — the "just a probe" framing may hide code execution.**

Operator checks that generalize to any framework resolving classes/modules/plugins from client input (plugin loaders, RPC method dispatch, dynamic routers):

1. Send a mount/redirect frame with `view = "<stdlib-or-sitepkg.module>.AnyName"` for an importable non-LiveView module against an authorized lab target; a "not a LiveView subclass" error **after** the frame means the import already executed — the reject is post-import, so it is not a control.
2. Distinguish the three outcomes as an enumeration oracle: module-not-found vs. attribute-not-found vs. not-a-subclass tells you what is importable; importable-name enumeration is recon even without side effects.
3. Check whether the resolution gate runs **before** import and whether it is fail-closed (fixed shape: resolve only if already in `sys.modules`, or explicit allowlist match on a module-segment boundary — not `startswith`).
4. Impact framing for reports: import-time side effects of any importable module (import bombs, dependency-tree DoS, side-effectful `__init__.py` files), not "class probing"; cite the pre-check import order as the root cause.

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

## djust template layer: auto-escape parity defects and a safety grant keyed by name, not value (2 GHSAs, published 2026-09-17T20:31Z)

Two djust records extend the realtime-framework family on this page into the **template escaping channel** — same framework, same operator lens (what crosses from attacker-controlled state into live markup), different boundary.

- **[GHSA-9395-2g46-rj3f](https://github.com/advisories/GHSA-9395-2g46-rj3f) — six auto-escape defects (fixed 1.1.1).** Shared shape: *a filter that escapes nothing itself and relies on render-time auto-escape, which something downstream then suppresses.* Highlights: `escape` was a no-op returning input unchanged, so the safe-looking idiom `{{ p|escape|safe }}` is a bare `|safe` on attacker input (their chain sweep found **104** live-markup cells across length-2/3 chains); `safeseq`/`unordered_list` earned an unconditional safe grant because they escape sequence items, but given a **string** they returned it verbatim under that grant — `{{ hostile|safeseq }}` ≡ `|safe` with no `mark_safe` anywhere; djust's own `{% render_slot %}` tag emitted handler returns raw (Django escapes `simple_tag` returns lacking `__html__`; djust inserted verbatim) — reachable with no app code at all, just component slots; `linebreaks` escaped neither content nor output, making `|safe` the *only* spelling that rendered — a visibly-broken plain form that pushes every app onto the unsafe spelling.
- **[GHSA-xjw9-38cr-6372](https://github.com/advisories/GHSA-xjw9-38cr-6372) — context safety grants keyed by *name*, not value (fixed 1.1.2).** A view marking `p` safe leaves the grant attached to the *name*; `{% with p=user_input %}{{ p }}{% endwith %}`, `{% for %}` loop vars, tuple unpacking, `{% include … with %}`, and `as`-assignment all rebind the name while keeping the mark — eight live bind shapes, no `|safe` required. Compounding the Sept 16 WS findings: safe keys accumulated per-**view** and were never revoked, and a djust view spans every event on the WebSocket, so render 1's `mark_safe` whitewashes render 2's user input on the same connection.

Operator patterns:

- **Differential-testing a custom template engine against its host framework is a high-yield bug class:** for every filter/tag the framework provides, render the same XSS canary chain through both engines and diff the output (their `djust` vs `django` two-column table is the reusable harness). Every cell where the framework escapes and the custom engine emits live is a finding; sweep short filter chains programmatically.
- **Audit "safe" grants by lifecycle, not just by API:** ask what happens when the *name* holding a safe grant is rebound (`with`/`for`/`include with`), and when the *value* behind a persistent grant changes across renders on a long-lived channel (WebSocket view reuse). Escaping metadata attached to names or views rather than values leaks across both axes.
- Same meta-lesson as the Grav `detectXss()` items: the fix family here shows **semantics parity, not just feature parity, is the security property** — a filter that *exists* but with subtly different eager/lazy escaping or grant behavior is a new bug class, so for any reimplemented template layer, re-run the framework's own escaping security tests.

Tracked without publication from the same 20:23–20:59Z window: CakePHP `FunctionsBuilder` `cast/extract/datePart/dateAdd` SQL injection in the `$dataType/$part/$unit` positions (CVE-2026-79752 / GHSA-vjqc-q4mp-2rvf, fixed 5.3.7/5.2.14/5.1.9/4.6.5/4.5.12) — a framework-side query-builder sink worth a fuzz-matrix mention but no new operator workflow beyond "SQLi-hunt every ORM helper argument that is interpolated rather than bound"; Chamilo LMS CStudio unauthenticated RCE ≤2.0.0 (CVE-2026-45140 / GHSA-g4c3-4g96-6g4m, 9.8) — no technical detail published yet, track for follow-up before any page; Jupyter Server 5xx logging leaking token-bearing `Referer` (CVE-2026-86049) and OpenTelemetry-Go log-exporter ignoring env TLS pins (CVE-2026-81871) — disclosure/MITM hygiene items, no offensive operator page; Soup Sieve polynomial ReDoS pair, HAPI FHIR DEFLATE DoS pair, react/http chunked DoS, CoreDNS custom-transport memory exhaustion, Steeltoe Consul/Eureka parse-DoS pair — availability-only.

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
