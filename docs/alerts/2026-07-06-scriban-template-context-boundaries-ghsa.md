# Scriban `TemplateContext` cache and sandbox-boundary checks

Source: hourly offensive-security scan, 2026-07-06. Primary entries: GitHub Advisory Database [GHSA-5wr9-m6jw-xx44](https://github.com/advisories/GHSA-5wr9-m6jw-xx44), [GHSA-x6m9-38vm-2xhf](https://github.com/advisories/GHSA-x6m9-38vm-2xhf), and adjacent Scriban resource-limit advisories including [GHSA-c875-h985-hvrc](https://github.com/advisories/GHSA-c875-h985-hvrc), [GHSA-xw6w-9jjh-p9cr](https://github.com/advisories/GHSA-xw6w-9jjh-p9cr), [GHSA-wgh7-7m3c-fx25](https://github.com/advisories/GHSA-wgh7-7m3c-fx25), [GHSA-q6rr-fm2g-g5x8](https://github.com/advisories/GHSA-q6rr-fm2g-g5x8), [GHSA-6q7j-xr26-3h2c](https://github.com/advisories/GHSA-6q7j-xr26-3h2c), [GHSA-p6q4-fgr8-vx4p](https://github.com/advisories/GHSA-p6q4-fgr8-vx4p), [GHSA-grr9-747v-xvcp](https://github.com/advisories/GHSA-grr9-747v-xvcp), [GHSA-5rpf-x9jg-8j5p](https://github.com/advisories/GHSA-5rpf-x9jg-8j5p), [GHSA-v66j-x4hw-fv9g](https://github.com/advisories/GHSA-v66j-x4hw-fv9g), [GHSA-xcx6-vp38-8hr5](https://github.com/advisories/GHSA-xcx6-vp38-8hr5), and [GHSA-m2p3-hwv5-xpqw](https://github.com/advisories/GHSA-m2p3-hwv5-xpqw).

These advisories are durable for operators because the strongest issues are not generic template DoS. They expose a reusable **cross-render template runtime state** pattern: applications pool or reuse a Scriban `TemplateContext`, then expect `Reset()`, `MemberFilter`, `MemberRenamer`, `ITemplateLoader`, `LoopLimit`, or `LimitToString` to enforce a new tenant/user/request boundary. A bug-hunting proof should show a harmless canary crossing that boundary without reading real templates, secrets, or tenant data.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-5wr9-m6jw-xx44](https://github.com/advisories/GHSA-5wr9-m6jw-xx44) | Scriban / `Scriban.Signed` `< 7.0.0` | `TemplateContext` caches `TypedObjectAccessor` by .NET type after applying the current `MemberFilter` and `MemberRenamer`; later renders on the same context can reuse stale accessors after policy tightening | Test template-as-a-service, CMS, email, report, and workflow-renderer targets for object-exposure policy drift across pooled contexts. |
| [GHSA-x6m9-38vm-2xhf](https://github.com/advisories/GHSA-x6m9-38vm-2xhf) | Scriban / `Scriban.Signed` `< 7.0.0` | `TemplateContext.Reset()` does not clear `CachedTemplates`, so request-, tenant-, or role-dependent `ITemplateLoader` results can survive into a later render | Test include/import behavior where template names are stable but loader decisions depend on current user, tenant, locale, role, project, or request path. |
| Resource-limit cluster | Scriban parser/evaluator, mostly `< 7.0.0` with some incomplete-fix variants | `ExpressionDepthLimit`, `LoopLimit`, and `LimitToString` do not cover every parser recursion, built-in iteration, range, string multiplication, padding, `to_json`, or BigInteger allocation path | Treat runtime safety knobs as incomplete unless the specific expression class is covered. Use tiny, non-crashing canaries and time-boxed local harnesses only. |

## Operator triage

Prioritize targets where all of these are true:

1. Users can create or edit Scriban templates, snippets, reports, notifications, themes, workflow messages, or document templates.
2. The application passes live .NET domain objects into the render context instead of flattened DTOs.
3. A long-lived worker, service container, object pool, or template-rendering service reuses `TemplateContext` instances across renders.
4. `MemberFilter`, `MemberRenamer`, `ITemplateLoader`, or include paths depend on request, user, tenant, project, role, feature flag, or workflow state.
5. The same template names, include names, or object types can appear in both privileged and less-privileged render paths.

Lower priority: systems that render only trusted, static templates; allocate a fresh `TemplateContext` per render; expose only inert dictionaries/DTOs; and never vary loader output by user or tenant.

## Replayable validation boundaries

### Stale `MemberFilter` accessor harness

Use this when a target claims Scriban sandboxing or object exposure is controlled by `TemplateContext.MemberFilter` / `MemberRenamer`.

- Preconditions: disposable .NET lab or explicitly scoped staging target, affected Scriban version, one harmless object type with both an allowed property and a canary property, and evidence that a context can be reused.
- Render 1: use a permissive policy for a canary object type and access `model.skillz_canary` or equivalent. This primes the accessor cache for that type.
- Reset/reconfigure: call the same reset/reuse path the application uses, then tighten the policy so only a safe property such as `Public` should be visible.
- Render 2: access the previously exposed canary property from the same object type.
- Positive evidence: the second render returns the canary even though a fresh context or patched version denies it.
- Negative controls: fresh `TemplateContext` per render, patched Scriban `>= 7.0.0`, a different object type that was never primed, and direct policy-denial proof for the canary property.
- Do not expose real domain objects, file paths, signed URLs, secrets, access tokens, customer records, or production object graphs. The canary object should return fixed strings only.

Report this as **context-pooled object accessor policy drift**, not generic template RCE. Strong evidence includes context lifetime, policy before/after, object type, template expression, expected denial, observed canary, and patched/fresh-context control.

### Stale include-cache authorization harness

Use this when `include`, `import`, or template loader paths resolve differently by user, tenant, role, locale, project, or request.

- Preconditions: disposable app or staging harness with affected Scriban, a request-dependent `ITemplateLoader`, and two synthetic principals or tenants.
- Principal A render: include a stable path such as `profile`, `invoice-footer`, or `tenant/banner` while the loader returns `skillz-admin-canary` or `tenant-a-canary`.
- Reset/reuse: follow the application's normal context pooling or reset path without constructing a fresh context.
- Principal B render: include the same stable path while the loader should now return `skillz-guest-canary` or `tenant-b-canary`.
- Positive evidence: Principal B receives Principal A's cached canary without the loader being called for B.
- Negative controls: patched Scriban, fresh context per render, unique cache keys that include tenant/user/role, and explicit cache clearing between renders.
- Keep proof content synthetic. Do not include real customer templates, invoices, email bodies, secrets, API keys, or account data.

Report this as **request-dependent template loader output reused across authorization boundaries**. Include a loader-call log or counter if possible; it proves the second render bypassed authorization logic rather than merely returning similar content.

### Resource-limit safety-control harness

The resource-limit advisories are mostly availability-oriented, so do not publish or run crash payloads against production. They still matter as supporting evidence when a vendor claims untrusted templates are safe because `LoopLimit`, `LimitToString`, or `ExpressionDepthLimit` is configured.

- Preconditions: local harness only, disposable process, strict timeout, small memory limit, and no shared CI worker if the proof intentionally stresses CPU or memory.
- Prefer bounded decision probes over exhaustion: use small ranges, short string multiplication, or reduced nesting to show the safety counter did not fire where expected.
- Capture policy settings and expression class: parser nesting, range consumed by built-ins, `string * int`, `pad_left` / `pad_right`, `to_json`, or BigInteger shift.
- Stop at evidence that a configured limit is bypassed. Do not tune values to crash production services or shared staging workers.
- Tie the finding back to a real untrusted-template entry point; standalone CPU/memory exhaustion without an operator path is lower-value for this wiki.

## Reporting notes

- Lead with the boundary crossed: **pooled context to stale member accessor**, **request-dependent loader to stale include**, or **configured safety knob to uncovered expression class**.
- Include version, render-context lifetime, whether contexts are pooled, template path/name, loader policy inputs, member filter before/after, and fresh-context or fixed-version negative controls.
- Frame impact conservatively around canary disclosure or policy bypass in the exact render path tested. Do not claim cross-tenant data exposure unless the proof uses two authorized synthetic tenants and shows content from one tenant reaching the other.
- Keep all artifacts inert: fixed canary strings, disposable object models, synthetic template names, local loader logs, and redacted request metadata.
