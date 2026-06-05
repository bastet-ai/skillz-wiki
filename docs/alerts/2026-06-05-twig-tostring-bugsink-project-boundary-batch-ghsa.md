# Twig `__toString()` sandbox and Bugsink project-boundary checks

Source: GitHub Security Advisories REST API, published/updated 2026-06-05.

This batch is durable because it captures reusable offensive validation patterns: **template-sandbox string-coercion policy gaps**, **debug/profiler output-encoding checks**, and **project-scoped object lookup failures in observability tooling**. Use these workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **Twig sandbox `__toString()` policy bypasses** — [GHSA-pr2w-4gpj-cpq4](https://github.com/advisories/GHSA-pr2w-4gpj-cpq4) / CVE-2026-47732: Twig `<= 3.25.0` missed several string-coercion paths in sandboxed templates, allowing a sandboxed template author to invoke `__toString()` on reachable objects even when that method was not allowlisted. Confirmed coercion points include conditionals passed to string-coercing filters/functions, `matches`, loose comparisons, tests such as `is empty`, concatenation with null coalesce, template-name expressions, dynamic attribute names, spread arguments, `do`, and the `..` range operator.
- **Twig profiler HtmlDumper XSS** — [GHSA-2g2g-8p8h-fgwm](https://github.com/advisories/GHSA-2g2g-8p8h-fgwm) / CVE-2026-47730: Twig `>= 3.0.0, < 3.26.0` inserted `Profile::getTemplate()` and `Profile::getName()` into profiler HTML without escaping. This is a debug/profiler rendering boundary, not a sandbox escape.
- **Bugsink sourcemap/debug-file project scoping** — [GHSA-5389-f7vh-wxj8](https://github.com/advisories/GHSA-5389-f7vh-wxj8) / CVE-2026-47728: Bugsink `< 2.2.0` resolved sourcemaps and debug files by debug ID without binding the lookup to the project that owned the uploaded metadata, allowing an authenticated user with access to one project to cause event processing to use another project's metadata on the same instance.
- **Bugsink direct UUID project-boundary checks** — [GHSA-vx2f-6m6h-9frf](https://github.com/advisories/GHSA-vx2f-6m6h-9frf) / CVE-2026-47715 and [GHSA-g5vc-q7qc-v939](https://github.com/advisories/GHSA-g5vc-q7qc-v939) / CVE-2026-47716: Bugsink `< 2.2.0` allowed issue-event views and bulk issue actions to act on direct event/issue UUIDs without requiring those objects to belong to the project authorized by the URL. Exploitation requires authentication and prior knowledge of valid target UUIDs.

## Operator triage

1. Search for applications that expose user-controlled Twig templates, themes, snippets, email bodies, CMS blocks, report templates, or preview features while passing rich objects into sandboxed render context.
2. Prioritize Twig targets where `Stringable` domain objects expose secrets, signed URLs, object identifiers, internal paths, or capability-bearing strings through `__toString()`.
3. For Twig profiler XSS, look for debug/profiler dumps reachable by administrators, support staff, CI artifact viewers, or bug-bounty triage tooling where template names or profile names can be attacker-controlled.
4. Search for self-hosted Bugsink instances in multi-project deployments. Prioritize instances where separate teams, customers, apps, or environments share one Bugsink server.
5. For Bugsink, distinguish **same-instance cross-project** impact from hosted cross-tenant impact. The advisory states Hosted Bugsink uses separate instances per tenant, so reports need proof of a boundary actually crossed in the tested deployment.

## Replayable validation boundaries

### Twig sandbox string-coercion canaries

Use a disposable Twig harness or in-scope staging template. Do not call methods that execute commands, mutate data, read files, or reach external networks.

1. Confirm the target uses Twig `<= 3.25.0`, enables sandboxing for the attacker-controlled template, and exposes at least one reachable object implementing `__toString()`.
2. Establish the baseline policy: render a direct method access or direct object output that should be denied when `__toString()` is not allowlisted.
3. Test inert coercion points one at a time with an object whose `__toString()` returns a harmless marker:
   - loose comparison or spaceship comparison against a guessed marker prefix;
   - `matches` against a benign regex;
   - `is empty` or another Twig test;
   - conditional/null-coalesce expression fed into a string-coercing filter/function;
   - concatenation, range, dynamic attribute name, or template-name expression in a lab-only harness.
4. Vulnerable result: a denied direct path still leaks, compares, or renders the marker through one of the implicit string-coercion paths.
5. Capture Twig version, sandbox policy, object class, allowed tags/filters/functions/tests, exact template canary, expected denial path, and observed coercion behavior. Frame impact around what the reachable object's `__toString()` reveals or enables.

### Twig profiler HtmlDumper canary

Keep this in debug/staging contexts; do not expose or browse production profiler output unless explicitly in scope.

1. Confirm the application can generate a Twig `HtmlDumper` profiler artifact and uses Twig `>= 3.0.0, < 3.26.0`.
2. Identify whether a template name, loader key, database template row identifier, or profile name can contain attacker-controlled text.
3. Use an inert HTML marker such as a unique `<span data-skillz="twig-profiler-canary">marker</span>` in the template/profile name. Avoid active JavaScript unless scope explicitly allows XSS payloads.
4. Vulnerable result: the marker is emitted as raw HTML in the profiler dump instead of escaped text.
5. Capture the input name, profiler artifact location, rendered HTML snippet, viewer role, and whether the artifact crosses from attacker input to a privileged reviewer.

### Bugsink project-scoped metadata and UUID canaries

Use two lab projects on the same Bugsink instance. Do not access real customer events, production sourcemaps, or live issue records.

1. Create two low-risk projects, `project-a` and `project-b`, and use separate test users/roles if the assessment scope includes project separation.
2. For sourcemap/debug-file scope, upload a lab sourcemap or debug file with a unique debug ID to `project-b`, then submit a synthetic event in `project-a` referencing the same debug ID.
3. Vulnerable result: `project-a` event processing resolves source context or symbolication metadata from `project-b`.
4. For direct event UUID scope, copy a lab event UUID from `project-b`, then request the stacktrace/details/breadcrumb route through an issue URL authorized for `project-a`.
5. For bulk issue actions, copy a lab issue UUID from `project-b`, then submit a bulk resolve/mute request from `project-a`'s issue list.
6. Vulnerable result: Bugsink discloses `project-b` event data or changes `project-b` issue state while the request is authorized through `project-a`.
7. Capture instance version, project IDs/names, role, endpoint path, request object UUIDs, before/after issue state, and sanitized event/debug metadata. Redact DSNs, session cookies, real stack traces, and source content.

## Reporting heuristics

- Frame Twig sandbox findings as **unguarded implicit string coercion**, not generic RCE. Strong reports prove a specific coercion construct reaches a non-allowlisted `__toString()` and explain the value exposed by that method.
- Frame Twig profiler findings as **debug artifact output encoding**, with a clear audience for who views the profiler artifact.
- Frame Bugsink findings as **project-scoped lookup/authorization failure**. Strong reports show two authorized lab projects on the same instance and avoid claiming cross-tenant impact unless the deployment actually shares tenant boundaries.
- Bugsink event-tag DoS ([GHSA-5x67-j5xg-c5gj](https://github.com/advisories/GHSA-5x67-j5xg-c5gj)), Apache Arrow IPC use-after-free ([GHSA-rgxp-2hwp-jwgg](https://github.com/advisories/GHSA-rgxp-2hwp-jwgg)), NATS JetStream admin API authorization drift ([GHSA-fhg8-qxh5-7q3w](https://github.com/advisories/GHSA-fhg8-qxh5-7q3w)), CoreDNS cache poisoning ([GHSA-h92q-fgpp-qhrq](https://github.com/advisories/GHSA-h92q-fgpp-qhrq)), and cert-manager PEM parsing DoS ([GHSA-r4pg-vg54-wxx4](https://github.com/advisories/GHSA-r4pg-vg54-wxx4)) were reviewed in the same scan but not promoted here because they were availability-only, old updated-feed items, or did not add a distinct replayable operator workflow for this wiki update.

## Sources

- GitHub Advisory Database: [GHSA-pr2w-4gpj-cpq4 / CVE-2026-47732](https://github.com/advisories/GHSA-pr2w-4gpj-cpq4)
- Twig advisory/source: <https://github.com/twigphp/Twig/security/advisories/GHSA-pr2w-4gpj-cpq4> and <https://github.com/twigphp/Twig>
- GitHub Advisory Database: [GHSA-2g2g-8p8h-fgwm / CVE-2026-47730](https://github.com/advisories/GHSA-2g2g-8p8h-fgwm)
- GitHub Advisory Database: [GHSA-5389-f7vh-wxj8 / CVE-2026-47728](https://github.com/advisories/GHSA-5389-f7vh-wxj8)
- GitHub Advisory Database: [GHSA-vx2f-6m6h-9frf / CVE-2026-47715](https://github.com/advisories/GHSA-vx2f-6m6h-9frf)
- GitHub Advisory Database: [GHSA-g5vc-q7qc-v939 / CVE-2026-47716](https://github.com/advisories/GHSA-g5vc-q7qc-v939)
- Bugsink source/advisories: <https://github.com/bugsink/bugsink> and <https://github.com/bugsink/bugsink/security/advisories>
