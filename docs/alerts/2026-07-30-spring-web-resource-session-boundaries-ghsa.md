---
title: Spring Web resource, view-name, expression, and session boundaries
---

# Spring Web resource, view-name, expression, and session boundaries

Nine Spring Framework advisories expose durable application-testing patterns across static-resource resolution, default view-name translation, restricted expression evaluation, JavaScript escaping, JSP tag attributes, multipart parsing, Kotlin Router filters, and concurrent WebFlux session rotation.

Sources:

- [GHSA-72pg-x5f8-j25j / CVE-2026-41843](https://github.com/advisories/GHSA-72pg-x5f8-j25j) and the [Spring advisory](https://spring.io/security/cve-2026-41843): versioned filesystem resources may resolve outside configured locations;
- [GHSA-mq64-j8f9-9gcj / CVE-2026-41841](https://github.com/advisories/GHSA-mq64-j8f9-9gcj) and the [Spring advisory](https://spring.io/security/cve-2026-41841): a shared static-resource cache may return an authenticated handler's resource through a public handler with the same name; and
- [GHSA-4hfh-6x8g-gwpp / CVE-2026-41839](https://github.com/advisories/GHSA-4hfh-6x8g-gwpp), the [Spring advisory](https://spring.io/security/cve-2026-41839), and the [session-store fix](https://github.com/spring-projects/spring-framework/commit/b8ddd2c690fe3f00bb5e3d9f913a37504aab49a0): a race in the in-memory WebFlux session store may exchange an attacker-known session ID for an authenticated user's ID;
- [GHSA-h3qp-gqrc-q736 / CVE-2026-41844](https://github.com/advisories/GHSA-h3qp-gqrc-q736), the [Spring advisory](https://spring.io/security/cve-2026-41844), and the [default-view-name fix](https://github.com/spring-projects/spring-framework/commit/3aaec987651cf82fd4ed7e0ed9b3deddcdf58853): a catch-all mapping with no explicit view name can reinterpret a request path beginning with `redirect:` or, in MVC, `forward:` as a view-resolver instruction; and
- [GHSA-9f52-rjqv-25qv / CVE-2026-41852](https://github.com/advisories/GHSA-9f52-rjqv-25qv) and the [Spring advisory](https://spring.io/security/cve-2026-41852): untrusted SpEL may invoke arbitrary zero-argument methods even in restricted or read-only evaluation contexts;
- [GHSA-957g-f97v-vppc / CVE-2026-41846](https://github.com/advisories/GHSA-957g-f97v-vppc) and the [Spring advisory](https://spring.io/security/cve-2026-41846): user-controlled `cssClass`, `cssErrorClass`, or `cssStyle` values in JSP form tags may cross into HTML/JavaScript structure;
- [GHSA-cjpg-rgq5-fr37 / CVE-2026-41853](https://github.com/advisories/GHSA-cjpg-rgq5-fr37) and the [Spring advisory](https://spring.io/security/cve-2026-41853): multipart requests may be interpreted differently across Spring MVC/WebFlux and another HTTP component; and
- [GHSA-vqgp-pf68-6947 / CVE-2026-41847](https://github.com/advisories/GHSA-vqgp-pf68-6947) and the [Spring advisory](https://spring.io/security/cve-2026-41847): Spring WebFlux 5.3 Kotlin Router DSL filters may not cover the route set the application expects.

The vendor lists Spring Framework 7.0.0–7.0.7, 6.2.0–6.2.18, 6.1.0–6.1.27, and 5.3.48 and earlier as affected, with fixes in 7.0.8 and 6.2.19 plus support-channel builds. GitHub's package-range fields differed from the vendor text when this page was written; use the vendor advisory and the exact deployed artifact as the version authority.

!!! warning "Authorized lab validation only"
    Use synthetic static files, two disposable users, an isolated cache, and an application with no production sessions or data. Never traverse to real secrets, retrieve another user's files, fixate a real user's session, or race a shared production login.

## Build one boundary matrix

| Surface | Attacker-controlled input | State reused across the boundary | Bounded proof |
| --- | --- | --- | --- |
| versioned resources | URL path plus guessed resource metadata | version resolver and filesystem location | one out-of-root canary hash |
| shared resource cache | public handler request and filename | cache entry populated under another handler/location | synthetic protected canary returned publicly |
| WebFlux session rotation | known pre-auth session ID and request timing | in-memory session object during `changeSessionId()`/`save()` | authenticated marker remains reachable under the known ID |
| default view name | path under a `/**` mapping with no explicit view | `redirect:` or MVC `forward:` view-resolver prefix | owned external redirect or internal no-op route selected |
| restricted SpEL | user-controlled expression | zero-argument method resolution in a restricted/read-only context | recorder object's no-op counter changes |
| JSP form tag | user-controlled style/class attribute | tag renderer and browser HTML/JavaScript parser | harmless DOM marker escapes the intended attribute context |
| multipart request | boundary/header/body bytes | front end, Spring multipart parser, and route/body consumer | components disagree on part or request boundaries in an isolated connection |
| Kotlin Router DSL | route nesting and filter placement | expected security filter coverage | protected canary handler is reached without its recorder filter |

Keep **route match**, **resolver selection**, **cache key**, **filesystem candidate**, **authorization decision**, **session-ID rotation**, and **authenticated-state attachment** as distinct edges. A path-shaped request is not traversal without an out-of-root result; a cache collision is not disclosure unless it crosses an authorization boundary; and knowing a session ID is not account access unless authenticated state remains bound to it.

## Versioned filesystem resource traversal

The Spring advisory requires all of these conditions: MVC or WebFlux, filesystem-backed static resources, versioned-resource support, and knowledge or a guess of the target resource's metadata. Do not assume classpath-only resources or unversioned handlers are affected.

### Canary-only workflow

1. Build the smallest application matching production configuration. Map one handler to a disposable resource root and enable the same version strategy, resource chain, URL pattern, and resolver order.
2. Place `public.txt` inside the root and a random `outside-canary.txt` in a sibling directory. Both files should contain generated markers only; put no credentials, source, configuration, keys, or user data in the fixture.
3. Establish controls for the ordinary public URL, a missing resource, an incorrect version, an unversioned handler, a classpath-backed handler, and the corrected Spring build.
4. Generate candidate requests from the application's legitimate versioned URL format. Vary one normalization dimension at a time: dot segments, encoded separators, repeated separators, mixed encoding, and version/path placement. Do not publish a weaponized path for a real deployment.
5. Capture the raw request target, framework-decoded path, selected handler and resolver, normalized filesystem candidate, returned status, content type, body length, and body hash.
6. A positive is **versioned request -> configured resource root is escaped -> sibling canary hash is returned**. Stop immediately; do not enumerate neighboring files.

The metadata precondition belongs in the report. Record whether it means a content hash, fixed version string, filename-derived token, manifest entry, or another application-specific value, and how the synthetic value was obtained.

## Shared static-resource cache collision

The cache advisory requires multiple resource handlers with different locations, at least one authenticated handler, and a cache shared by those configurations. The vendor describes the protected object becoming reachable when a public resource with the same name is resolved first and cached. Test both ordering directions rather than inferring the exact key composition.

### Two-handler, two-user differential

1. Configure `/public/**` and `/private/**` with separate disposable locations but the same resource filename, such as `logo.txt`. Give each file a different random body marker.
2. Require authentication for the private handler and use the deployment's actual cache implementation and sharing arrangement. Record whether the cache object is process-local, distributed, framework-managed, or application-supplied.
3. With a fresh cache, replay these sequences independently:

| Sequence | First request | Second request | Expected public result |
| --- | --- | --- | --- |
| A | anonymous public name | anonymous public name | public marker |
| B | authenticated private name | anonymous public same name | public marker or denial, never private marker |
| C | anonymous public name | authenticated private same name | private route returns only private marker to the authenticated user |
| D | authenticated private different name | anonymous public name | public marker |

4. Repeat with handler registration order reversed, case and encoding variants accepted by the actual server, cache eviction between runs, separate caches, and the corrected build.
5. Preserve cache-key hashes and marker labels, not cache dumps or resource bodies.

Strong evidence is **one handler primes a shared cache -> another handler with a different authorization/location context reuses that entry -> the anonymous response contains only the synthetic protected marker**. Report the priming order observed; do not generalize it beyond the measured configuration.

## WebFlux in-memory session rotation race

The vendor requires WebFlux and a compromised sibling subdomain, for example through XSS. The published fix adds locking around in-memory session save and ID rotation. Treat sibling-domain cookie placement, concurrent request timing, ID rotation, and authenticated-state reuse as separate preconditions.

### Recorder-only race harness

1. Use a disposable WebFlux application backed by `InMemoryWebSessionStore`, two owned sibling hostnames, one synthetic user, and a test-only authentication endpoint that sets an inert `role=user` marker. Do not use production cookies or identity providers.
2. Verify whether the session cookie's `Domain`, `Path`, `Secure`, and `SameSite` attributes let the owned sibling supply a known pre-auth ID to the application. If not, record the failed precondition and stop.
3. Instrument `retrieveSession`, `save`, `changeSessionId`, and authentication completion. Log opaque request labels, old/new ID hashes, session-object identity, and marker presence; never log complete cookies.
4. Establish a sequential control: start with the known ID, authenticate, and verify that rotation makes the old ID unusable while the new ID alone reaches the marker.
5. In the lab only, place barriers around session save/rotation and release two benign requests in controlled orders. Compare old-ID lookup before, during, and after authentication. Avoid unbounded timing loops.
6. Repeat with a fresh store for every schedule, an unrelated ID, no sibling cookie placement, one request only, a persistent session-store implementation if actually deployed, and the corrected build.
7. A bounded positive is **attacker-known pre-auth ID -> concurrent in-memory save/rotation schedule -> authenticated canary state remains retrievable with that known ID**. Stop at the synthetic marker; do not perform account actions.

Do not call a stale map entry session fixation unless it remains usable after authentication. Conversely, do not require a real victim or real XSS: owned sibling cookie placement and a deterministic barrier schedule are safer, stronger evidence.

## JavaScript escaping follow-up

[GHSA-3chg-m5w7-qfv5 / CVE-2026-41845](https://github.com/advisories/GHSA-3chg-m5w7-qfv5) adds a separate output-context boundary: `JavaScriptUtils.javaScriptEscape()` in affected Spring Framework releases can leave input able to change generated JavaScript structure. This is only relevant when an application places attacker-controlled data into a JavaScript context through that helper; Spring MVC use alone is not sufficient.

1. Locate actual helper call sites and trace whether a scoped low-privilege input reaches an inline script, event handler, JavaScript URL, JSON-in-script block, or quoted JavaScript string.
2. Build a canary corpus for the exact sink context: quote terminators, backslashes, line terminators, closing script text, and harmless expression markers. Do not use cookie, storage, navigation, or network APIs.
3. Capture source input, helper output bytes, complete enclosing script context, parsed browser syntax tree, and a recorder-only marker such as `window.__springCanary = 1` in a disposable browser profile.
4. Add controls for literal text/HTML contexts, a framework encoder intended for a different context, a fixed build, and a strict JSON serializer where appropriate.
5. A positive is **attacker-controlled string -> `javaScriptEscape()` output -> browser parses a new inert statement or expression outside the intended string**. Merely seeing punctuation in page source is not enough.

The vendor identifies affected lines through 7.0.7, 6.2.18, 6.1.27, and 5.3.48, with public fixes in 7.0.8 and 6.2.19 plus support-channel releases. Report the exact artifact and call site; do not generalize this helper flaw to every Spring template or call it exploitable without a reachable JavaScript sink.

## Default view-name prefix confusion follow-up

[GHSA-h3qp-gqrc-q736 / CVE-2026-41844](https://github.com/advisories/GHSA-h3qp-gqrc-q736) applies only when an MVC or WebFlux application maps `/**` and does not explicitly select a view name. Spring can then derive the view name from the request path. In affected builds, a derived name beginning with `redirect:` is interpreted as an external redirect; MVC also recognizes `forward:` as an internal forward. This is default-view translation, not a generic redirect in every Spring route.

1. Inventory catch-all mappings and determine whether their handler return values cause Spring to derive a default view name. Exclude explicit view names, response-body routes, and unrelated redirect parameters.
2. In a disposable application, use one owned external listener and one inert internal route that increments a recorder counter. Send path variants matching the application's real servlet context, proxy normalization, and route decoding.
3. Capture the raw target, framework path, selected mapping, derived view name, response status and `Location`, or selected internal route. Do not rely on a browser screenshot alone.
4. Compare MVC with WebFlux: test `redirect:` on both, but test `forward:` only as an MVC-specific edge. Add an explicit-view handler, a non-catch-all mapping, ordinary path text, and a corrected build as negative controls.
5. A positive is **request path -> implicit default view name begins with a special resolver prefix -> 302 reaches only the owned origin, or MVC forwards to the inert internal route**. Never use privileged internal actions, credential-bearing destinations, or third-party hosts.

Keep parser layers separate. If a reverse proxy rejects or rewrites a colon-bearing path before Spring sees it, record the failed reachability precondition rather than claiming the application is exploitable. The public fix rejects these prefixes during default view-name generation; fixed OSS versions are 7.0.8 and 6.2.19, with support-channel fixes for older lines.

## Restricted SpEL zero-argument method follow-up

[GHSA-9f52-rjqv-25qv / CVE-2026-41852](https://github.com/advisories/GHSA-9f52-rjqv-25qv) requires an application to accept and evaluate untrusted SpEL. The reusable audit question is whether a context advertised as restricted or read-only still permits a zero-argument method to cross from data selection into application behavior.

1. Locate the exact expression ingress and evaluator construction. Record the parser, root object, variables, property and method resolvers, type/construction access, bean access, and whether the application calls the context restricted, read-only, or data-binding-only.
2. Build a purpose-made root object exposing a harmless zero-argument method such as `mark()` that increments an in-memory counter and returns a fixed string. Do not test process, file, network, reflection, class-loading, or environment-access gadgets.
3. Evaluate a decision corpus: literal/property access, the recorder method, a method requiring arguments, constructor/type references, bean references, assignment, and an unknown method. Run every case in the application's normal context, its intended restricted context, and a corrected Spring build.
4. Capture the input expression, parsed AST or normalized form where available, evaluator/context class, resolver list, return value, exception type, and recorder count before and after. Reset the object for every case.
5. A positive is **untrusted expression -> context intended to prevent behavior -> arbitrary recorder zero-argument method resolves and changes the no-op counter**. A parse error, property getter, or method allowed by explicit application policy is not equivalent evidence.

Report the concrete reachable method surface separately from the framework primitive. The advisory establishes unintended zero-argument invocation, not universal code execution. Fixed OSS versions are 7.0.8 and 6.2.19, with support-channel fixes for older lines.

## JSP form-tag attribute context

This issue is not generic Spring MVC XSS. The application must pass attacker-controlled data into `cssClass`, `cssErrorClass`, or `cssStyle` on a JSP form tag. Trace actual tag attributes from their source to the rendered response before testing.

1. Build a disposable JSP form with separate server-owned and user-controlled values for each affected attribute. Render one attribute at a time.
2. Use a corpus of quote boundaries, whitespace, HTML metacharacters, CSS punctuation, and one harmless marker such as setting `window.__jspTagCanary = 1`. Do not read cookies, storage, DOM data, or network resources.
3. Preserve input bytes, the complete generated start tag, browser-parsed attributes, CSP state, and marker result. Page-source punctuation without a parser-context escape is not proof.
4. Compare ordinary body text, a JSP attribute not named by the advisory, a server-owned class/style, the corrected Spring build, and a context-appropriate encoder.
5. A positive is **untrusted tag attribute -> renderer fails to preserve the intended attribute boundary -> browser creates a new inert attribute or statement**.

## Multipart parser differential

Treat multipart smuggling as a disagreement experiment, not a generic malformed-upload test. Use an isolated proxy/application pair and a single disposable connection so no shared user traffic can be desynchronized.

1. Put a raw-byte recorder before a minimal MVC or WebFlux application. Expose `/upload-canary` and `/after-canary`; each only increments a different counter.
2. Start from a valid multipart request captured from the exact stack. Mutate one grammar dimension at a time: boundary quoting, leading/trailing whitespace, duplicate `Content-Type` parameters, line endings, terminal delimiters, part-header folding, and declared versus actual body length.
3. Record the exact bytes received by every hop, each component's request count, selected route, part count/names/lengths, unread bytes, connection reuse, and counter deltas.
4. Add direct-to-Spring, connection-close, one-request-per-connection, MVC-versus-WebFlux, front-end parser, and corrected-build controls.
5. Strong evidence is **same byte stream -> front end and Spring disagree on request or multipart boundaries -> trailing canary bytes are interpreted under a different request/route context**. A 400/500 response or parser exception alone is not smuggling.

Never place a second user's request behind the test, poison a shared connection pool, or target authentication-changing routes.

## WebFlux Kotlin Router filter coverage

The affected record is specific to Spring WebFlux 5.3 applications using the Kotlin Router DSL. Review how nested routes and filters are assembled; do not infer bypass from the presence of Kotlin code alone.

1. Build the application's route tree in a disposable fixture with `/public-canary` and `/protected-canary`. The expected security filter should increment a recorder and attach a fixed principal marker.
2. Enumerate the effective route tree from source and runtime mappings. Test nesting, `and`/`andOther`, path predicates, method predicates, trailing slashes, and route declaration order independently.
3. For each request, capture the selected handler, filter recorder count, principal marker, authorization decision, and handler counter.
4. Compare a request that definitely traverses the filter, one outside the protected subtree, an explicit per-route filter, equivalent Java DSL if relevant, and a corrected/support-channel build.
5. A positive is **route intended to be inside the filtered Kotlin DSL subtree -> protected handler runs -> expected filter recorder remains zero**. Prove only with a marker handler, never a real privileged action.

## Evidence and reporting checklist

Preserve:

- exact Spring artifacts, versions, MVC versus WebFlux mode, resource-handler configuration, version strategy, cache implementation, session-store implementation, default-view mapping, SpEL context/resolvers, and any `JavaScriptUtils.javaScriptEscape()` call site;
- raw and normalized paths, selected handler/resolver, configured root, and synthetic returned-file hash;
- cache state and request order, opaque key hashes, route authorization context, and public/private marker labels;
- cookie scope, old/new session-ID hashes, request schedule, session-object identity, and authenticated marker decision;
- vulnerable and corrected build results using identical fixtures; and
- separate claims for path escape, response disclosure, cache-context collision, session race, old-ID persistence, authenticated-state access, escape mismatch, browser-side statement execution, special-prefix view selection, external redirect, internal forward, and restricted-context method invocation.

Stop at the smallest synthetic proof. These advisories do not by themselves establish arbitrary file read in every Spring application, universal cache poisoning, XSS on a sibling domain, or compromise of a production account.

## October 7 follow-up: GitHub-published enrichment wave — WebFlux header-predicate pre-flight bypass + SSE fragment stream corruption (CVE-2026-47892 / [GHSA-9qf2-26p9-2q2q](https://github.com/advisories/GHSA-9qf2-26p9-2q2q) critical-labeled; CVE-2026-47890 / [GHSA-j9f9-w8pj-32f8](https://github.com/advisories/GHSA-j9f9-w8pj-32f8))

Two Spring Framework advisories from the Aug 20 vendor disclosures landed in the GitHub advisory feed with package ranges on Oct 7 — use them as version-fingerprint updates to this page's coverage:

- **Header predicate bypass in WebFlux functional endpoints under DispatcherServlet (CVE-2026-47892).** A WebFlux functional-endpoint app *deployed in servlet mode via `DispatcherServlet`* (the hybrid migration shape) can have header-based route predicates bypassed **in a pre-flight request**. Vendor ranges: 7.0.0–7.0.8 (fix 7.0.9 OSS; 7.0.8.1/6.2.20/6.1.29/6.0.31/5.3.50/5.2.26 enterprise-only — long-Tail versions get no OSS fix, so enterprise-support deployments fingerprint differently). Operator translation: predicate-gated routes (`header(...)`, `accept(...)`, `contentType(...)`) are authorization-relevant when a sibling route family serves more; pre-flight/`Expect`-style and other transport-preformatted requests must be re-tested against the *effective* predicate decision, not the plain request. Test shape on a lab fixture: protected route gated on `header("X-Authz","yes")`-style predicate with a marker handler, then replay the same route through the hybrid servlet deployment with `Expect: 100-continue`, pipelined, and chunked pre-leg variants, recording selected-handler + predicate-recorder counters per variant. A positive is *protected marker handler runs while the predicate recorder stays zero*. This is the servlet/reactive-bridge sibling of this page's Kotlin Router filter-coverage leg: the same route works, the deployment mode changes which matcher sees the request.
- **SSE stream corruption when rendering view fragments (CVE-2026-47890, CWE-93).** Spring MVC/WebFlux apps that stream *view fragments* to clients over Server-Sent Events corrupt the stream when attacker-controlled data enters the fragment: unescaped `data:` framing characters in the rendered fragment break SSE field boundaries for every subsequent event on that stream (7.0.0–7.0.8, 6.2.0–6.2.19; fix 7.0.9/6.2.20). Durable axis: **SSE is a line-oriented framing protocol and any renderer that interpolates attacker data into a fragment without per-line `data:` re-prefixing is a cross-user injection surface** — the same CRLF-into-framing class as this quarter's Coraza audit-log forgery and ASUSTOR header-CRLF legs, new carrier. Probe shape (lab, own two users): user A injects `\n\ndata: ` + a synthetic marker into whatever field reaches the fragment renderer; user B subscribes to the SSE stream and records whether the marker arrives as a *separate trusted event* rather than escaped text. Prove only with synthetic markers; never inject real UI markup into a stream other users consume beyond the minimal event-boundary demonstration.
- Both vendor pages label severity MEDIUM/LOW despite GitHub's critical tag; report the *transition* you prove (predicate bypass → which handler; stream corruption → which downstream state), not the GitHub CVSS label. Version fingerprint from outside: neither is externally distinguishable without an app-specific route — enumerate hybrid WebFlux-on-servlet deployments from stack traces/error shapes and SSE endpoints from `text/event-stream` responses first.
