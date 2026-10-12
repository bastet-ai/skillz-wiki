# Quarkus, OpenMRS, and Incus path/import boundary batch (GHSA)

**Signal:** GitHub Security Advisories Atom surfaced five durable advisories on **2026-05-04** covering URL path authorization differentials, archive/path traversal, unauthenticated file read, and authenticated import-triggered daemon crashes.

## Advisories in this batch

- **Quarkus matrix-parameter authorization bypass** — `io.quarkus:quarkus-vertx-http` can authorize one path while RESTEasy Reactive routes another after stripping semicolon matrix parameters. Example pattern: `/api/admin;anything` may bypass policies protecting `/api/admin`. Fixed in **3.20.6.1**, **3.27.3.1**, **3.33.1.1**, and **3.35.1.1** depending on release line. References: <https://github.com/advisories/GHSA-rc95-pcm8-65v9>, CVE-2026-39852.
- **OpenMRS module upload Zip Slip / arbitrary file write** — `org.openmrs.web:openmrs-web` versions `<= 2.7.8` and `2.8.0-2.8.5` allow authenticated module upload archives to write outside the intended module directory; writing JSPs under the webapp root can become RCE. No patched version was listed for this advisory at scan time. Reference: <https://github.com/advisories/GHSA-78fc-9688-w8xw>, CVE-2026-40076.
- **OpenMRS unauthenticated module resource path traversal** — `ModuleResourcesServlet` can serve arbitrary local files through module resource paths on affected OpenMRS deployments; OpenMRS `2.8.6` fixes the `2.8.x` line, while `<= 2.7.8` had no patched version listed at scan time. Exploitability depends on older Tomcat path-parameter handling for the published bypass. Reference: <https://github.com/advisories/GHSA-jjgj-cx3q-pw4w>, CVE-2026-40075.
- **Incus custom volume backup import nil-pointer DoS** — authenticated users with custom volume import access can crash `incusd` using crafted `index.yaml` volume snapshot metadata. Fixed in **7.0.0**. Reference: <https://github.com/advisories/GHSA-r7w7-mmxr-47r9>, CVE-2026-40197.
- **Incus storage bucket import nil-pointer DoS** — authenticated users with storage bucket import access can crash `incusd` using malformed bucket backup metadata. Fixed in **7.0.0**. Reference: <https://github.com/advisories/GHSA-gc7j-g665-rxr9>, CVE-2026-40195.

## Why this is durable

The recurring failure is that string or archive structure was trusted before being resolved into the thing policy actually protects.

- Path authorization must happen on the same canonical route key the application will dispatch.
- Archive extraction must validate the normalized destination path, not only the entry prefix.
- Static file handlers must prove the resolved file stays under an intended base directory.
- Import paths must reject absent/null metadata before dereferencing it in privileged daemons.

## Immediate triage

1. **Find affected components:** search SBOMs and manifests for `io.quarkus:quarkus-vertx-http`, `org.openmrs.web:openmrs-web`, and `github.com/lxc/incus/v6/cmd/incusd`.
2. **Patch quickly:** move Quarkus to the fixed release for the deployed line, OpenMRS `2.8.x` to `2.8.6` or later where available, and Incus to **7.0.0**.
3. **Constrain risky endpoints while patching:** restrict OpenMRS module upload to trusted administrators from trusted networks; disable or proxy-block module upload REST paths if not required; restrict unauthenticated access to module resource paths where compatible with the deployment.
4. **Normalize before policy:** for Java/HTTP services, test whether semicolon path parameters, encoded separators, and dot segments are treated identically by auth middleware, routers, and containers.
5. **Harden extraction/import:** reject archive entries after `normalize().startsWith(allowedBase)` fails; reject null/missing metadata blocks before import side effects start.

## Hunt ideas

- Query access logs for `;` in protected Quarkus paths, especially requests that returned `2xx/3xx` against admin/API routes.
- Search OpenMRS logs for module uploads through `/ws/rest/v1/module`, newly written files under webapp roots, JSP files with recent mtimes, or archive entries containing `../` after a valid prefix such as `web/module/`.
- Look for unauthenticated OpenMRS requests to `/moduleResources/` containing dot segments, semicolon path parameters, URL-encoded traversal, or unexpected module IDs.
- Inspect Incus logs for `panic: runtime error: invalid memory address or nil pointer dereference` near storage volume or bucket import operations; correlate with user/project/storage-pool activity.

## Durable controls

- Build path-policy tests that exercise raw path, decoded path, framework route path, servlet/container path, and filesystem path as separate values.
- Prefer deny-by-default module administration: no public module upload surface, explicit admin role checks on every API path, and audit logs for module install/update/delete operations.
- Treat uploaded archives as hostile data structures. Validate type, size, compression ratio, entry count, symlinks, hardlinks, absolute paths, normalized destinations, and metadata schema before extraction/import.
- Put daemon import operations behind authorization, quotas, crash containment, and rate limits; a single malformed import should not repeatedly take a control plane offline.

## Operator lesson

When auditing paths, ask: “What exact string did auth approve, what exact object did the router/filesystem/daemon use, and what transformations happened between them?” Bugs live in that gap.

## October 8 follow-up: RESTEasy `SourceProvider` XXE — the JAX-RS body-type handler your framework picked for you (CVE-2026-17615 / [GHSA-h82j-45qh-f65r](https://github.com/advisories/GHSA-h82j-45qh-f65r), high)

RESTEasy's `SourceProvider.writeTo()`/read side constructs a `SAXParser` with default features, so **any endpoint whose resource method accepts `application/xml` into `Source`/`StreamSource` resolves external entities** — unauthenticated remote file read into the HTTP response body. Published Aug 31, enriched into the updated feed Oct 8; fixed per advisory branch.

Why this earns a fold onto this page's Quarkus/RESTEasy lineage:

- **XXE in a framework message-body reader is everywhere at once.** The vulnerable parser is not in any application file — it is the provider the framework auto-selects when a resource method's parameter type is `Source`/`StreamSource`/`DOMSource`. A single library fix covers N deployments, and conversely: fingerprinting an app for `org.jboss.resteasy` jars plus any `javax.xml.transform.Source` parameter (grep-able in decompiled classes or via error/behavior probes) tells you the surface exists before you send a payload. Same "the framework's default choice is the boundary" theme as this page's matrix-parameter route split.
- **Type-based XXE probe battery:** for every XML-accepting endpoint, POST the same body under `Content-Type: application/xml` with each of the parameter shapes frameworks accept — the generic `Source`-typed leg is the one that bypasses app-level hardening, because app-level `XMLInputFactory` hardening only covers the readers the *app* constructs. Classic external-entity canary (`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` in a benign element) against your own lab RESTEasy deployment is the proof; against third parties, use a parameter-entity/timeout-blind shape or an owned HTTP callback and stop at resolution proof.
- Sweep extension for any Java stack: enumerate which `MessageBodyReader`s are registered (RESTEasy providers, Jackson XML, JAXB, Digester) — each is its own parser with its own entity settings, and hardening one says nothing about the others. This is the multi-backend guard-parity rule restated inside a single framework.

## October 12 follow-up: JAXB `FEATURE_SECURE_PROCESSING` was the only XXE control — a single-flag security assumption that fails per-JAXP-implementation (CVE-2026-92877 / [GHSA-j929-4rw7-84fh](https://github.com/advisories/GHSA-j929-4rw7-84fh), high, fix PR [eclipse-ee4j/jaxb-ri#2013](https://github.com/eclipse-ee4j/jaxb-ri/pull/2013))

JAXB's factory methods (`XmlFactory.createParserFactory`, in both `jaxb-ri/core` and `jaxb-ri/xsom`) relied **solely on `FEATURE_SECURE_PROCESSING`** to prevent external-entity resolution. FSP is a *limiting* feature, not a blocking one — on JAXP implementations where FSP alone doesn't disable external entities (alternate SAX providers, some vendored/repackaged Xerces), unmarshalling untrusted XML through JAXB = OOB XXE local-file read. The fix diff is the operator lesson: the patched code sets the four explicit features — `disallow-doctype-decl`, `external-general-entities`, `external-parameter-entities`, `load-external-dtd` — instead of trusting one umbrella flag.

- **Single-flag security assumptions are per-provider contracts, not guarantees.** "We enabled FEATURE_SECURE_PROCESSING / secure processing / a hardened `XMLInputFactory`" proves nothing about the JAXP implementation actually resolved at runtime (`SAXParserFactory.newInstance()` follows the ServiceLoader/META-INF discovery order — a jar on the classpath can silently swap the provider). Audit pattern: enumerate the *resolved* factory class name at runtime (log/print `factory.getClass()`), not the configured features, then probe with an external-entity canary against your own lab deployment.
- **Fix-diff fingerprint for sweep timing:** deployments still carrying a JAXB build predating PR #2013 are XXE-probable wherever untrusted XML reaches `unmarshal()` — grep the app's XML-accepting endpoints for JAXB-bound parameter types, then send the same entity-canary battery per Content-Type. This leg generalizes the Oct 8 RESTEasy `SourceProvider` leg directly above it: the vulnerable parser was a *library default*, invisible in application code, and app-level hardening never covered it.
- Both legs are the same hunt: **framework/library-constructed parsers are a separate inventory from app-constructed parsers** — enumerate both, probe both, and treat any single-boolean "secure" setting as a claim to test, not a control to trust.

## October 12 21:3xZ follow-up: Quarkus REST Data panache — customizing one generated operation silently DROPS class-level security (CVE-2026-87744 / [GHSA-jh67-c59w-8h9x](https://github.com/advisories/GHSA-jh67-c59w-8h9x), 9.1 critical)

Quarkus REST Data with panache generates REST endpoints from entity/repository interfaces, and security normally comes from **class-level** `@RolesAllowed`/`@Authenticated` annotations fanned out to every generated method. The generator's defect: when a developer customizes a *specific* operation with `@MethodProperties` (name/description/OpenAPI tweaks) **without re-declaring the security annotations on that method**, the code generator emits the customized operation **without the class-level security requirements at all** — the affected endpoint defaults to permissive, unauthenticated access. One cosmetic OpenAPI edit turns a protected CRUD route into an open data endpoint, and the developer never sees the security annotation disappear because it was never written at method level in the first place.

- **Code-generated surfaces inherit security by *generation rule*, and generation rules have override branches.** The class-level-annotation-to-every-method fan-out fails exactly on the branch where a method gets *any* per-method customization — the generator treats "method carries its own annotation block" as "method brings its own security." Sweep rule on any annotation-driven generator (Quarkus REST Data/panache, Spring Security annotation scanning, JAX-RS sub-resource generation, OpenAPI codegen with security schemes): for each generated route family, find the *customized* operations first and test auth on those before the untouched siblings — they're the ones whose inheritance is in question. Black-box shape: unauthenticated `GET` on generated entity collection paths with a 200-vs-401 diff against sibling non-customized entities.
- **Differential rule: generated-route inventory vs declared-security inventory vs runtime gating.** Pull the OpenAPI document (`/q/openapi` on Quarkus, frequently itself unauthenticated) and diff which operations advertise `security` requirements against what actually gates at runtime. Spec-says-secured / server-says-200 = enforcement dropped at generation. This page's RESTEasy and JAXB legs established framework-constructed layers as a separate inventory from app code; this adds **generated-from-your-code** as a third inventory — app, framework, and generator each enforce (or not) independently.
- **Fingerprint:** Quarkus-shaped banners + REST Data extension + any entity whose generated route answers unauthenticated; white-box grep is one pattern (`@MethodProperties` without adjacent security annotations). Silent-security-drop report framing, same family as the JAXB single-flag leg directly above: the control exists somewhere else and nobody verifies it reached the enforcement point.
- Validation boundary: own lab app with a disposable entity; prove 401-on-sibling vs 200-on-customized with synthetic rows; never enumerate third-party deployments' generated endpoints beyond owned scope.
