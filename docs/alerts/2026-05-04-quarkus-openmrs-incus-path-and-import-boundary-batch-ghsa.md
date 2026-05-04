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
