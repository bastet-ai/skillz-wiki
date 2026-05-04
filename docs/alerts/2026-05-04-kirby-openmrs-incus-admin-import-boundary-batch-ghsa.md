# Kirby, OpenMRS, and Incus admin/import boundary batch (GHSA)

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-04** batch where authenticated-but-limited users could cross admin, template, or import boundaries in CMS, healthcare, and container-management systems.

## Advisories in this batch

- **Kirby CMS site/user/role read authorization gap** — `getkirby/cms <= 4.8.0` and `>= 5.0.0, <= 5.3.3` allow authenticated Panel users to read site, user, and role information when role permissions should deny it. Fixed in **4.9.0** and **5.4.0**. References: <https://github.com/advisories/GHSA-2h7v-4372-f6x2>, CVE-2026-42069.
- **Kirby CMS system API version/license disclosure** — the same affected Kirby ranges expose installed version and license data through missing authorization on system API actions. Fixed in **4.9.0** and **5.4.0**. References: <https://github.com/advisories/GHSA-x68m-c7jf-2572>, CVE-2026-42051.
- **Kirby CMS user-avatar permission bypass** — the same affected Kirby ranges allow avatar create/replace/delete where user-update permissions should deny those actions. Fixed in **4.9.0** and **5.4.0**. References: <https://github.com/advisories/GHSA-39cp-6679-8xv2>, CVE-2026-42174.
- **OpenMRS stored Velocity SSTI to RCE** — `org.openmrs.api:openmrs-api >= 2.7.0, < 2.7.9` and `>= 2.8.0, < 2.8.6` evaluate database-stored concept reference-range criteria as unsandboxed Apache Velocity templates. A user with `Manage Concepts` can store payloads that later execute with server-side Java reflection. Fixed in **2.7.9** and **2.8.6**. References: <https://github.com/advisories/GHSA-xj4f-8jjg-vx4q>, CVE-2026-41258.
- **Incus unbounded binary import disk exhaustion** — `github.com/lxc/incus/v6/cmd/incusd <= 6.23.0` streams large binary imports to host temporary files without visible request-size limits on multiple import paths, allowing authenticated users to exhaust host disk unless separate image/backup volumes contain the blast radius. No patched version was listed at scan time. References: <https://github.com/advisories/GHSA-98vh-x9cx-9cfp>, CVE-2026-41685.
- **Incus malformed YAML restore nil dereferences** — `incusd <= 6.23.0` can trust one backup metadata source during preflight and later parse malformed legacy metadata, causing nil dereferences. No patched version was listed at scan time. References: <https://github.com/advisories/GHSA-x5r6-jr56-89pv>, CVE-2026-41684.
- **Incus unbounded YAML metadata decode** — `incusd <= 6.23.0` parses image and backup YAML metadata without size caps, allowing authenticated users to force large memory allocations. No patched version was listed at scan time. References: <https://github.com/advisories/GHSA-67wx-r9xr-x75x>, CVE-2026-41648.
- **Incus S3 bucket import nil-pointer crash** — `incusd <= 6.23.0` can dereference a nil tar header when truncated bucket backup imports return non-EOF tar errors. No patched version was listed at scan time. References: <https://github.com/advisories/GHSA-fwj8-62r8-8p8m>, CVE-2026-41647.
- **Incus snapshot bounds-check panic** — `incusd < 7.0.0` can crash during storage-volume import/migration when crafted snapshot metadata hits invalid bounds checks. Fixed in **7.0.0**. References: <https://github.com/advisories/GHSA-4m88-wxj4-9qj6>, CVE-2026-40251.

## Why this is durable

These systems differ, but all three categories failed at secondary boundaries after the first login or import gate succeeded:

- CMS permissions must protect every action and model read, not only obvious write endpoints.
- Template engines embedded in administrative data are code execution engines unless sandboxed or replaced with declarative predicates.
- Import archives are hostile programs for storage daemons: they consume disk, memory, parser state, and crash paths unless every metadata layer is bounded and schema-validated.

## Immediate triage

1. **Patch Kirby:** upgrade 4.x deployments to **4.9.0+** and 5.x deployments to **5.4.0+**. Review Panel roles that intentionally hide users, roles, license data, or avatar-management actions.
2. **Patch OpenMRS:** upgrade affected OpenMRS Core/API deployments to **2.7.9+** or **2.8.6+**. Restrict `Manage Concepts` to trusted administrators until patched.
3. **Harden Incus imports:** upgrade Incus to **7.0.0+** where it covers the snapshot panic and related import fixes; for advisories without listed patched versions at scan time, add reverse-proxy/body limits, separate image/backup volumes, quota enforcement, and strict import permissions.
4. **Reduce unaudited admin surfaces:** disable or tightly restrict CMS/healthcare admin panels and Incus import endpoints from broad internal networks.
5. **Preserve evidence for suspected template execution:** if OpenMRS criteria fields contain suspicious Velocity syntax, snapshot database rows and application logs before cleanup.

## Hunt ideas

- Kirby: review authenticated Panel/API requests to system, users, roles, site model, and avatar endpoints by roles that should lack those permissions.
- Kirby: compare avatar file mtimes and user profile changes against role permission expectations.
- OpenMRS: search concept reference range criteria for Velocity expressions, Java reflection chains, process execution strings, network calls, or encoded payloads.
- OpenMRS: correlate `Manage Concepts` changes with unexpected server process, file, or outbound network activity.
- Incus: inspect `incusd` logs for tar parsing errors, nil-pointer panics, YAML parse failures, OOM events, disk-pressure alerts, and repeated import attempts by the same user/project.
- Incus: monitor host temporary directories, image volumes, backup volumes, and storage-pool usage during large or failed imports.

## Durable controls

- Build permission tests around every CMS action: list/read, metadata disclosure, upload/replace/delete, and system introspection must all fail for denied roles.
- Avoid general-purpose template engines for stored administrative rules. If templates are unavoidable, use a sandboxed engine with a deny-by-default object model and no reflection.
- Treat import endpoints as resource-consumption APIs: enforce body limits, tar entry caps, YAML byte caps, decompression ratios, disk quotas, timeout budgets, and schema validation before restore side effects.
- Parse archive metadata once into a validated immutable structure; do not trust a second legacy metadata file later in the restore path.
- Make daemon crashes visible through alerts and rate limits; repeated malformed imports should degrade one tenant, not the whole control plane.

## Operator lesson

Authenticated admin features are not automatically trusted. Audit them like public APIs whenever users, tenants, or operators have different roles: read actions can leak sensitive state, stored templates can become RCE, and import formats can take down the daemon before business logic notices.
