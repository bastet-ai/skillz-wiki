# TYPO3, Budibase, GeoServer, and Appsmith control-plane boundary checks

Source: hourly offensive-security scan, 2026-06-12. Primary entries: GitHub advisories [GHSA-chm7-4vch-h8vr](https://github.com/advisories/GHSA-chm7-4vch-h8vr) / CVE-2026-49742, [GHSA-jf56-v8jc-jcc5](https://github.com/advisories/GHSA-jf56-v8jc-jcc5) / CVE-2026-49738, [GHSA-2j54-93q2-3hjq](https://github.com/advisories/GHSA-2j54-93q2-3hjq) / CVE-2026-47352, [GHSA-q93m-25xv-94hh](https://github.com/advisories/GHSA-q93m-25xv-94hh) / CVE-2026-47351, [GHSA-c78m-c52x-jgwp](https://github.com/advisories/GHSA-c78m-c52x-jgwp) / CVE-2026-49740, [GHSA-3gp5-q4jw-3v94](https://github.com/advisories/GHSA-3gp5-q4jw-3v94) / CVE-2026-48152, [GHSA-qhv3-wjg8-6fx6](https://github.com/advisories/GHSA-qhv3-wjg8-6fx6) / CVE-2026-48151, [GHSA-6xp4-cf37-ppjh](https://github.com/advisories/GHSA-6xp4-cf37-ppjh) / CVE-2026-48150, [GHSA-cv96-5348-p5p8](https://github.com/advisories/GHSA-cv96-5348-p5p8) / CVE-2026-48148, [GHSA-wxq7-x3qp-vcr8](https://github.com/advisories/GHSA-wxq7-x3qp-vcr8) / CVE-2026-48147, [GHSA-x4r9-gmw3-hxww](https://github.com/advisories/GHSA-x4r9-gmw3-hxww) / CVE-2025-58175, [GHSA-7qmg-grcp-qf25](https://github.com/advisories/GHSA-7qmg-grcp-qf25) / CVE-2025-52465, and [GHSA-j9gf-vw2f-9hrw](https://github.com/advisories/GHSA-j9gf-vw2f-9hrw).

This batch is durable because the advisories expose reusable operator boundaries: backend CMS file controls resolving outside intended mounts, local storage write primitives crossing into PHP deserialization, low-code datasource secrets moving from server-side storage to attacker-controlled endpoints, unauthenticated webhook schema mutation, app-scoped API roles becoming global administration, host fields crossing into server-side network connections, CSRF route matching bypasses, geospatial XML/entity and absolute-path file boundaries, and email-link base URLs derived from caller-controlled origins.

## What changed

- **TYPO3 FAL and Media Module file boundaries** — several TYPO3 advisories describe backend users with limited file or metadata permissions reaching files outside permitted file mounts, fallback storage resolving paths relative to document root, and clipboard/media APIs accepting records or files without the expected read checks.
- **TYPO3 storage-to-deserialization boundary** — TYPO3's `VariableFrontend` cache and `Registry` deserialized PHP payloads without integrity validation or class restrictions. Exploitation requires direct local write access to the cache store or `sys_registry` database table, making it useful as a post-compromise or chained-write validation path rather than a standalone remote issue.
- **Budibase REST datasource secret relay** — affected Budibase versions let a Basic app user read an existing REST datasource with redacted auth values, update only the base URL while preserving redaction placeholders, and execute a saved relative-path query so the server reattaches stored credentials to an attacker-controlled endpoint.
- **Budibase webhook schema authorization bypass** — the schema-building route lives under builder routes, but generic webhook endpoint detection bypassed authorization for `/api/webhooks/schema`, letting unauthenticated callers mutate a known webhook's body schema and automation trigger output schema.
- **Budibase public roles assignment escalation** — `/api/public/v1/roles/assign` accepted workspace-scoped builders via `x-budibase-app-id`, then forwarded request-body assignment properties into the SDK, allowing global builder/admin flags to be set in affected Enterprise deployments.
- **Budibase VectorDB host SSRF** — builder-controlled VectorDB host values were only checked as non-empty strings before server-side connection attempts, creating internal TCP reachability and timing/error evidence boundaries.
- **Budibase Worker CSRF route matcher bypass** — unanchored route regexes evaluated against the full URL, including query string, can cause CSRF middleware to skip token validation when a public route pattern is injected into the query string.
- **GeoServer entity-resolution SSRF and master-password dump file write** — GeoServer deployments using `ENTITY_RESOLUTION_ALLOWLIST` and a proxy base URL without a path/slash can resolve XML entities to unintended locations, while authenticated security administrators can supply absolute paths to dump the master password into new files where parent directories already exist.
- **Appsmith origin-derived reset links** — Appsmith password-reset and email-verification flows derived the link base URL from the request `Origin` header when `APPSMITH_BASE_URL` was unset, allowing attacker-controlled hosts in security-sensitive email links on deployments with email enabled.

## Operator triage

1. **Sort by role and feature precondition:** TYPO3 requires backend or storage-write access; Budibase findings range from unauthenticated known-webhook mutation to Basic app user and Builder/API-key prerequisites; GeoServer file write requires security admin; Appsmith requires a specific missing base-URL configuration.
2. **Prioritize boundary crossings over severity labels:** datasource credential relay, app-builder-to-global-admin, file-mount escape, absolute-path writes, and token-bearing link host control are stronger reports than generic XSS, DoS, or configuration summaries.
3. **Use canary objects only:** callbacks should be tester-controlled; file proofs should use marker files and disposable paths; reset-link tests should use owned accounts; webhook and automation proofs should use synthetic schemas and workflows.
4. **Do not upgrade proof into impact you did not safely show:** avoid reading real logs/secrets, dumping real master passwords, sending victim reset emails, mutating production automations, or executing JSP/PHP payloads.

## Replayable validation boundaries

### TYPO3 backend file and storage boundaries

- Test with a disposable backend user whose file mounts and record access are intentionally limited. Record the visible allowed mount set before probing.
- For FAL prefix checks, use synthetic directories whose names share a prefix, such as `/tmp/typo3-root` and `/tmp/typo3-root-extra`, and a marker file outside the intended root. Positive proof is creation of a storage definition or metadata lookup that reaches only the marker path.
- For Media Module and Backend API checks, compare the limited user's visible file list with metadata/download or clipboard actions against out-of-mount marker files. Do not read real logs, configuration, or user-uploaded private files.
- For the deserialization boundary, keep validation in a lab where the tester controls the cache or `sys_registry` write primitive. A safe proof is deserialization of an inert test class or marker object, not a gadget chain or command execution.
- Evidence should include TYPO3 version, package/component, user role, allowed mounts, route or API name, marker path/object, and patched-version negative behavior if available.

### Budibase datasource, webhook, role, SSRF, and CSRF boundaries

- Use a lab or customer-approved workspace with synthetic apps, datasources, automations, webhooks, users, and API keys.
- For REST datasource secret relay, configure a saved relative query with a disposable Basic/Bearer canary token, then as a Basic app user update only the datasource base URL to a tester callback. Positive proof is the canary token reaching the callback from Budibase, not reuse of production credentials.
- For webhook schema mutation, use a known disposable webhook ID and submit a harmless schema field change without credentials. Confirm whether the automation trigger schema changes and whether patched 3.39.0 rejects the request.
- For role assignment, use a workspace-scoped builder API key and a disposable target user. Attempt only a marker privilege change in a test tenant; immediately clean up. Evidence should show app-scoped pre-state, request shape with tokens redacted, and resulting global flag.
- For VectorDB host SSRF, point the host at a tester-controlled listener or unroutable canary range and capture timing/error differences. Do not connect to metadata services or internal production ports.
- For Worker CSRF route matching, prove the bypass with an owned browser session and a harmless state change, such as a canary profile/config field. Include the exact query-string route-pattern injection and a negative control without the injected pattern.

### GeoServer XML/entity and file-write boundaries

- Confirm GeoServer version, proxy base URL shape, `ENTITY_RESOLUTION_ALLOWLIST` use, and the exact role available to the tester.
- For XML/entity SSRF, submit only an entity or XML import path that calls back to a tester-controlled URL. Do not probe internal services, cloud metadata, or arbitrary customer hosts.
- For the master-password dump path, validate only in a lab or a customer-approved clone. Use a disposable absolute path under a test directory whose parents already exist; never dump a production master password or write into live webroots.
- If demonstrating write-to-executable-path risk, keep it theoretical unless a dedicated lab WAR/container is supplied. A marker text file is enough to prove the arbitrary absolute-path write primitive.
- Evidence should include role, affected GeoServer version, configuration preconditions, sanitized XML/path input, callback or marker-file result, and cleanup.

### Appsmith reset-link origin control

- Validate only with owned accounts on a deployment where email delivery is enabled and `APPSMITH_BASE_URL` is confirmed unset or intentionally unset in a lab.
- Send `POST /forgotPassword` or `POST /resendEmailVerification` with an attacker-controlled `Origin` pointing to a tester domain. Capture the delivered email to a tester-controlled mailbox and verify the clickable reset/verification link host.
- Do not target other users' accounts or attempt token redemption outside an owned test account.
- Evidence should include Appsmith version, configuration state, route used, redacted request headers, email link host comparison, and patched/configured negative behavior.

## Reporting heuristics

- Lead with the exact crossed boundary: backend file permission to outside-mount file, local storage write to PHP object deserialization, Basic app user to stored datasource credential relay, unauthenticated webhook schema mutation, workspace builder to global role assignment, builder host field to server-side TCP connection, route-matcher query injection to CSRF skip, GeoServer XML to outbound request, absolute path to file creation, or request `Origin` to token-bearing email link.
- Preserve preconditions in the title or first paragraph. These findings are high-signal when the report names the required role, feature flag, known webhook ID, deployment config, package version, and safe proof object.
- Keep proof artifacts inert and owned. Strong evidence is a callback receipt, marker file, synthetic metadata row, canary schema field, or owned-account email; weak evidence is broad claims about RCE, secret theft, or account takeover without controlled validation.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. Tornado C-extension memory access, pypdf resource-consumption issues, gorest race-condition crash, nebula-mesh cache headers, Routinator crash/cache traversal updates, and TYPO3 indexed-search/sanitizer XSS were tracked but not promoted here because they either skew toward availability/robustness or add less reusable offensive operator workflow than the file, authz, SSRF, role, and token-link boundaries above. No new PortSwigger, Trail of Bits, ProjectDiscovery, Disclosed, or CISA KEV item in this run added a higher-signal workflow than the GitHub advisory batch above.
