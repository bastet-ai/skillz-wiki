# GeoServer JNDI, WsgiDAV share-root, OpenFGA cache-key, DevGuard public-asset, and Filament scope boundary checks

Source: hourly offensive-security scan, 2026-06-11. Primary entries: GitHub advisories [GHSA-g628-r368-6vh7](https://github.com/advisories/GHSA-g628-r368-6vh7) / CVE-2025-27511, [GHSA-wxq4-cc2q-338q](https://github.com/advisories/GHSA-wxq4-cc2q-338q) / CVE-2026-48099, [GHSA-8396-jffm-qx4w](https://github.com/advisories/GHSA-8396-jffm-qx4w) / CVE-2026-48096, [GHSA-6p54-fw2f-q7gf](https://github.com/advisories/GHSA-6p54-fw2f-q7gf) / CVE-2026-48089, [GHSA-7q3w-xqjw-g3cr](https://github.com/advisories/GHSA-7q3w-xqjw-g3cr) / CVE-2026-48067, and [GHSA-r236-5pc3-3qcp](https://github.com/advisories/GHSA-r236-5pc3-3qcp) / CVE-2026-11401.

This batch is durable because each item exposes a reusable operator boundary: admin-controlled datastore connection strings crossing into JNDI lookup, string-prefix filesystem confinement, authorization decisions cached under colliding keys, public-read assets permitting cross-tenant writes, UI-scoped relation selectors accepting tampered values, and PostgreSQL wrapper search-path privilege crossing.

## What changed

- **GeoServer DB2 datastore JNDI RCE boundary** — when the DB2 extension is installed, authenticated users who can create vector data stores can submit crafted DB2 JDBC connection parameters. The advisory describes a JNDI attack path through unrestricted connection parameters that can lead to code execution via deserialization of untrusted data.
- **WsgiDAV encoded-dot share escape** — WsgiDAV 4.3.3 filesystem shares built candidate paths with `abspath(join(root_path, *path_parts))` and then used raw `startswith(root_path)` containment. Encoded parent-directory segments can escape into sibling paths whose absolute names share the same prefix, enabling GET, PUT, and DELETE outside the configured share root when OS permissions allow it.
- **OpenFGA iterator cache-key delimiter injection** — OpenFGA deployments with `SharedIteratorCache` and `ListObjectsIteratorCache` enabled can map two distinct check/list requests onto the same cache key, causing a later request to reuse an earlier authorization result inside the same store.
- **DevGuard public-asset write authorization gap** — any authenticated user on an affected instance can write or delete VEX rules and related vulnerability-triage objects on public assets without membership in the owning organization/project/asset. Private assets are not described as affected by this public-read exemption path.
- **Filament AttachAction/AssociateAction scope mismatch** — Filament relation actions may scope visible `Select` options with `recordSelectOptionsQuery()`, but the built-in validation did not enforce the same scope. A user who can trigger the action can tamper with Livewire component state and submit an out-of-scope related record value.
- **AWS Advanced Go Wrapper Aurora PostgreSQL privilege boundary** — AWS Go Wrapper 2026-04-06 for Aurora PostgreSQL may allow a low-privilege authenticated database user to create a crafted function that is later executed with permissions of another RDS user, potentially escalating to `rds_superuser`.

### June 23 Filament temporary-upload update

[GHSA-44wp-g8f4-f4v5](https://github.com/advisories/GHSA-44wp-g8f4-f4v5) adds a separate Filament boundary: schemas that do not need file upload, such as panel login forms, still received Livewire's `WithFileUploads` behavior, exposing unauthenticated temporary file uploads. Treat framework-level upload traits as a route-surface boundary, not only as a form-field feature.

## Operator triage

1. **Confirm the exact trust boundary before probing:** these are not broad unauthenticated internet RCEs. Most require authenticated access, a specific extension, a feature flag, a public asset, a relation action, or an affected database wrapper version.
2. **Prioritize admin-to-runtime and tenant-to-tenant crossings:** GeoServer datastore creation, DevGuard public assets, Filament relation actions, OpenFGA shared authorization services, and Aurora wrapper deployments all sit on high-value control planes.
3. **Inventory path-prefix layouts and inherited traits:** WsgiDAV and similar static/file-share providers are most interesting when the served root has prefix-sharing siblings, such as `/srv/share` next to `/srv/share_private`; Filament and Livewire are most interesting when upload traits are inherited by unauthenticated components that do not visibly expose upload fields.
4. **Use canary objects only:** proof should be a callback URL, marker file, disposable relation row, synthetic FGA tuple, harmless VEX rule, or test database function. Do not read secrets, destroy production files, alter real SBOM/VEX data, or execute payloads on production systems.

## Replayable validation boundaries

### GeoServer DB2 datastore connection boundary

- Test only in a lab or with a customer-approved GeoServer instance where you are allowed to create data stores. Confirm the DB2 extension is installed and the tester account has datastore creation rights.
- Use an inert JNDI/callback canary to prove outbound lookup behavior or connection-parameter acceptance. Do not host deserialization payloads or attempt command execution on production.
- Evidence should include GeoServer version, DB2 extension presence, role/permission used, datastore creation route, sanitized JDBC parameter shape, and callback receipt or controlled error trace.
- A strong report states that exploitation requires authenticated datastore creation; it does not claim unauthenticated GeoServer compromise.

### WsgiDAV filesystem share-root escape

- Build proof with disposable directories, for example `/tmp/skillz-share` and `/tmp/skillz-share_private/skillz-wsgidav-canary.txt`.
- Send one encoded traversal request through the WebDAV share, such as `/%2e%2e/skillz-share_private/skillz-wsgidav-canary.txt`, adapted to the mounted path layout.
- If write/delete testing is authorized, create and remove only disposable marker files outside the share root. Prefer read-only marker proof in production-like environments.
- Evidence should compare in-root access, non-prefix sibling rejection, prefix-sharing sibling canary access, authenticated/anonymous state, and patched 4.3.4 behavior if available.

### OpenFGA authorization-cache collision

- Validate in an isolated store with cache features explicitly enabled. Do not run collision experiments against shared production authorization stores.
- Create two synthetic users, objects, relations, and tuple sets where request A should return allow and request B should return deny, then shape tuple/object/user strings to exercise delimiter ambiguity in the cache key.
- Run request A first, then request B, and record whether B reuses A's cached authorization result. Clear cache and reverse the order to rule out ordinary model error.
- Evidence should include the authorization model, synthetic tuple set, cache flags, request pair, expected results without cache, observed cached result, and OpenFGA version.

### DevGuard public-asset triage write boundary

- Use two disposable organizations or projects on the same DevGuard instance. Make only a test asset public.
- From an authenticated account with no membership in the victim org/project/asset, attempt a harmless VEX rule create/update/delete or external-reference write against the public asset.
- Preserve only canary fields, object IDs, and before/after state for the synthetic asset. Do not modify real vulnerability status, SBOM, VEX, license-risk, or mitigation records.
- Evidence should show attacker account tenancy, lack of victim membership, public asset identifier, route/method, canary write, and cleanup.

### Filament relation-action scope enforcement

- Use a low-privilege test user who can open the affected AttachAction or AssociateAction but should only see scoped options.
- Capture the visible `Select` option set, then tamper with the Livewire component state to submit a related record ID outside `recordSelectOptionsQuery()` scope.
- Proof is positive when the out-of-scope relation is attached/associated despite being absent from the UI-scoped options.
- Evidence should include model/resource names, user role, visible in-scope IDs, out-of-scope canary ID, request diff, and final relation state.

### Filament unauthenticated temporary uploads

- Use a lab Filament app with a panel login or other unauthenticated schema that should not accept uploads. Do not test production storage buckets or shared app disks with large files.
- Send a small benign marker file through the Livewire temporary-upload route reachable from the unauthenticated component context. Keep the file inert, non-executable, and clearly disposable.
- Positive evidence is successful temporary-object creation without authentication or a form-level upload requirement, plus storage path, route, response, and version. Avoid disk-fill, cost-inflation, malware, web-shell, or public execution tests.
- Negative controls: unauthenticated components without file fields cannot invoke temporary uploads, and authenticated components enforce expected role/storage restrictions.

### Aurora PostgreSQL wrapper search-path privilege boundary

- Use an isolated Aurora PostgreSQL test instance or a customer-approved lab clone with AWS Go Wrapper 2026-04-06 behavior. Do not attempt privilege escalation on shared production databases.
- As a low-privilege canary user, create a benign function or object in a schema that can be reached through the wrapper's search path. The proof should emit a marker value or write to a test table, not run OS commands or access secrets.
- Trigger only the documented wrapper-mediated path needed to show execution under another RDS user's permissions. Confirm the patched wrapper release no longer reaches the canary function under elevated context.
- Evidence should include wrapper version, database engine, low-privilege role, search path, canary function name/body redacted to marker behavior, caller/effective role observation, and cleanup.

## Reporting heuristics

- Lead with the crossed boundary: datastore admin to server-side JNDI lookup, WebDAV share user to sibling filesystem path, one authorization request to another cached result, cross-org authenticated user to public-asset writes, UI-scoped relation picker to unscoped server-side attach, unauthenticated component to temporary upload storage, or low-privilege DB user to wrapper-mediated elevated execution.
- State preconditions and non-claims up front. These reports become weak if they omit extension presence, cache flags, public asset visibility, relation action reachability, or affected wrapper version.
- Keep destructive primitives theoretical unless the customer explicitly authorized them in a lab. For WsgiDAV, DevGuard, and PostgreSQL, marker evidence is enough.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. MessagePack LZ4, Russh allocation/prompt/banner parsing, and similar parser/resource-exhaustion items were tracked but not promoted in this batch because they are primarily availability or robustness issues without a stronger reusable privilege, file, tenant, or authorization boundary. No new PortSwigger, Trail of Bits, ProjectDiscovery, Disclosed, or CISA KEV item in this run added a higher-signal offensive operator workflow than the GitHub advisory batch above.
