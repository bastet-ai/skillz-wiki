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

### August 20 GeoServer FreeMarker template-injection follow-up

[GHSA-wf6j-gr27-g7ch / CVE-2024-45747](https://github.com/advisories/GHSA-wf6j-gr27-g7ch) extends the GeoServer surface: on a plain GeoServer `< 2.27.0` installation (no extension needed), the built-in WMS `GetFeatureInfo` HTML/JSON and `GetMap` KML/GeoRSS output formats render FreeMarker templates, and `TemplateUtils.getSafeConfiguration()` only blocks direct access to `freemarker.template.utility.Execute`. A method-call chain can still reach that utility class, so an authenticated user who can supply template content reaches OS command execution and arbitrary file read/write.

Replayable validation:

- Preconditions: lab or customer-approved GeoServer `< 2.27.0`, an authenticated account that can reach the affected WMS output-format route, and no production maps or data stores.
- Submit a canary template through the affected route that resolves a synthetic method chain toward the blocked utility class, ending in an inert marker such as a `touch`/`echo` into a temporary lab directory or a controlled environment-variable readback rendered into the response. Do not read secrets or write outside the lab root.
- Record: version, role, WMS output format, raw template, the exact chain step that reaches the utility class, and the marker or rendered value. Compare against patched 2.27.0 behavior, where `GEOSERVER_FREEMARKER_BLOCK_LIST`, `GEOSERVER_FREEMARKER_ALLOW_LIST`, and `GEOSERVER_FREEMARKER_API_EXPOSED` restrict reachable objects to getters by default.
- A bounded positive is **authenticated template content -> rendered output format -> canary chain reaches the blocked utility -> marker readback or inert file operation only**. Report it as a template-author-to-runtime boundary, not as unauthenticated compromise, and state the output formats and role required up front.

### August 28 WsgiDAV MySQL provider blind SQLi follow-up

[GHSA-p6gw-4frg-j7jw / CVE-2026-55509](https://github.com/advisories/GHSA-p6gw-4frg-j7jw) (high) adds a second WsgiDAV boundary, distinct from the filesystem share-root escape above. The sample `MySQLBrowserProvider` builds its SQL by string concatenation: a path like `/db/users/1` is split into a validated table name and an **unescaped record key** dropped straight into `WHERE id = '<key>'`, so a single quote in the key breaks out into SQL. The provider's numeric-type check has a typo (`INTT` instead of `INT`), so even integer primary keys take the quoted branch — but that branch is equally injectable via quote breakout. The key is read during the normal existence check on a plain `GET`, so no authentication, write access, or special method is needed when the share is published anonymously, as these read shares commonly are.

Durable operator value: the **status-code / response-time oracle**. A condition that matches one row and one that matches none produce different DAV status codes (e.g. 200 vs 404), which turns the provider into a boolean blind-SQLi oracle against the backing database — the advisory confirmed full data extraction this way locally.

Replayable validation:

- Preconditions: a lab WsgiDAV with `MySQLBrowserProvider` enabled against a disposable test database (the module is sample-only and not default-enabled; installations that do not activate it are not affected), a known test table, and a read share published without authentication.
- Confirm the provider is active by listing the configured table via the share, then send a key that breaks out with a boolean payload (e.g. `1' AND 1=1 -- ` vs `1' AND 1=2 -- `) and record the two different DAV status codes as the oracle.
- Extract only a single marker column value from a disposable table to prove full extraction capability. Do not read, copy, or exfiltrate real database data, and do not issue `UPDATE`/`DELETE`/`DROP` against production.
- Evidence: provider version, enabled-module config, the share URL, the oracle request pair with their status codes, and the single extracted marker value. Report it as an unauthenticated (or share-scoped) blind SQLi boundary, not a general WsgiDAV compromise.

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

## September 16 follow-up: OpenFGA `ListUsers` exclusion miss under wildcard-intersected intersections

[GHSA-g3pg-frfm-pr2m](https://github.com/advisories/GHSA-g3pg-frfm-pr2m) / CVE-2026-61709 (OpenFGA `<= 1.18.0`, fixed 1.18.1) is a second **authorization-decision divergence** on the same engine family as the cache-collision item above, this time in the `ListUsers` rewrite rather than the cache. Preconditions: a relation defined as an intersection where one operand is an exclusion (`rel1: (public_user but not blocked) and rel2`), the exclusion's base granted via a type-bound wildcard (`user:*`), and the excluded user also granted a concrete tuple through the other intersection operand. `ListUsers` then returns the deliberately-excluded user.

Operator framing: this is a differential-oracle opportunity, not just a bug. On any OpenFGA-backed app that uses `ListUsers` for enumeration or enforcement, build a two-user synthetic model (wildcard grant + `but not` exclusion + concrete grant via sibling operand) and diff `Check` vs `ListUsers` vs `ListObjects` for the same (user, relation) pair. A subject visible through one API and invisible through another means the app's authorization answer depends on which API the developer happened to call — trace which API guards the sensitive action before claiming impact. Prove with synthetic tuples in an isolated store only; the same three-API differential applies to any relationship-based engine (ReBAC) evaluation.

## Reporting heuristics

- Lead with the crossed boundary: datastore admin to server-side JNDI lookup, WebDAV share user to sibling filesystem path, one authorization request to another cached result, cross-org authenticated user to public-asset writes, UI-scoped relation picker to unscoped server-side attach, unauthenticated component to temporary upload storage, or low-privilege DB user to wrapper-mediated elevated execution.
- State preconditions and non-claims up front. These reports become weak if they omit extension presence, cache flags, public asset visibility, relation action reachability, or affected wrapper version.
- Keep destructive primitives theoretical unless the customer explicitly authorized them in a lab. For WsgiDAV, DevGuard, and PostgreSQL, marker evidence is enough.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. MessagePack LZ4, Russh allocation/prompt/banner parsing, and similar parser/resource-exhaustion items were tracked but not promoted in this batch because they are primarily availability or robustness issues without a stronger reusable privilege, file, tenant, or authorization boundary. No new PortSwigger, Trail of Bits, ProjectDiscovery, Disclosed, or CISA KEV item in this run added a higher-signal offensive operator workflow than the GitHub advisory batch above.
