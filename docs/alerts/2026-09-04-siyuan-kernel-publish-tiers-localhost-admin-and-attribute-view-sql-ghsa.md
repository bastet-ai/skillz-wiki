# SiYuan kernel: publish-access tiers, localhost-trust admin bypass, and attribute-view SQL/SSTI boundaries (GHSA)

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (SiYuan kernel cluster). This is the largest cluster in the wave — 22 advisories across one desktop note-app kernel — and it is durable because it exposes a **repeatable trust-boundary audit axis** that the 2026-07-10 boundary page first flagged: a loopback note-app kernel that grants broad privileges on origin/localhost trust and that is missing per-route access-tier enforcement on its publish and attribute-view endpoints.

Primary entries (all linked in the source index): [GHSA-5fhr-f75j-8wr9](https://github.com/advisories/GHSA-5fhr-f75j-8wr9), [GHSA-8x84-r2ff-h8pq](https://github.com/advisories/GHSA-8x84-r2ff-h8pq), [GHSA-jv8v-xq2h-657v](https://github.com/advisories/GHSA-jv8v-xq2h-657v), [GHSA-qvq9-hq6p-v378](https://github.com/advisories/GHSA-qvq9-hq6p-v378), [GHSA-vpjw-wf5h-cgpq](https://github.com/advisories/GHSA-vpjw-wf5h-cgpq), [GHSA-67x2-mq63-v9vm](https://github.com/advisories/GHSA-67x2-mq63-v9vm), [GHSA-6mcf-g667-w3qv](https://github.com/advisories/GHSA-6mcf-g667-w3qv), [GHSA-x67c-8pwr-m8g3](https://github.com/advisories/GHSA-x67c-8pwr-m8g3), [GHSA-v7ph-r5r6-4jcj](https://github.com/advisories/GHSA-v7ph-r5r6-4jcj), [GHSA-3mp7-4rh5-jrv9](https://github.com/advisories/GHSA-3mp7-4rh5-jrv9), [GHSA-mw8r-mw84-88v2](https://github.com/advisories/GHSA-mw8r-mw84-88v2), [GHSA-q2vg-7qgx-x5fc](https://github.com/advisories/GHSA-q2vg-7qgx-x5fc), [GHSA-wgwx-479j-23vq](https://github.com/advisories/GHSA-wgwx-479j-23vq), [GHSA-7j72-f6wg-cxw6](https://github.com/advisories/GHSA-7j72-f6wg-cxw6), [GHSA-pm3w-vxp9-ccwc](https://github.com/advisories/GHSA-pm3w-vxp9-ccwc), [GHSA-36v8-mpjm-8j5r](https://github.com/advisories/GHSA-36v8-mpjm-8j5r), [GHSA-69mh-gvh4-8gp7](https://github.com/advisories/GHSA-69mh-gvh4-8gp7), [GHSA-fph3-ghq9-vw66](https://github.com/advisories/GHSA-fph3-ghq9-vw66), [GHSA-7hm9-v7vf-7g4w](https://github.com/advisories/GHSA-7hm9-v7vf-7g4w), [GHSA-vh22-h7hf-www7](https://github.com/advisories/GHSA-vh22-h7hf-www7), [GHSA-gw25-m53r-qh88](https://github.com/advisories/GHSA-gw25-m53r-qh88), and [GHSA-99rq-75j6-5j9f](https://github.com/advisories/GHSA-99rq-75j6-5j9f).

!!! warning "Authorized validation only"
    Keep proofs to a disposable SiYuan desktop or Docker kernel with synthetic notebooks and no personal workspace data. Use synthetic block IDs, marker-only workspace files, a lab `AccessAuthCode`, and denied SQLite/file sinks. Do not query real note content, read assets or sync keys, capture browser history, exfiltrate encrypted-notebook derivation material, or execute SQL beyond inert canary statements.

## Why this cluster is one audit axis

The 2026-07-10 page established that SiYuan's loopback kernel treats `chrome-extension://` origins as administrators and reaches unauthenticated render/template helpers. This wave generalizes that into a **route-by-route access-tier inventory**:

- **Publish-access tier is not enforced consistently.** A large share of the kernel's read endpoints (`getAttributeViewKey`, `getBlockAttrs`, `getFileAnnotation`, `getBlockBreadcrumb`, `getBlockInfo`, `getBacklinkDoc`, and the Graph endpoints) either omit the publish-password tier entirely, apply the wrong tier, or allow anonymous access where a password-protected tier should apply. The same route family is also reachable through WebSocket broadcast, where the publish-boundary check is bypassed.
- **Localhost-trust admin bypass.** `GHSA-3mp7-4rh5-jrv9` / CVE-2026-72809: endpoints gated by `AccessAuthCode` still grant administrator action to a caller identified only by localhost origin/loopback peer. Pair with the 2026-07-10 blanket `chrome-extension://` administrator trust.
- **Attribute-view → SQL/SSTI chain.** `GHSA-x67c-8pwr-m8g3` / CVE-2026-72807 routes second-order SSTI into arbitrary SQL via attribute-view rendering; `GHSA-fph3-ghq9-vw66` / CVE-2026-69083 and `GHSA-vh22-h7hf-www7` / CVE-2026-69084 reach unauthenticated arbitrary SQL execution (including `REGEXP` injection); `GHSA-q2vg-7qgx-x5fc` / CVE-2026-72811 adds SQL injection in backlink/mention search through an unescaped fragment.
- **Path/identifier handling.** `GHSA-7hm9-v7vf-7g4w` / CVE-2026-69086 (path traversal via unvalidated `avID` in `RenderAttribute...`) and `GHSA-gw25-m53r-qh88` (path traversal via an `/export/temp/` short-circuit branch) are filesystem-boundary legs; `GHSA-jv8v-xq2h-657v` / CVE-2026-72802 discloses absolute filesystem path and OS username; `GHSA-8x84-r2ff-h8pq` / CVE-2026-72801 is encrypted-notebook key-derivation/wrap exposure.
- **DoS / disclosure tails.** `GHSA-99rq-75j6-5j9f` (stored and reflected XSS via an SVG sanitizer gap) and the remaining cross-boundary disclosure records (`GHSA-pm3w-vxp9-ccwc`, `GHSA-36v8-mpjm-8j5r`, `GHSA-69mh-gvh4-8gp7`).

## Boundary map

| Class | Route / sink | Defect | Reusable check |
| --- | --- | --- | --- |
| Publish-tier omission | `getAttributeViewKey`, `getBlockAttrs`, `getFileAnnotation`, `getBlockBreadcrumb`, `getBlockInfo` | publish-password tier not applied; anonymous reaches protected data | For each read endpoint, compare anonymous vs. publish-password vs. full-auth tier and record which tier actually gates it. |
| Publish-tier omission (Graph) | Graph endpoints | publish-password tier omitted; anonymous graph access | Enumerate graph read routes; test anonymous reachability against a password-protected notebook. |
| Publish-boundary bypass | WebSocket broadcast | broadcast path skips publish-boundary check | Drive the same read through the broadcast channel and compare the access decision vs. the REST route. |
| Localhost-trust admin | auth-code-gated endpoints | loopback peer treated as administrator | Confirm whether the admin decision binds to `AccessAuthCode`, a peer address, or origin; a loopback/origin allow is the vulnerable pattern. |
| Second-order SSTI → SQL | attribute-view rendering | rendered template value reaches a SQL/REGEXP sink | Seed a value that survives one round-trip then reaches the SQL sink; prove the sink is reached with an inert canary query, not a real read. |
| Unauth SQL execution | `searchEm...`, backlink/mention search | unescaped user fragment into SQL | Craft an unescaped fragment that changes the query shape; stop at query-shape/parse evidence, not data exfiltration. |
| Path traversal | `RenderAttribute` `avID`, `/export/temp/` short-circuit | unvalidated identifier escapes the intended root | Use a sibling marker file outside the intended root; record whether the traversal reaches it. |
| Info disclosure | filesystem path / OS username; encrypted-notebook key material | absolute path, username, KDF/wrap material disclosed | Capture the disclosed fields as the boundary proof; do not use KDF material to decrypt real notebooks. |
| XSS | SVG sanitizer | legacy handler list blocked but newer attributes allowed before insert | Insert a harmless event marker via a newer attribute; prove the sanitizer gap, not script execution. |

## Replayable validation boundaries

### Publish-access tier inventory (the core check)

1. Stand up a disposable SiYuan kernel (Docker or desktop) with one synthetic notebook whose publish password is set, and one notebook with no publish password as the negative control.
2. For each attribute/read endpoint in the map above, issue the same request under three principals: **anonymous**, **publish-password**, and **full auth-code**. Record which tier actually gates the response.
3. A positive finding is a route that returns protected data to **anonymous** when a publish-password tier is configured, or a route whose tier is weaker than the notebook's configured protection.
4. Repeat the flagged routes through the **WebSocket broadcast** channel and record whether the broadcast path enforces the same tier as the REST route.
5. Capture the `AccessAuthCode` / peer-address / origin decision for the admin-gated endpoints: does the administrator role bind to a token, or is a loopback peer sufficient?

Report each positive as **configured publish tier -> observed tier -> route** without disclosing real note content. Keep evidence to route metadata, status differentials, and one synthetic block ID.

### Attribute-view → SQL/SSTI chain

1. In a lab notebook, create one attribute-view record whose cell value contains an inert canary template token, for example `SILYUAN-CANARY-{{ }}` or a fragment that would be a tautology in SQL.
2. Trigger the attribute-view render and capture the query string or prepared statement that the renderer builds (lab logging or a proxy between kernel and SQLite). A positive is that the user value reaches the SQL/`REGEXP` sink without parameterization.
3. Prove sink reach with a **query-shape differential only** — for instance, a fragment that turns the query into a syntax error vs. a clean value — not a real data read. Do not run `SELECT` against real notebook tables, do not use `UNION`/stacked queries to exfiltrate, and do not escape the SQLite sandbox.
4. For the second-order SSTI leg, confirm the value survives one round-trip (write → store → re-render) before it reaches the SQL sink; the two-stage persistence is the reusable part of the chain.

Report as **attribute-view cell -> unescaped template/fragment -> SQL/REGEXP sink**, naming the exact endpoint and the round-trip that carries the value.

### Path-traversal and identifier handling

1. Place one inert marker file just outside the intended workspace/asset root in the lab.
2. Drive `avID` in `RenderAttribute...` and the `/export/temp/` short-circuit branch with values that would escape the root (encoded `..`, absolute path, or a value that the short-circuit branch treats as a literal filesystem path).
3. A positive is the handler reading or writing the sibling marker file. Record the exact input that escaped and the resolved path.
4. For the filesystem-path/username disclosure and the encrypted-notebook key-material item, capture the disclosed fields as the boundary proof and **stop** — do not use the KDF/wrap material to decrypt a real notebook or turn the absolute path into a read primitive.

### XSS / SVG sanitizer gap

1. Seed a note containing an SVG payload that uses a *newer* handler attribute (one the legacy blocklist does not name).
2. Render it through the affected stored/reflected sink and record whether the attribute survives sanitization to the DOM. A positive is the attribute reaching the renderer with a harmless event marker, not executed script.
3. Do not escalate to cross-origin or storage-XSS data theft; the reusable value is the sanitizer-allowlist gap, proven with a marker.

## Durable operator value

1. **Access-tier drift is a whole-route-family bug, not a single-CVE bug.** SiYuan shipped 10+ advisories that are all "endpoint X forgot the publish-password tier." The operator workflow is a **full route × tier matrix** (every read endpoint × anonymous / publish-password / auth-code / loopback), not per-CVE patching. Any note-app, wiki, or "personal data" service with tiered access should be audited this way.
2. **Localhost/origin trust is the root enabler.** The admin bypass and the 2026-07-10 `chrome-extension://` administrator trust are the same class: a decision that grants privilege from *where* the request came from rather than *who* authenticated. Inventory every route that keys authorization on origin, peer address, or scheme instead of a token.
3. **Attribute-view / template-to-SQL is a reusable injection class.** Any UI that renders user cell values into a generated query (SQL, `REGEXP`, template) is a second-order injection surface. Test the value's full lifecycle: write → store → re-render → sink, because the dangerous leg is the round-trip, not the first request.
4. **Short-circuit branches are where path checks live or die.** The `/export/temp/` branch bypassing the normal root check is a pattern: audit *every* route that branches on request shape (query param, temp flag, alternate method) and re-apply the containment check on each branch.
5. **DoS/XSS tails are the disclosure, not the impact.** The SVG sanitizer gap and the disclosure items are what makes the cluster reportable; keep them bounded to marker proof so the page stays a durable recon/heuristic asset rather than a payload sheet.

## Safety

- **Disposable kernel only.** Synthetic notebooks, one synthetic block ID, marker files outside the intended root, a lab `AccessAuthCode`, and denied SQLite/file sinks.
- **No real data exfiltration.** No real note content, no asset/sync-key reads, no KDF-material use against real notebooks, no browser-history capture.
- **No real SQL execution.** Query-shape/parse evidence only; no `UNION`/stacked data reads, no sandbox escape.
- **No script execution.** XSS proven with a harmless event marker, not a live payload.

## September 4 late-wave follow-up: metadata, static-file, and secret-stripping boundaries (8 GHSAs)

A second SiYuan kernel cluster published on 2026-09-04 extends the same audit axis into three route families the first wave did not cover: **reader-reachable metadata endpoints**, **static-file route registrations**, and **the secret-stripping inventory for non-administrator `getConf`**. All eight are `CheckAuth`-only routes reachable by a publish `RoleReader` token and, when `Publish.Auth.Enable` is `false`, by the anonymous account.

Primary entries: [GHSA-mp7r-57w4-5qm3](https://github.com/advisories/GHSA-mp7r-57w4-5qm3) / CVE-2026-72792, [GHSA-h4v5-crx2-3cv4](https://github.com/advisories/GHSA-h4v5-crx2-3cv4) / CVE-2026-72793, [GHSA-34fj-mwm6-fjfg](https://github.com/advisories/GHSA-34fj-mwm6-fjfg) / CVE-2026-72794, [GHSA-h6w7-xxcf-w2mq](https://github.com/advisories/GHSA-h6w7-xxcf-w2mq) / CVE-2026-72795, [GHSA-fgmr-7w36-9qfq](https://github.com/advisories/GHSA-fgmr-7w36-9qfq) / CVE-2026-72796, [GHSA-f2rw-w22v-54vh](https://github.com/advisories/GHSA-f2rw-w22v-54vh) / CVE-2026-72797, [GHSA-mfrj-v65r-979c](https://github.com/advisories/GHSA-mfrj-v65r-979c) / CVE-2026-72798, and [GHSA-5w7r-f4cg-rqq7](https://github.com/advisories/GHSA-5w7r-f4cg-rqq7) / CVE-2026-72799.

### Boundary map

| Class | Route / sink | Defect | Reusable check |
| --- | --- | --- | --- |
| Session-signing-key disclosure | `POST /api/system/getConf` (non-admin) | `HideConfSecret` blocklist omits `Conf.CookieKey`, `NotebookCrypto`, and `Export.PandocBin` that the `exportConf` cloner already strips | Compare the two secret-stripping inventories; a positive is a field one strips and the other returns. |
| Session-cookie forge primitive | same, `Conf.CookieKey` | the session-cookie signing key is returned to any reader | Capture the key as the boundary proof; on instances without an access-auth code a forged cookie can authenticate as a privileged user. |
| Metadata tag vocabulary | tag-list endpoint using `FilterTagsByPublishIgnore` | tags from password-protected docs are counted/returned without the publish-password check | Compare the visible-only tag filter against a password-gated one; a positive is a tag label + usage count from a protected document. |
| Transclusion / embedded blocks | embedded-block render | block content is returned without publish-access filtering | Seed a marker block in a hidden/publish-forbidden doc; confirm it is returned to an anonymous reader. |
| Related-database content | `renderAttributeView` `Relation`/`Rollup` cells | the row filter is keyed only to the first cell; related-DB `Contents` are never publish-checked | Request a *published* database that relates to a *hidden* one; a positive is the private DB's block text in the published rows. |
| Fail-open row filter | `renderAttributeView` when column 0 is not a block | `bt == nil` skips the accessibility check entirely | Reorder a database so column 0 is non-block; confirm rows are returned unchecked. |
| Static-file route bypass | `/templates/`, `/snippets/`, `/widgets/`, `/plugins/`, `/emojis/`, `/export/` | registered with `CheckAuth` only; no publish-access / `refuseToAccess` / `IsSensitivePath` check | Pick a file the REST API refuses (`refuseToAccess`) and confirm the static route still serves it to the same reader. |
| Export-artifact retrieval | `/export/csv/<name>/`, `/export/code/<name>` | code/CSV export names are derivable from `listDocsByPath` titles while the artifact exists | Derive the name, request the artifact, and record whether a private document's export is returned. |
| Encrypted-notebook enumeration | `POST /api/notebook/getEncryptedNotebookStatus` | returns id/name/`unlocked` for every encrypted notebook, unfiltered | Compare against `lsNotebooks` (which filters publish-invisible notebooks); a positive is encrypted-notebook names + live lock state returned to a reader. |
| Private document-tree mapping | `getFullHPathByID`, `getHPathByID`, `getPathByID`, `getIDsByHPath`, `getHPathByPath` | five path-resolution endpoints with no publish-access check | Resolve a hidden/publish-forbidden document ID to its full HPath and notebook; then `getIDsByHPath` to enumerate sibling IDs. |

### Replayable validation boundaries

1. **Two-secret-inventory diff (the `getConf` core).** In a disposable kernel, diff every field returned by non-admin `POST /api/system/getConf` against the `exportConf` cloner's output. The reusable finding is any field the cloner strips but `HideConfSecret` does not. Capture `Conf.CookieKey`, `NotebookCrypto`, and `Export.PandocBin` as marker values, **not** real keys. Do not forge a live session against a real instance; the boundary proof is "secret present in reader response vs. absent in export."
2. **Static-route vs. REST-route differential.** For `/templates/`, `/snippets/`, `/widgets/`, `/plugins/`, `/emojis/`, and `/export/`, pick one path the REST `getFile`/`refuseToAccess` control denies to a reader and confirm the static route serves it under the same principal. A positive is identical reader principal, denied via REST, served via static. Use synthetic template/snippet files; do not read real notebook content or export real documents.
3. **Related-database leak.** Build two databases: a published DB-A with a `Relation`/`Rollup` column pointing at a publish-forbidden DB-B that holds a marker value. Request `renderAttributeView` for DB-A. A positive is DB-B's marker appearing in DB-A's published rows. For the fail-open leg, reorder DB-A so column 0 is non-block and confirm the row is returned with no accessibility check.
4. **Document-tree mapping.** With one document in a publish-forbidden notebook, call `getFullHPathByID` and `getPathByID` for its ID, then `getIDsByHPath` on the parent folder. A positive is the private HPath/notebook returned plus sibling document IDs. Stop at metadata; do not open the resolved documents' content.
5. **Encrypted-notebook enumeration.** Confirm `getEncryptedNotebookStatus` returns notebooks that `lsNotebooks` withholds from the same reader, and record the live `unlocked` flag. Do not use the lock-state signal to time a real read of decrypted content.

### Durable operator value

1. **Two secret-stripping inventories is the root enabler.** `HideConfSecret` (a blocklist) and the `exportConf` cloner (an allowlist the project actually maintains) diverge, and the blocklist fails open on every field nobody added. Any tiered system that has "strip these secrets for lower roles" in *two places* should be audited by diffing the two inventories field-by-field.
2. **Static-file registrations are a second, parallel route family.** The REST API's `refuseToAccess` / publish / sensitive-path controls do not apply to `gin` `.Static`/`.StaticFile` route groups. Enumerate *both* the REST handlers and the static registrations for the same data directory; the divergence is the bug.
3. **Row-level filters that key only to the primary cell leak relation/route content.** Attribute-view, table, or card UIs that render "this row's primary block is public" but ship related-cell content (`Relation`, `Rollup`, rollups, joins, embeds) from a *different* object's scope will leak that other object. Test the full cell set, not just column 0, and test the fail-open path when column 0 is not the primary identifier.
4. **`*ByPublishIgnore` visible-only filters are a recurring blind spot.** The tag, graph-node, and transclusion paths each used a visible-only filter that skipped the password tier. Audit every `*ByPublishIgnore` / "visible-only" call site against the password-aware access check.
5. **Path/ID-resolution endpoints are metadata exfiltration primitives.** Five `CheckAuth`-only filetree endpoints let an anonymous reader map the entire private tree and convert titles to IDs — removing the "attacker must know an ID" precondition for every other block-read endpoint. Inventory ID↔path↔title resolution routes separately from the content routes.

## September 5 follow-up: attribute-view key/cell filter bypass (2 GHSAs)

Two later SiYuan kernel advisories published 2026-09-05 (both fixed in `v3.8.2`, both `CheckAuth`-only, both reachable by a publish `RoleReader` — and by anonymous when `Publish.Auth.Enable` is `false`) close out the attribute-view axis with the *schema* half of the leak:

- **[GHSA-rw64-64f2-x73j](https://github.com/advisories/GHSA-rw64-64f2-x73j) — `getAttributeViewKeys` returns private cell values.** The endpoint filters attribute-view *rows* by publish access, but *cell values* (`KeyValues`) from rows bound to inaccessible documents are not filtered — a publish reader retrieves hidden payloads from rows whose document is not theirs.
- **[GHSA-5p8j-x73f-mfw4](https://github.com/advisories/GHSA-5p8j-x73f-mfw4) — `getAttributeViewKeysByID` skips parent-database visibility.** The by-ID variant never verifies the parent database's visibility, so a reader enumerates complete key schemas — sensitive field names and relation definitions — from hidden databases by ID.

Reusable checks, extending the late-wave row-filter findings:

1. **Row-level vs. cell-level vs. schema-level filtering are three separate controls.** The late-wave wave fixed row-level filtering in `renderAttributeView`; this follow-up shows the *keys/cells* endpoints (`getAttributeViewKeys`, `getAttributeViewKeysByID`) each carry their own access decision. For any attribute-view/database UI, build the full matrix: rows × cell values × key/schema definitions × parent-database visibility — a positive is any one cell of the matrix returned under a principal that should not see the source object.
2. **By-ID endpoints are the weak sibling.** Name/path-based endpoints usually inherit the caller's visible-object set; by-ID endpoints take the ID as the sole authority. For every `*ByID` route, confirm the ID is re-checked against the caller's accessible-object set *and* that the parent object's visibility is checked, not just the child's.
3. **Hidden-database schema is a recon primitive.** Sensitive field names and relation definitions from a hidden database tell an operator what data the tenant holds and how objects relate — the schema is the disclosure even when the row values stay hidden.

All proofs are marker-only in a disposable kernel: a synthetic hidden database holding one marker row + one marker key definition, requested through both endpoints with a publish reader token; the positive is the marker value/schema returned. No real note content, no real database dump, no production mutation.

## September 8 follow-up: attacker-writable clipboard MIME skips sanitization into the Node-enabled desktop renderer (1 GHSA)

A later SiYuan desktop advisory published 2026-09-08 extends the kernel audit axis into the **client-side clipboard/paste trust boundary** in the Node-enabled desktop renderer:

- **[GHSA-358r-j9r9-9hv6](https://github.com/advisories/GHSA-358r-j9r9-9hv6) / CVE-2026-86712 (high 8.8, CWE-79)** — SiYuan before `3.8.2` trusts the attacker-writable `text/siyuan` clipboard MIME type and **skips sanitization in the paste handler**. An attacker crafts a malicious web page that writes `text/siyuan` content to the clipboard; when the victim pastes into SiYuan, the injected script executes with **full Node.js access through the Electron main process** (desktop renderer only — the web/browser build is not the affected surface).

This is the desktop-client analogue of the kernel's "untrusted input reaches a privileged sink" axis, but the input channel is the OS clipboard rather than an HTTP route. Durable operator value:

1. **Clipboard MIME type is untrusted input, not a format guarantee.** A MIME label (`text/siyuan`) written by *any* web page the user visited is attacker-controlled. Any paste/import/autofill handler that branches on a client-writable MIME/content-type and *skips the sanitizer on that branch* is the vulnerable pattern — the same "short-circuit branch bypasses the containment check" lesson from the `/export/temp/` finding above, applied to the paste path.
2. **Desktop (Electron + Node) vs. web (browser) is a separate trust tier.** Code execution here requires the Node-enabled desktop renderer; the web build does not grant `process` access. When reporting, name the affected build (desktop vs. web) and the renderer's Node access level, because the impact tier is set by the *host*, not the payload.
3. **The reusable check is a differential: same payload, sanitized-on-plain-paste vs. unsanitized-on-`text/siyuan`-paste.** Prove the sanitizer skip with a harmless event marker that survives only on the MIME-branch path; do not escalate to real Node code execution or exfiltration.

Replayable validation (marker-only): in a disposable SiYuan **desktop** build, write a `text/siyuan` clipboard payload containing a harmless event marker (no executed script), paste into a synthetic notebook, and confirm the marker reaches the renderer un-sanitized while an identical payload pasted as plain text is sanitized. Positive evidence is the MIME-branch differential. Do not run a live Node payload, do not read clipboard contents of a real user, and do not target the web build.

## Safety

- **Disposable kernel only.** Synthetic notebooks, synthetic template/snippet files, one synthetic block/document ID, a lab `AccessAuthCode`, and denied SQLite/file sinks.
- **No real secret use.** Capture `Conf.CookieKey`, `NotebookCrypto`, and encrypted-notebook material only as marker values; do not forge a live session, decrypt a real notebook, or use the OS username/path to build a real read primitive.
- **No real content exfiltration.** Prove related-DB, transclusion, and document-tree leaks with synthetic marker values; do not open or dump real protected documents.
- **No production mutation.** All checks are read/decision differentials.

---

*Source: hourly offensive-security scan, 2026-09-04 and 2026-09-05. All 22 SiYuan kernel advisories in the first wave, the 8 late-wave advisories, and the 2 September 5 attribute-view follow-ups above (32 total) tracked in the [source index](../notes/source-index.md).*
