---
title: Agent, CMS, renderer, and export boundary checks from July 9 GHSA updates
---

# Agent, CMS, renderer, and export boundary checks from July 9 GHSA updates

This update promotes July 9 GHSA records into reusable operator checks for authorized assessments. The shared pattern is trusted automation accepting caller-shaped data after the platform has already made an access, sanitization, or locality decision: MCP tools skip the REST route's scope gate, CMS config arrays re-enter framework event binding, CSS imports follow redirects into `file://`, and export jobs turn stored slugs into filesystem paths.

Sources:

- [GHSA-382c-vx95-w3p5: Gittensory profile endpoint and MCP tool miss contributor-scoped access control](https://github.com/advisories/GHSA-382c-vx95-w3p5)
- [GHSA-3c3g-7hwg-9qmr / CVE-2026-10566: MetaGPT argument mapping reaches deserialization](https://github.com/advisories/GHSA-3c3g-7hwg-9qmr)
- [GHSA-86vw-x4ww-x467: Craft CMS `FieldsController::actionRenderCardPreview` event-handler injection](https://github.com/advisories/GHSA-86vw-x4ww-x467)
- [GHSA-c43v-4cr8-6mvp: Craft CMS `assets/icon` traversal for local `.svg` reads](https://github.com/advisories/GHSA-c43v-4cr8-6mvp)
- [GHSA-9pmc-p236-855h / CVE-2026-53727: Ruby `css_parser` SSRF and redirect-to-local-file disclosure](https://github.com/advisories/GHSA-9pmc-p236-855h)
- [GHSA-rqrh-8wpv-x7hh / CVE-2026-50553: Note Mark export path traversal through unanchored slug validation](https://github.com/advisories/GHSA-rqrh-8wpv-x7hh)
- [GHSA-588f-fvcv-xhvf / CVE-2026-50554: Note Mark public-book `deleted=true` metadata disclosure](https://github.com/advisories/GHSA-588f-fvcv-xhvf)
- [GHSA-q6qc-xp4q-rjq5 / CVE-2026-10281: Claw Orchestrator component API missing authentication](https://github.com/advisories/GHSA-q6qc-xp4q-rjq5)

!!! warning "Authorized validation only"
    Keep proofs in disposable agent, CMS, renderer, and note-export labs. Use inert MCP calls, synthetic contributor/profile rows, harmless framework event callbacks, owned redirectors, marker-only SVG and export files, and route/role decision tables. Do not collect financial data, production prompts, secrets, environment dumps, customer notes, real CMS files, or run shell payloads.

## Operator use

Use these checks when a scope includes:

- MCP servers or agent platforms that expose the same data through REST and tool transports;
- agent frameworks that deserialize or reconstruct typed messages from user, repo, checkpoint, or tool-output data;
- Craft CMS or Yii2-based admin features that accept nested config arrays, preview payloads, or `on event`-style keys;
- server-side CSS parsing for email, rich-text, document preview, or HTML-to-email flows, especially Premailer-style `@import` handling;
- note/wiki/export tools that store user-editable slugs and later join them into backup, migration, or archive paths;
- local orchestration dashboards that expose embedded component APIs on browser- or network-reachable ports.

## Recon checklist

| Boundary | What to look for | Safe canary |
| --- | --- | --- |
| REST vs MCP authorization parity | A REST route returns 403 for cross-tenant or cross-contributor access while the sibling MCP tool returns the object | Two disposable users and a synthetic non-sensitive profile field |
| Agent message reconstruction | `mapping`, checkpoint, tool-output, or instruction fields that are converted into typed objects or deserialized classes | Inert class/type marker and local-only harness logs |
| CMS config preview | Nested POST/JSON config passed to framework component constructors without cleansing event-handler keys | Harmless callback such as a marker function in a disposable admin lab, not `phpinfo()` on production |
| Icon/static helper path construction | User-controlled extension or icon name checked for existence before validation | Temp `.svg` marker under a lab-controlled readable directory |
| CSS import fetching | `@import url(...)` accepted from attacker-influenced CSS with `base_uri`, recursive redirects, or `file://` support | Owned HTTP redirector and a temp local canary explicitly placed for the test |
| Export slug-to-path joins | Stored book/note/page slugs validated with unanchored regexes, then used in `path.Join`, `filepath.Join`, archive names, or backup paths | Disposable export root and sibling marker directory under `/tmp` |
| Soft-delete public filters | Public unauthenticated list endpoints that accept `deleted`, `archived`, or `trash` flags and disable ORM scopes | Public test book/note with synthetic title only |
| Embedded component APIs | Component, plugin, or node APIs listening without the same auth as the main dashboard | Route matrix showing unauthenticated 200 vs authenticated control route |

## Validation patterns

### MCP and REST authorization parity

The Gittensory advisory is useful beyond that package because it shows a common agent-platform mistake: a route family has object-scoped authorization, but the MCP tool path reconstructs the same object without calling the same guard.

1. Enumerate each MCP tool and find the REST/API route or service method it wraps.
2. Build a two-user matrix: owner token, non-owner token, REST route decision, MCP tool decision, and returned fields.
3. Use synthetic objects with non-sensitive marker fields. A valid proof is the mismatch itself, not the value of private data.
4. Stop at field-presence evidence. Redact values and never collect production financial, wallet, prompt, or profile data.

A strong report includes the specific missing guard, the sibling endpoint that enforces it correctly, and a recommendation to share authorization middleware/service checks across transports.

### Agent deserialization and instruction mapping

For MetaGPT-style findings, test locally whether message or instruction content can cross from untrusted mapping data into object reconstruction.

1. Identify places where agent messages accept `dict`, JSON, checkpoint, or tool-returned structures and call constructors, validators, or deserializers.
2. Keep the harness local and deterministic. Use inert class names or marker methods that prove type selection without executing commands.
3. Record the exact call chain: untrusted mapping field -> `check_instruct_content` or equivalent -> deserialization/type reconstruction sink.
4. Pair any positive result with a fixed-version or hardened parser that rejects unknown type keys or treats the content as plain data.

Do not publish payloads that execute shell commands or read local secrets. The durable operator lesson is the mapping-to-runtime boundary.

### Craft CMS preview config and icon helper boundaries

Craft's July 9 advisories expose two different admin-side boundaries: config arrays reaching Yii2 event registration, and path validation happening after file-existence checks.

1. In a disposable Craft lab, inspect preview/admin endpoints that accept nested `fieldLayoutConfig`, element index config, entry-type config, or similar arrays.
2. Submit a harmless `on init`-style marker only if the route is in scope and the lab user has the required admin role. Capture marker execution or a safe error that proves event-handler interpretation.
3. For icon/static helpers, test extension/path normalization with a lab `.svg` marker file. Evidence should show existence check before validation and a patched negative control.
4. Avoid environment-dump functions, web shells, or reads of real app files. Use a marker callback and a single synthetic SVG.

### CSS parser SSRF and local-file redirect boundary

The `css_parser` advisory is directly reusable for rich-text, email rendering, and document conversion assessments.

1. Confirm the application parses attacker-influenced CSS and passes a `base_uri` or follows `@import` URLs.
2. Host an owned `@import` URL that first returns a harmless CSS file, then a redirect to an explicitly approved canary destination.
3. In a lab-only proof, place a temp local file canary and redirect to `file://` only when the program owner has approved local-file validation.
4. Capture outbound request logs, redirect chain, and parsed CSS outcome. Do not target metadata endpoints, loopback admin services, or arbitrary local files.

If the product already has a rich-text import SSRF checklist, fold the evidence into that model: initial URL validation must be repeated after every redirect and scheme transition.

### Note export and soft-delete visibility boundaries

Note Mark's slug and `deleted=true` issues are a reminder to test data-lifecycle paths, not just live CRUD routes.

1. Create a disposable public book/note pair. Use a slug with traversal syntax plus at least one character that satisfies any suspected unanchored regex.
2. Run export/migration into a temp root and confirm whether files are created outside that root. Evidence should be a marker path under `/tmp`, not a sensitive system path.
3. For public list routes, soft-delete a synthetic note and compare unauthenticated responses with and without `deleted=true`.
4. Capture the role state, public/private flag, query parameter, and returned metadata fields. Do not enumerate unknown book IDs or disclose real note content.

### Embedded orchestrator component APIs

For Claw Orchestrator-style missing-auth component APIs, prefer route-state evidence over destructive calls.

1. Map listening ports and route prefixes in a lab deployment.
2. Compare the main dashboard/API auth requirement with embedded component endpoints.
3. Call only read-only or inert marker endpoints. If a component route is action-capable, prove reachability with an OPTIONS/404/405/route-metadata decision table where possible.
4. Report the exposed authority boundary: unauthenticated component API -> component state/action surface -> expected dashboard authentication.

## Reporting notes

Lead with the boundary that failed:

- **authorized REST route -> unaudited MCP wrapper -> cross-object data**;
- **agent message mapping -> deserialization/type reconstruction**;
- **CMS preview config -> framework event-handler registration**;
- **icon extension -> pre-validation existence check -> local SVG read**;
- **CSS `@import` -> recursive redirect -> local file or internal fetch**;
- **stored slug -> export path join -> outside-root write**;
- **public list flag -> soft-delete scope bypass**;
- **embedded component route -> missing dashboard authentication**.

Include version, required role, route/tool name, object ownership, the exact input class, synthetic canary evidence, and a patched or negative control. Avoid generic RCE/SSRF claims unless the approved lab proof reaches that specific sink without relying on sensitive data or production side effects.
