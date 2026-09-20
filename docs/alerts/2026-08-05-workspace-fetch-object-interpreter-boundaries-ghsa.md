---
title: Workspace, outbound-fetch, object-scope, and interpreter boundaries
---

# Workspace, outbound-fetch, object-scope, and interpreter boundaries

Twenty records expose one reusable operator pattern: a weak early gate authorizes a route, path, object, destination, or structured value, then a stronger filesystem, credential, tenant, network, SQL, template, or process sink acts on it. Test the complete transition and deny the final effect.

Discovery and primary-source seeds:

- Eclipse Theia tokenless HTTP filesystem read [GHSA-xrrm-6636-87r2](https://github.com/advisories/GHSA-xrrm-6636-87r2) / [CVE-2026-61891](https://nvd.nist.gov/vuln/detail/CVE-2026-61891), hosted-plugin traversal [GHSA-34gw-v4cc-pv7c](https://github.com/advisories/GHSA-34gw-v4cc-pv7c) / [CVE-2026-12609](https://nvd.nist.gov/vuln/detail/CVE-2026-12609), tokenless upload [GHSA-2mw2-h8hj-xpjg](https://github.com/advisories/GHSA-2mw2-h8hj-xpjg) / [CVE-2026-60009](https://nvd.nist.gov/vuln/detail/CVE-2026-60009), and workspace-preference prototype pollution [GHSA-5f8h-2xph-wwxv](https://github.com/advisories/GHSA-5f8h-2xph-wwxv) / [CVE-2026-14574](https://nvd.nist.gov/vuln/detail/CVE-2026-14574);
- Assemblyline service-client server-supplied digest traversal [GHSA-75jv-vfxf-3865](https://github.com/CybercentreCanada/assemblyline/security/advisories/GHSA-75jv-vfxf-3865) / [CVE-2025-55013](https://nvd.nist.gov/vuln/detail/CVE-2025-55013) and the [upstream validation patch](https://github.com/CybercentreCanada/assemblyline-service-client/commit/351414e7e96cc1f5640ae71ae51b939e8ba30900);
- `art-template` sub-template root escape [GHSA-mj55-6q5h-prw4](https://github.com/advisories/GHSA-mj55-6q5h-prw4) / [CVE-2026-71215](https://nvd.nist.gov/vuln/detail/CVE-2026-71215);
- Firefly III webhook loopback/rebinding [GHSA-q8pq-98hq-mg7f](https://github.com/advisories/GHSA-q8pq-98hq-mg7f) / [CVE-2026-71250](https://nvd.nist.gov/vuln/detail/CVE-2026-71250), Pixelfed ActivityPub fetch [GHSA-5cfc-gvxj-5r55](https://github.com/advisories/GHSA-5cfc-gvxj-5r55) / [CVE-2026-71246](https://nvd.nist.gov/vuln/detail/CVE-2026-71246), MLflow AI Gateway destination authority [GHSA-h7x2-h6g9-p789](https://github.com/advisories/GHSA-h7x2-h6g9-p789) / [CVE-2026-71211](https://nvd.nist.gov/vuln/detail/CVE-2026-71211), and Mealie DNS-rebinding [GHSA-q2c2-jwjg-8cxx](https://github.com/advisories/GHSA-q2c2-jwjg-8cxx) / [CVE-2026-71210](https://nvd.nist.gov/vuln/detail/CVE-2026-71210);
- Paperless-ngx stored IMAP credential relay [GHSA-666w-8983-6664](https://github.com/advisories/GHSA-666w-8983-6664) / [CVE-2026-71244](https://nvd.nist.gov/vuln/detail/CVE-2026-71244);
- Akaunting upload ownership [GHSA-h26w-wq3x-9p76](https://github.com/advisories/GHSA-h26w-wq3x-9p76) / [CVE-2026-71251](https://nvd.nist.gov/vuln/detail/CVE-2026-71251), Crater note scope [GHSA-2467-45mc-2xp5](https://github.com/advisories/GHSA-2467-45mc-2xp5) / [CVE-2026-71242](https://nvd.nist.gov/vuln/detail/CVE-2026-71242), Documize attachment proof [GHSA-4gcg-395p-mg6g](https://github.com/advisories/GHSA-4gcg-395p-mg6g) / [CVE-2026-71234](https://nvd.nist.gov/vuln/detail/CVE-2026-71234), and Documenso assistant/signature ownership [GHSA-v65x-57rf-cpg3](https://github.com/advisories/GHSA-v65x-57rf-cpg3) / [CVE-2026-71247](https://nvd.nist.gov/vuln/detail/CVE-2026-71247);
- Magistrala rule-script authority [GHSA-vq5v-m87m-6pqm](https://github.com/advisories/GHSA-vq5v-m87m-6pqm) / [CVE-2026-71235](https://nvd.nist.gov/vuln/detail/CVE-2026-71235), `backmeup` shell construction [GHSA-c6xg-rfqh-85cp](https://github.com/advisories/GHSA-c6xg-rfqh-85cp) / [CVE-2026-71243](https://nvd.nist.gov/vuln/detail/CVE-2026-71243), and `xidown` option injection [GHSA-f3j9-9qqv-p4r8](https://github.com/advisories/GHSA-f3j9-9qqv-p4r8) / [CVE-2026-71212](https://nvd.nist.gov/vuln/detail/CVE-2026-71212);
- Mautic field-name-to-SQL construction [GHSA-rq57-g9hr-4f9r](https://github.com/advisories/GHSA-rq57-g9hr-4f9r) / [CVE-2026-71245](https://nvd.nist.gov/vuln/detail/CVE-2026-71245); and
- Grocy post-sanitization entity reversal [GHSA-c924-wcfj-cr8j](https://github.com/advisories/GHSA-c924-wcfj-cr8j) / [CVE-2026-71236](https://nvd.nist.gov/vuln/detail/CVE-2026-71236).

Most records were unreviewed GitHub/NVD mirrors when this page was written. Treat them as validation seeds, confirm behavior against the linked upstream project and exact revision, and do not infer affected or fixed versions that a primary source does not state.

!!! warning "Synthetic fixtures and denied final sinks only"
    Use disposable workspaces, random marker files, owned DNS/HTTP/IMAP listeners, fake credentials, two-tenant objects, patched interpreters, and argv/SQL/DOM recorders. Never read host files, overwrite startup files, query cloud metadata or internal services, collect credentials, retrieve foreign records, forge signatures, run scripts or commands, or execute injected SQL/HTML.

## 1. Map developer-workspace HTTP authority before testing paths

The Theia records are strongest as one route-to-filesystem matrix. Browser deployments can protect WebSocket upgrades with a connection token while ordinary HTTP handlers continue after reissuing a cookie. Test authentication and path confinement independently; a valid workspace session does not authorize every backend-readable file, and a confined path does not repair a tokenless route.

Create a disposable backend root with:

- workspace `/tmp/theia-lab/workspace`;
- plugin root `/tmp/theia-lab/plugins/publisher.name`;
- sibling files containing only random `READ-<uuid>` markers; and
- a writable sibling target reserved for a denied upload recorder.

Instrument raw request target, route family, cookie/token input, middleware result, decoded route parameter, URI-to-path conversion, final canonical path, and patched read/move sink. Exercise:

| Route family | Input matrix | Secure invariant |
| --- | --- | --- |
| `GET /file`, `GET /files/`, `PUT /files/` | no cookie, invalid cookie, valid token; workspace and sibling URI | reject before resolution without a valid HTTP credential; canonical path remains in the authorized root |
| `/hostedPlugin/:pluginId/:path` | ordinary asset, encoded and double-encoded dot segments, mixed separators | authorize the final decoded canonical path beneath the selected plugin root |
| `POST /file-upload` | no credential and valid credential; relative and absolute multipart `uri` | authenticate before staging and deny every target outside an explicit upload root |

For upload testing, parse a locally generated multipart request and replace `fs.move` with a recorder that rejects the operation. Include a cross-origin `multipart/form-data` fixture to determine whether a browser can reach the handler without preflight, but do not host a public exploit page. A bounded positive is **tokenless HTTP request reaches handler -> decoded/canonical target escapes the authorized root -> denied sink records the synthetic marker path**. Never retrieve the marker body or write the target.

The `art-template` record extends the path fixture to loaders. Record configured template root, supplied include/extend name, `path.resolve` result, final real path, and denied `readFileSync`. Test relative in-root names, `..`, absolute names, symlinked parents, and platform separators. The decisive evidence is the out-of-root canary path reaching the loader, not rendered file content.

### Treat remote artifact identifiers as paths until proven otherwise

Assemblyline adds a client/server variant: the service server returns a value represented as a SHA-256 digest, but the client joins that value directly beneath its tasking directory before writing a downloaded artifact. The finding requires a malicious or compromised service server, or an actor able to impersonate that server; normal deployments are expected to run the client in a constrained service container. Establish that trust precondition instead of presenting the client as an unauthenticated public file-write surface.

Build a disposable client fixture with a tasking root, one in-root marker target, and one sibling target that contains only a random name. Replace the final file open/write operation with a recorder that always denies the syscall. Have an owned mock server return:

- a lowercase 64-hex digest and a matching inert body as the positive control;
- short, long, uppercase, and non-hex identifiers;
- relative dot segments, absolute paths, mixed separators, and encoded separators; and
- a syntactically valid digest whose body hash does not match, to keep identifier validation separate from content verification.

Record the authenticated server identity, raw response field, decoded identifier, digest-schema result, joined path, canonical parent, write mode, and denied destination. A bounded positive is **trusted server response -> non-digest identifier is interpreted as path syntax -> canonical destination leaves the tasking root -> denied writer records only the synthetic sibling path**. Do not create the sibling file, target startup or service-manager paths, or infer host execution from destination control.

Replay the same matrix against the fixed revision. The upstream patch rejects identifiers that do not match the project's SHA-256 schema before path construction. Also verify full-string matching rather than prefix acceptance, and retain containment at the write sink as defense in depth. Apply this workflow to artifact caches, malware-analysis workers, CI agents, object downloaders, and any protocol where a remote peer supplies a value named `digest`, `hash`, `key`, or `object_id` that later becomes a filename.

### Repository-controlled preferences

Use a separate Theia process for workspace-preference testing. Put inert nested keys, `__proto__`, `constructor`, and `prototype` shapes into synthetic `.theia/settings.json` and `.vscode/settings.json` files. Patch `PreferenceUtils.merge` or run it in an isolated subprocess, then inspect only canary properties on fresh empty objects before and after preference resolution.

A positive is **opening the disposable workspace -> preference merge handles a prototype-related key -> a fresh object inherits the inert canary**. Stop there. Do not seek a code-execution gadget, open an unknown repository in a privileged IDE, or claim process compromise from pollution alone.

## 2. Bind URL validation to the final socket peer

Use one disconnected network harness for Firefly III, Pixelfed, MLflow, and Mealie. Provide owned listeners representing a public validation peer and a synthetic denied peer. The second peer must serve only `INTERNAL-CANARY-<uuid>` and must not be a real internal service or metadata endpoint.

Capture this chain for every request:

1. caller and required feature/role;
2. raw and normalized URL;
3. validation-time DNS answers and address classification;
4. redirect hops;
5. connection-time DNS answers and selected socket peer;
6. forwarded headers or stored credentials; and
7. patched response-return or logging sink.

| Surface | Boundary to vary | Required proof |
| --- | --- | --- |
| Firefly III webhook | explicit loopback branch; validation lookup versus send-time lookup | accepted URL and final owned peer differ; harmless webhook canary reaches the recorder |
| Pixelfed remote search | literal-host block versus resolved private/mapped address; ActivityPub content type | policy accepts a representation whose final owned peer is denied |
| MLflow gateway secret/proxy | low-role secret creation, stored `api_base`, caller-selected suffix | basic-auth user selects a destination outside their network authority and response recorder sees only the canary hash |
| Mealie recipe scrape/image | validation resolution versus transport re-resolution | public first answer passes, denied second peer is selected, and content-return sink records only canary presence |

Test loopback, private, link-local, IPv4-mapped IPv6, alternate numeric forms, redirects, and rebinding only against owned fixtures. Preserve the final peer IP rather than reporting a hostname string as SSRF. For MLflow, patch the outbound request and response serializer; never request metadata credentials even in a cloud lab.

### Mealie follow-up: the recipe-action trigger is a third outbound-fetch leg (Sept 20)

Mealie reappeared (CVE-2026-94028, [GHSA-2g3w-vrh2-xg2p](https://github.com/advisories/GHSA-2g3w-vrh2-xg2p), fixed 3.26.0): the household **recipe action trigger** (`controller_group_recipe_actions.py`) passes a stored/request-supplied `url` into an outbound fetch, adding a third outbound-fetch leg beyond the earlier recipe-scrape/image and DNS-rebinding items. Operator rule this reinforces: on any product with a documented SSRF fix, enumerate **every** feature that performs an outbound fetch (webhooks, action triggers, importers, preview/scrape, feed readers) and test each against the same validation-to-connect matrix — one patched loader says nothing about its siblings. Prove with owned listeners and canary presence only, same harness as the table above.

## 3. Separate destination editing from stored-credential use

Paperless-ngx provides a reusable confused-deputy test for every “test connection” or “verify credentials” endpoint. Seed a mail account with fake credentials such as `IMAP-PASS-<uuid>`, then expose the test action to a low-role user with only the documented object-level change permission.

Vary account ID, masked-password sentinel, account type, host, port, and transport mode. The owned IMAP recorder should accept a connection but retain only the credential field name and a one-way hash of the fake value. Capture which fields came from storage and which came from the request.

A bounded positive is **stored password/token retained because the request uses a masked sentinel -> caller replaces the server destination -> connector would authenticate to the owned listener with the stored fake credential -> patched sender records the hash**. Do not collect a real password or OAuth token. Generalize this matrix to SMTP tests, cloud-storage validators, datasource tests, webhook previews, and AI-provider health checks.

## 4. Bind route proof, role, and action to the exact object

Create two synthetic tenants and random marker objects. Patch downloads, updates, deletes, and signature writes to append-only decision recorders.

| Surface | Weak early proof | Exact binding to verify |
| --- | --- | --- |
| Akaunting `uploads/{id}/download` | authenticated portal customer | media parent contact and company equal the caller's contact and company |
| Crater note detail/update/delete | blanket `view/manage notes` ability | target Note model is passed to policy and belongs to caller's company |
| Documize public attachment download | non-empty `secure` parameter | supplied proof is constant-time compared with the token bound to that attachment and organization |
| Documenso V1 sign-with-token | valid recipient token plus assistant role/order | actor owns the field and is permitted to perform the exact field type/action |

Record caller tenant/recipient, route proof, object ID, parent owner, field type, sibling-order rule, policy result, and denied sink. Exercise list/detail, API version, public/authenticated, and read/write siblings because authorization often drifts between route families.

The positive is **valid but insufficient generic proof -> foreign or stronger-action object resolves -> object/action predicate is absent -> denied sink records only the random target ID**. For Documenso, never save a signature: use inert text fields as positive controls and a no-op signature-field recorder for the negative boundary. Do not retrieve attachments or note bodies.

## 5. Patch interpreters and process wrappers before supplying canaries

Magistrala illustrates the difference between an intentional scripting feature and authorization to expose host capabilities. In an isolated rules-engine process, replace Go/Lua file, database, environment, HTTP, and process functions with recorders. Test low-role rule creation and message-trigger execution with inert calls that identify only the requested capability.

Record rule owner, role, script language, accepted imports/libraries, validation decision, trigger tenant, and patched capability sink. A reportable boundary is **low-role rule accepted -> server-side interpreter exposes a host/network/database capability outside the rule tenant's contract -> recorder receives the inert operation**. The existence of scripting is not itself a vulnerability; establish the documented trust model and expected sandbox.

For command wrappers, capture argv and shell grammar without launching a child:

- `backmeup`: vary `name`, `source`, `destination`, and `filter` with ordinary values plus inert metacharacter markers; distinguish local execution from an SSH-selected remote host. A positive requires a shell string whose parse tree contains an extra command node.
- `xidown`: vary the URL position with ordinary URLs, a leading dash, `--`, and inert option-shaped values. Record the final `yt-dlp` argv and parse it with the same option grammar. A positive requires the URL slot to become an option; do not claim command execution unless a separate safe sink proves it.
- `yt-dlp-web-ui` (Sept 18 follow-up, [GHSA-vppc-qfgr-6vg2](https://github.com/advisories/GHSA-vppc-qfgr-6vg2) / [CVE-2026-93371](https://nvd.nist.gov/vuln/detail/CVE-2026-93371), remote, public exploit disclosed): up to v4 the download API passed user-supplied `params` straight into the `yt-dlp` argv (`NewGenericDownload` in `server/internal/downloaders/generic.go`) with only weak sanitization — command injection. The fix commit [c7ad3bd](https://github.com/marcopiovanello/yt-dlp-web-ui/commit/c7ad3bd79c7c520a7d17e7f2ba19d962be8e7897) replaced the sanitizer with an explicit **flag allowlist** (format/selection/filesize-class flags only) plus a download-path subpath check. Audit rule for every web front-end around a CLI tool: treat each user-reachable "extra arguments/options" field as argv injection until an allowlist (not a denylist/blacklist regex) is proven; capture the final argv and diff the parse tree against an inert option-shaped canary set, including output-path and config-file flags (`-o`, `--config-locations`, `-P`) that reach filesystem sinks.

- `WP Photo Album Plus` (Sept 19 follow-up, [GHSA-mx4x-6r5x-jrh9](https://github.com/advisories/GHSA-mx4x-6r5x-jrh9) / [CVE-2026-87909](https://nvd.nist.gov/vuln/detail/CVE-2026-87909), subscriber → RCE): `wppa_image_magick()` concatenates the **multipart upload filename** into an ImageMagick command run via `exec()`, with `escapeshellcmd()` applied to the *whole command* rather than quoting individual arguments. `escapeshellcmd()` escapes metacharacters but **leaves spaces as argument separators**, so a crafted filename injects ImageMagick options/arguments; the plugin's filename sanitization is applied at the database layer only and never to the physical temp path handed to ImageMagick. Audit rule: on any PHP wrapper, check *which unit* the escaper is applied to — whole-command `escapeshellcmd()` without per-argument `escapeshellarg()` is argument injection by construction; also verify the sanitizer covers the *physical path* leg, not just the stored/metadata leg. Prove with an inert option-shaped filename that changes the recorded argv parse tree; never run the resulting command.

Prefer direct process execution with a fixed executable, explicit argument array, end-of-options marker where supported, and a schema for every structured field. Path normalization does not quote shell syntax.

## 6. Record SQL grammar and render stages, not payload effects

Mautic's field selector is a reusable identifier-injection fixture. Seed a disposable database with one synthetic lead and patch query execution. Vary known field names, unknown identifiers, spaces, parentheses, comments, and delimiter canaries. Capture the request field, sanitizer output, constructed Doctrine/SQL identifier, parsed query shape, permission result, and denied executor.

A positive is **ordinary authenticated route -> unlisted field crosses into identifier grammar -> parser shows structure beyond one allowed column -> executor remains denied**. Bound parameters do not solve identifier selection; map the field to a fixed server-side column allowlist. Never extract rows or use delay/error amplification against a shared database.

Grocy demonstrates a sanitize-then-transform differential. Feed inert text through request parsing, HTMLPurifier, entity replacement, storage serialization, and a detached DOM parser with scripting disabled. Include raw tags, once-encoded text, double-encoded text, and benign ampersands. A positive is **purifier neutralizes the marker -> later replacement reconstructs an active element in the detached parser -> render sink remains disabled**. Do not execute JavaScript or collect a session. Report the exact stored and rendered forms; an API accepting angle brackets is not enough.

## Reporting boundaries

- Preserve raw, decoded, normalized, canonical, and final path forms; route reachability is not file read/write.
- For SSRF, prove the final owned socket peer and response/log sink; never use metadata or production internal services.
- Credential-relay evidence must use fake credentials and hashes, with request-supplied and stored fields recorded separately.
- Cross-tenant findings require a random foreign marker reaching a denied sink, not merely an enumerable ID.
- Prototype pollution is not code execution without an independently proven gadget and impact path.
- Process, SQL, template, and DOM findings stop at argv, parser, loader, or detached-render evidence; do not execute the effect.
