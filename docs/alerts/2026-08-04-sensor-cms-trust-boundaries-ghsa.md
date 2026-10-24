---
title: Sensor-proxy controller, CMS, and mobile profile-render boundaries
---

# Sensor-proxy controller, CMS, and mobile profile-render boundaries

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-08-04. The Camaleon, Microweber, and LINE records were unreviewed database entries at scan time; confirm the affected revision, route/configuration, caller capability, and corrected behavior from upstream before reporting.

This wave yields four durable operator patterns:

1. an operator-approved enrollment action does not necessarily authenticate the controller whose response reaches a privileged sensor;
2. a specialized autosave controller can override a protected parent controller while dropping object scope and authorization; and
3. input can survive several incomplete filters because each parser sees a different representation before a later HTML sink reparses it; and
4. remotely supplied mobile-profile templates can cross from display content into an application-privileged script runtime.

Primary sources:

- Tenable Sensor Proxy controller trust [GHSA-24h7-mgmp-x4j6 / CVE-2026-18667](https://github.com/advisories/GHSA-24h7-mgmp-x4j6) and [TNS-2026-21](https://www.tenable.com/security/tns-2026-21);
- Camaleon CMS draft authorization [GHSA-hwrq-jcj5-6vc6 / CVE-2026-67616](https://github.com/advisories/GHSA-hwrq-jcj5-6vc6), [upstream fix](https://github.com/owen2345/camaleon-cms/commit/88ab703b5ac041afb93a9993470aa366093c5311), and [authorization design notes](https://github.com/owen2345/camaleon-cms/pull/1196);
- Microweber content-tag rendering [GHSA-793c-7c93-m769 / CVE-2026-67617](https://github.com/advisories/GHSA-793c-7c93-m769) and [research write-up](https://github.com/theopaid/Stored-XSS-via-Content-Tag-Names-Microweber-); and
- LINE Android profile-template code injection [GHSA-86g4-8jpx-6pgq / CVE-2026-16881](https://github.com/advisories/GHSA-86g4-8jpx-6pgq) and the [LY Corporation advisory](https://line.github.io/security-advisory-blog/CVE-2026-16881).

!!! warning "Synthetic controllers, content, and render sinks only"
    Use a disconnected Sensor Proxy lab, an owned TLS/control endpoint, disposable CMS/mobile accounts and content, random markers, and patched process/DOM/script recorders. Never redirect an operational sensor, serve executable controller content, alter production drafts or profiles, execute JavaScript, collect sessions or CSRF tokens, or make a browser/mobile client perform authenticated side effects.

## Boundary map

| Surface | Trusted decision | Detached selector or later interpreter | Safe positive |
| --- | --- | --- | --- |
| Sensor enrollment | operator chooses to connect a sensor | remote host identity/content reaches an elevated execution path | owned endpoint plus inert response reaches a patched privileged sink |
| Camaleon draft create | caller may autosave under post type A | `post_id`, owner fields, and a global draft lookup select another object | draft B reaches a no-op update recorder after authorization only against A/session |
| Camaleon draft update | caller may edit one draft | global draft ID lookup ignores post type and object policy | foreign synthetic draft reaches update recorder |
| Microweber tag save | tag text passes method-specific and regex checks | title normalization preserves encoded structure that HTML parsing later revives | inert tag marker becomes an element/attribute in a detached DOM recorder |
| Microweber render | stored tag is treated as display text | public template output or admin `innerHTML` reparses it as markup | parser creates a harmless marker node without an executable attribute |
| LINE Android profile render | remote profile is accepted as display content | externally supplied template script reaches an application-privileged runtime | patched evaluator receives only an inert marker and aborts before execution |

## 1. Treat sensor enrollment as privileged remote-code provenance

Tenable states that Sensor Proxy 1.4.1 and earlier could execute code with elevated privileges after an operator was induced to connect the sensor to an attacker-controlled host. The public advisory does not identify the exact protocol message or artifact sink. Do not guess a wire payload from the impact statement. Instrument the lab first.

### Prerequisites

- Sensor Proxy 1.4.1 or an earlier affected build in an isolated disposable VM;
- Sensor Proxy 1.4.2 as the corrected control;
- an owned hostname, generated lab CA, and HTTP/TLS response recorder;
- patched download, archive, package, process, and service-management boundaries that record metadata and abort; and
- fake enrollment identifiers and credentials with no route to a Tenable production tenant.

### Validation workflow

1. Record the legitimate enrollment flow end to end: configured authority, DNS result, TLS peer identity, redirects, response types, artifact metadata, signature or digest checks, and final privileged sink.
2. Point only the disposable sensor at the owned endpoint through the normal operator-visible configuration path. Do not use phishing or deceptive UI in the proof.
3. Vary one binding at a time: hostname, certificate authority, redirect authority, response content type, artifact name, declared digest, and signer identity.
4. Return inert protocol-shaped responses that contain a random marker but no script, package, shell text, or executable bytes.
5. At every privileged boundary, record the source authority, authenticated peer, expected signer/digest, selected artifact, effective user, and whether the marker arrived. Abort before write, install, service restart, or process creation.
6. Repeat the same matrix against 1.4.2.

The strongest bounded positive is **operator selects owned lab host -> sensor accepts insufficiently authenticated controller response -> inert marker reaches a patched elevated install/process sink on 1.4.1 -> 1.4.2 rejects before that sink**. A connection to the owned endpoint alone is not code execution. Report the exact missing binding—TLS peer, redirect authority, artifact signature, digest, or command provenance—that the recorder proves.

## 2. Audit specialized controllers for dropped parent authorization

The Camaleon fix documents four separable failures in the draft autosave path: global draft lookup, missing `authorize!` checks, unvalidated `post_parent`, and ownership reassignment through `user_id`. The parent posts controller protected ordinary mutations, but the specialized drafts controller overrode create/update and did not preserve those decisions.

### Two-user, two-post-type fixture

Create:

- users `author-a` and `author-b` with only ordinary author permissions;
- post types A and B;
- one parent post and one draft owned by each user in each post type; and
- a persistence recorder that captures the selected draft, requested parent, stored post type/owner, changed field names, and authorization object, then rolls back.

Exercise create and update with these selector combinations:

| Session | Route post type | `post_id` or draft ID | Expected |
| --- | --- | --- | --- |
| A | A | A-owned object | allowed control |
| A | A | B-owned object in A | denied by object policy |
| A | A | object in post type B | denied by post-type scope |
| A | A | nonexistent parent | rejected without persistence |
| A | A | A object plus caller-supplied `user_id=B` | ownership remains A |

Capture both the affected and fixed build. A reportable positive is not merely a 2xx response: show **request route is scoped to A -> global lookup selects B's synthetic draft -> no object authorization is recorded -> B reaches the rollback recorder**. Test create and update separately because they take different lookup paths. Do not overwrite real content or publish draft bodies.

### General audit heuristic

When a framework controller inherits a protected CRUD path, search overrides and alternate route families for:

- direct model lookups replacing parent-scoped relations;
- skipped policy hooks in autosave, draft, preview, clone, import, bulk, or validation actions;
- caller-supplied owner/parent fields applied after authorization; and
- `save(validate: false)` or equivalent paths that make authorization the only remaining gate.

Diff the object selected for authorization from the object passed to persistence. That identity comparison is stronger evidence than route status alone.

## 3. Record every parser in stored rich-text and label-like fields

The Microweber record describes a chain in which a GET save route bypasses method-limited middleware, a regex recognizes only one quoted event-attribute shape, title-case normalization leaves numeric entities structurally intact, and two renderers later treat the stored tag as HTML. The durable lesson is representation drift, not a reusable execution payload.

### Inert parser pipeline

Use a disposable admin account and post. Replace the public-template output and admin `innerHTML` assignment with recorders that parse into a detached DOM where scripts, event attributes, URL loads, custom elements, and navigation are disabled.

Submit one random marker per case:

1. plain alphanumeric tag control;
2. harmless markup-shaped text such as a custom element with only `data-canary`;
3. the same text with quoted, unquoted, and mixed-case harmless attributes;
4. numeric-entity encoding of letters in the marker only;
5. GET, POST, PATCH, and PUT versions where the route accepts them; and
6. malformed tags that should remain text or be rejected.

At each stage record:

- raw method and decoded parameter value;
- value after middleware;
- value after field sanitizer;
- value after title normalization;
- exact stored bytes;
- server-rendered bytes; and
- detached-DOM node, attribute, and text output for both the public page and admin editor.

A safe positive is **method/representation avoids an earlier filter -> stored bytes retain markup structure -> public or admin sink creates a harmless marker element rather than text**. Do not include event handlers, script URLs, network callbacks, CSRF-token reads, or authenticated requests. If no executable sink is exercised, report trusted markup insertion rather than XSS; if the affected application behavior is confirmed from the upstream record and your inert differential, label the evidence boundary precisely.

## 4. Trace mobile profile templates to the final script authority

LY Corporation states that LINE for Android before 26.7.2 inadequately validated or sandboxed externally supplied script content embedded in profile templates. Viewing a crafted profile could therefore execute code with the application's privileges. The advisory does not disclose the template format, ingestion field, evaluator, or bridge surface, and a server-side mitigation now protects older clients too. Do not invent a payload or treat an old APK version as proof of current reachability.

Use two disposable LINE lab accounts on isolated Android test devices or emulators with no real contacts, messages, media, payment state, or production credentials. If the program permits client instrumentation, replace each template compiler, script evaluator, WebView navigation hook, and native bridge dispatcher with a recorder that logs the source profile, raw template bytes, decoded representation, selected runtime/origin, exposed bridge names, and effective application context, then aborts.

1. Establish controls with a plain profile, a supported static template, and malformed template data that should remain inert or be rejected.
2. Through only the product-supported profile-editing path available to the owned sender account, place a random non-executable marker in every documented template-capable field. Do not add JavaScript syntax, URLs, event handlers, native method names, or data-access expressions.
3. Have the owned viewer open the profile while recording server-delivered bytes, client decoding, renderer selection, evaluator entry, origin/sandbox state, and bridge exposure.
4. Vary representation separately: missing or empty template state, duplicated fields, encoding boundaries, nested template objects, cached versus freshly fetched profiles, and sender/viewer account transitions.
5. Compare an affected client in the authorized lab, 26.7.2 or later, and the same old client with current server-side mitigation. Preserve a result matrix even if the mitigated service prevents reproduction.

The safe positive is **owned sender stores an inert profile-template marker -> owned viewer renders it -> affected path selects a script-capable runtime -> patched evaluator records the marker under application privilege and aborts -> corrected client or server-filtered path rejects, strips, or renders it as data**. Merely displaying the marker is not code injection. A static review that identifies a reachable evaluator and privileged bridge is useful evidence, but label it separately from dynamic sink reachability.

Report the exact sender capability, profile field, server transformation, client version, renderer, runtime origin, sandbox flags, and exposed application bridge. Never execute script, read client storage, invoke native APIs, contact a callback, access another user's profile data, or attempt to bypass the deployed server mitigation outside an explicitly approved vendor lab.

## Reporting checklist

- [ ] Advisory review status, exact affected/fixed build, route, role, and feature configuration are recorded.
- [ ] Sensor evidence identifies the authenticated controller and exact privileged sink; it does not equate a callback with execution.
- [ ] Camaleon evidence records route parent, requested object, stored owner/post type, authorization object, and persistence object.
- [ ] Create, update, parent validation, and ownership assignment are tested as independent decisions.
- [ ] Microweber evidence preserves every intermediate representation and uses a non-executable detached DOM.
- [ ] LINE evidence distinguishes server acceptance, renderer selection, evaluator reachability, and native-bridge exposure; affected-version metadata alone is not a positive.
- [ ] No executable controller artifact, shell input, live CMS/mobile content, session, CSRF token, client storage, callback, or browser/mobile side effect appears in evidence.

## October 24 follow-up: Camaleon second wave — media permission alone → RCE via `crop_url` data-URI write with `../` in the *name* parameter (CVE-2026-116009 / [GHSA-wq77-q3hj-c75x](https://github.com/advisories/GHSA-wq77-q3hj-c75x), high 8.8, <2.9.3)

Same product as this page's Camaleon draft-authorization section, second independent boundary break — the vendor-sibling re-sweep rule paying off again. The `crop_url` media action accepts a **base64 `data:` URI** as its image source, decodes it server-side, and writes the result to a path built from an attacker-supplied `name` parameter **containing `../` sequences**, with no containment check — media-only users write an ERB template into a theme's `views/` directory, which executes when rendered. Media permission → arbitrary file write → template RCE, no editor/post capabilities needed.

Operator rules:

- **Every media action is an upload in disguise.** Enumerate all media-controller verbs (`crop_url`, resize, rotate, save, import) separately from the main upload endpoint; each one may re-implement source fetching (`data:` URIs, remote URLs) and destination naming (`name`, `slug`, `path`) independently. For each: test (a) non-file source schemes (`data:`, `http:`, `file:`) and (b) traversal in the *destination* parameter even when the source validates. This is the validation-target-vs-write-target mismatch by parameter pair (Sept 19 shortcode page) applied to media actions: what gets validated (the image) is never what gets controlled (the filename).
- **CMS template directories are the RCE pivot for any file-write primitive.** On Ruby/Rails-flavored CMSes (ERB views) and PHP CMSes (theme/partials), test whether the web root contains a renderer-consulted directory writable by your current role; one marker-template write + render request closes the chain. Validate only in lab installs with your own theme copy.
- Adjacent Oct 24 CMS waves tracked without publication: RosarioSIS missing-authorization pair, DaybydayCRM controller-level authz misses, ONEARMY IDOR, Xiaozhi-esp32 IDOR, Scada-LTS/InternAgent thin singles — flat-missing-authz class already on this page's audit heuristic.
