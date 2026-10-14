# Report-renderer fetch and desktop-updater trust-boundary checks

Source: hourly offensive-security scan of the GitHub Security Advisory feed on 2026-08-03. These records were unreviewed when this page was written; confirm the exact product version, reachable content field, render path, updater behavior, and fixed behavior before reporting.

This wave and August 9–11 CTI-Transmute follow-ups yield seven durable operator patterns:

- rich-text content can become a server-side URL or file selector when a report renderer resolves embedded resources;
- TLS does not authenticate a software update when the client accepts every certificate and then executes an unsigned, unhashed installer;
- server-side HTML escaping is not authoritative when a client framework recompiles the parsed DOM as template source;
- a graph or JSON viewer can reparse trusted text as HTML through several library and popup sinks after the main template path was fixed;
- an outbound-fetch guard can reject IP literals yet accept a hostname whose resolved destination is private;
- table highlighting, tag icons, remote MISP fields, visualization tooltips, and saved graph styles can each be a separate HTML interpreter; and
- report exports and reaction endpoints can omit the object-level policy enforced by the corresponding interactive read path.

Sources:

- [GHSA-7gc9-2qrw-frvj / CVE-2026-69078: CTI-Transmute evaluation-report SSRF and local-file fetch](https://github.com/advisories/GHSA-7gc9-2qrw-frvj)
- [CTI-Transmute restrictive WeasyPrint fetcher fix](https://github.com/MISP/cti-transmute/commit/20f35307bcb706c8dd8ca3884a88fb36b05b5244)
- [GHSA-6x7q-w685-49vg / CVE-2026-71502: CTI-Transmute stored Vue template injection](https://github.com/advisories/GHSA-6x7q-w685-49vg)
- [CTI-Transmute global delimiter-neutralization fix](https://github.com/MISP/cti-transmute/commit/ecfdaef63860a071c6f07afd30156ca77a77ad2b)
- [CTI-Transmute mounted-region `v-pre` fixes](https://github.com/MISP/cti-transmute/commit/522fa8ff8223b12a6128ea3fc2344a77b7b9108d)
- [GHSA-p8v9-h3m5-mvj9: CTI-Transmute conversion-graph and raw-JSON stored XSS](https://github.com/advisories/GHSA-p8v9-h3m5-mvj9)
- [GHSA-x373-32xc-7gqv / CVE-2026-73160: anonymous MISP fetch/search SSRF through unresolved hostnames](https://github.com/advisories/GHSA-x373-32xc-7gqv)
- [GHSA-9p42-c923-p9c9 / CVE-2026-73161: conversion-table highlighting HTML interpretation](https://github.com/advisories/GHSA-9p42-c923-p9c9)
- [GHSA-3vx2-8r8r-pf7r / CVE-2026-73159: tag-icon `v-html` interpretation](https://github.com/advisories/GHSA-3vx2-8r8r-pf7r)
- [GHSA-j8cv-pjx7-pvqf / CVE-2026-73158: saved graph `svgIcon` interpretation](https://github.com/advisories/GHSA-j8cv-pjx7-pvqf)
- [GHSA-fh4x-m2h5-c6vx / CVE-2026-73157: remote MISP values reaching HTML sinks](https://github.com/advisories/GHSA-fh4x-m2h5-c6vx)
- [GHSA-fq55-48v3-mc95 / CVE-2026-73156: ECharts tooltip HTML interpretation](https://github.com/advisories/GHSA-fq55-48v3-mc95)
- [GHSA-vrrh-vgmq-m54x / CVE-2026-73140: private comments included in report exports](https://github.com/advisories/GHSA-vrrh-vgmq-m54x)
- [GHSA-rv36-q8cj-wgr9 / CVE-2026-73155: reaction mutation without comment visibility](https://github.com/advisories/GHSA-rv36-q8cj-wgr9)
- [GHSA-75j5-9v4m-c666 / CVE-2026-73162: state-changing account GET routes without CSRF binding](https://github.com/advisories/GHSA-75j5-9v4m-c666)
- [GHSA-gw22-gf8m-29g5 / CVE-2026-0392: eParakstītājs 3.0 unauthenticated update chain](https://github.com/advisories/GHSA-gw22-gf8m-29g5)
- [CERT.LV vulnerability record](https://cvd.cert.lv/inbox/view/vuln-all-1689187061)

!!! warning "Authorized validation only"
    Use a disposable CTI-Transmute instance, synthetic report content, a detached or script-disabled DOM harness, an owned callback service, a fake local canary service, an isolated Windows VM, a locally controlled update endpoint, and harmless compiler/process recorders. Never execute JavaScript in a privileged origin, target metadata or internal production services, read host files, intercept real update traffic, redirect vendor domains outside an isolated lab, or execute an untrusted installer.

## Preconditions and trust map

| Workflow | Attacker-controlled input | Privileged interpreter | Required precondition | Bounded positive |
| --- | --- | --- | --- | --- |
| CTI-Transmute report | conversion name, description, or comment rendered from Markdown | HTML conversion followed by WeasyPrint resource fetching | attacker content reaches evaluation-report PDF generation | owned HTTP canary or synthetic local-service marker reaches a no-content fetch recorder |
| CTI-Transmute web UI | conversion/profile/flash text containing configured Vue delimiters | browser parse followed by Vue runtime compilation of a mounted region | low-privilege or public stored text is rendered inside a Vue mount root | patched compiler records a harmless marker expression while an equivalent `v-pre` or unmounted control stays inert |
| CTI-Transmute graph and raw JSON | labels, types, property keys/values, hashes, child attributes, edge metadata, and serialized raw objects | Pivotick HTML resolution, property panels, hover/select rendering, or popup document construction | attacker-controlled CTI data is converted and viewed | patched HTML/DOM sink receives an inert marker while a text-only control stays literal |
| eParakstītājs updater | update descriptor and installer response | permissive TLS client followed by updater execution | approved lab can redirect or interpose the updater's vendor authority | fake certificate is accepted, descriptor chooses an owned URL, and inert installer reaches a process-start recorder |

Keep each transition separate. A Markdown preview, a URL-shaped string in a PDF, an update request, or acceptance of a test certificate does not by itself prove the final privileged sink.

## Report rendering: trace content through every resource resolver

The CTI-Transmute advisory describes conversion names, descriptions, and comments passing through Markdown-to-HTML conversion and then WeasyPrint. The renderer's default URL fetcher accepted `http:`, `https:`, and `file:` references. The important review question is therefore: **which resource references survive the first content parser and what authority does the final renderer use to resolve them?**

### Disposable fetch matrix

1. Deploy an affected CTI-Transmute revision in a network-isolated lab. Create a low-privilege author, a report-generating user, and one synthetic conversion/evaluation object.
2. Start two owned recorders:
   - an external callback endpoint with a random per-test token; and
   - a fake local HTTP service bound only inside the lab, returning a non-sensitive random marker.
3. Instrument or wrap WeasyPrint's URL fetcher if possible. Record the final scheme, canonical host, port, path, redirect count, calling report ID, and whether response bytes are embedded. Redact ambient headers.
4. Place unique inert references in each candidate field and context: Markdown image, HTML image if preserved, stylesheet/font reference, and link-only control. Start with the owned external endpoint.
5. Trigger PDF generation through the normal application workflow. Positive evidence requires a callback produced by rendering, not by browser preview, validation, or link checking.
6. Repeat with the fake local service only after proving the external callback. Stop when the request reaches the recorder; do not target metadata endpoints, loopback admin panels, cloud APIs, or unrelated internal hosts.
7. For the `file:` branch, patch the file opener or use a synthetic file inside a disposable fixture. Record the attempted canonical path and return only a sentinel. Do not read `/etc/passwd`, application configuration, keys, tokens, databases, or user files.
8. Exercise redirects from the owned external endpoint to the fake local service. Preserve both the initially accepted URL and final authority; this distinguishes initial-only validation from per-hop enforcement.
9. Repeat against the fixed revision. The cited patch supplies a restrictive fetcher that permits self-contained `data:` resources and removes intentional external font fetching. Require network and filesystem references to fail before dispatch while a benign embedded `data:` image still renders.

A bounded positive is **low-privilege rich-text field -> Markdown/HTML resource reference -> report generation -> WeasyPrint dispatch to an owned or synthetic local canary**. Report local-file behavior through the opener recorder, not by returning file content.

### Generalize the renderer check

Apply the same matrix to:

- invoice, ticket, dashboard, wiki, and compliance PDF exports;
- headless-browser screenshot or print-to-PDF jobs;
- server-side SVG, CSS, font, and image processing;
- email-template previews and document conversion queues; and
- imports that rewrite Markdown or HTML before a second renderer sees it.

For each pipeline, preserve the representations before and after Markdown parsing, HTML sanitization, URL normalization, redirect handling, and final fetch. A sanitizer that blocks scripts may still preserve resource-loading primitives.

## Vue mount boundaries: test the browser's second interpretation

The August 9 CTI-Transmute record describes stored conversion names/descriptions and profile names crossing two interpreters. Jinja escaped the value as HTML, but the browser reconstructed text inside a region that Vue later used as template source. CTI-Transmute configures `[[ ... ]]` delimiters, and its runtime compiler requires the CSP's `unsafe-eval` exception. The reusable question is not merely whether server output is escaped; it is **whether any later framework compiles the resulting DOM, including user-controlled text, as trusted template markup**.

### Mounted-region decision matrix

1. Use an affected CTI-Transmute revision in a disposable instance with one low-privilege author and one viewer. Store only a random inert marker in a synthetic conversion name, description, flash-message source, or profile field.
2. Replace or instrument Vue's compile/evaluation boundary so it records expression text and returns inert text. Do not invoke the JavaScript `Function` constructor or run an action-bearing expression.
3. Preserve four representations separately: stored value, Jinja output, browser-parsed DOM text, and the exact subtree supplied to Vue's mount/compiler path.
4. Place a marker shaped for the configured delimiters in each candidate field. Compare:
   - inside and outside the mounted element;
   - ordinary descendants and `v-pre` descendants;
   - server-rendered text and a non-executable JSON data island;
   - default and application-configured delimiters; and
   - overlapping delimiter runs and delimiters assembled across adjacent rendered values.
5. A bounded positive is **low-privilege stored text -> HTML-escaped response -> browser reconstructs configured delimiters inside the mount root -> patched Vue compiler receives the marker**. A reflected bracket sequence or CSP containing `unsafe-eval` is not enough.
6. Repeat against the fixed revision. The cited fixes add `v-pre` to known static regions and a Jinja `finalize` hook that inserts an invisible word joiner at every configured delimiter seam. Require the parsed DOM to contain no live delimiter while ordinary bracket text still displays correctly.
7. Add regression controls for values already marked as HTML/JSON, macros, adjacent values whose boundaries could reassemble a delimiter, and new templates added after the fix. The global hook must not corrupt JSON data islands, while the mounted-region inventory should fail when a future unprotected server expression enters a Vue root.

Apply this workflow to Alpine, AngularJS, Vue runtime compilation, client-side Handlebars, and any hydration/bootstrap layer that reads `innerHTML` or DOM text as template input. Report **server-rendered value -> browser normalization -> client compiler authority**, not generic stored XSS, until the final compiler/evaluator sink is demonstrated with the inert recorder.

## Graph and raw-object viewers: enumerate every HTML resolver

The August 10 CTI-Transmute record adds a different browser path. Converted CTI fields can reach Pivotick's HTML-oriented rendering for node labels, sublabels, edge labels, node types, property names and values, hash names, child attributes, and hover/selection panels. The raw-object action also constructed a new document around serialized JSON. Fixing only the obvious label or main template therefore leaves alternate interaction and popup sinks alive.

Use synthetic CTI objects in a detached browser profile with outbound networking and navigation denied. Patch `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, template-element parsing, Pivotick's HTML resolver, event-handler assignment, and popup/document creation so they record and reject candidate markup. Do not execute JavaScript.

1. Give every source field and context a unique inert marker. Preserve the imported object, converted object, graph model, renderer argument, and final DOM operation separately.
2. Exercise initial graph load, node and edge creation, hover, selection, expand/collapse, property panels, search/filter results, export/preview, and raw-JSON viewing. A sink reachable only after interaction is still part of the normal render surface.
3. Compare plain text, HTML-shaped text without an event, quotes, angle brackets, entity spellings, identifier punctuation, nested objects, arrays, nulls, and long-but-bounded values. Do not use credential forms, realistic login overlays, keylogging, browser APIs, or network-bearing elements.
4. Verify context-appropriate behavior: labels and properties should become text nodes; node-type fields should enforce identifier grammar where required; serialized JSON should be assigned with `textContent` inside a DOM-built `pre`, not interpolated into a new HTML document.
5. Replay against each intermediate and final fix. A first patch can cover labels while leaving property panels or hover paths exposed, so preserve the exact sink inventory by revision.

A bounded positive is **synthetic CTI field -> conversion preserves the marker -> a normal graph interaction passes it to an HTML-parsing recorder rather than a text-only sink**. If the recorder only sees markup-shaped input, report an HTML interpretation boundary; do not claim script execution unless a separately approved inert event marker reaches an executable handler decision. Generalize this sink inventory to topology graphs, report viewers, diff tools, log explorers, and object inspectors that wrap a third-party visualization library.

## August 11 follow-up: resolve fetch peers, enumerate renderers, and replay object policy

The late CTI-Transmute wave adds three adjacent workflows. Treat the GitHub records as leads until the affected revision, route exposure, role, and final sink are confirmed.

### Final-peer MISP fetch matrix

The affected `/fetch_misp_event` and `/misp_search_events` validator reportedly classified IP literals but accepted ordinary hostnames without first resolving them. Build the proof with an owned DNS name, a no-content synthetic private service, and a patched HTTP connector. Do not query metadata, loopback applications, or production internal services.

| Case | DNS/route state | Required result |
| --- | --- | --- |
| public baseline | owned name resolves only to an owned public recorder | request is attributable to the tested route |
| private literal | literal synthetic private address | rejected before connect |
| private resolution | owned name resolves only to the synthetic private recorder | affected build reaches denied connect; corrected build rejects every address |
| mixed answer set | one public and one synthetic private answer | reject the whole destination set rather than select the convenient answer |
| redirect | public recorder redirects to the private canary | re-resolve and re-check at the redirect hop |
| authorization | anonymous, ordinary user, and authorized integration user | record route policy independently from destination policy |

Capture the raw URL, normalized host, all `getaddrinfo()` answers, selected address, redirect chain, final socket peer, route identity, and whether response bytes would be relayed. A strong bounded positive is **anonymous or lower-trust route call -> accepted hostname -> resolution selects the synthetic private peer -> patched connector denies dispatch -> corrected build rejects before connect**. DNS resolution evidence alone is not SSRF, and an authentication fix does not replace final-peer enforcement.

### Alternate renderer inventory

Use one synthetic CTI/MISP corpus and assign a unique inert markup marker to every candidate field. Patch HTML-oriented sinks and deny events, navigation, and networking. Exercise both empty and non-empty search queries, initial rendering, hover, selection, administrative triage, saved-style application, and remote-event browsing.

| Surface | Controlled field | Boundary to record |
| --- | --- | --- |
| conversion table | highlighted value with empty and non-empty query | source text is escaped before application-owned `<mark>` insertion |
| tag renderer | icon name | structured class binding receives a constrained slug; no `v-html` string is built |
| MISP event browser | IDs, info, organization, tags, colors, TLP/distribution labels, and flash text | text reaches `textContent`; color is limited to the expected grammar |
| Sunburst/Treemap | STIX/MISP-derived slice name or value | ECharts tooltip formatter escapes every HTML-bearing argument |
| saved graph config | style keys including unknown keys and `svgIcon`/`iconClass` controls | server and client schemas reject HTML-capable properties before Pivotick |

Preserve source object, conversion result, formatter argument, interaction, and final DOM operation. The positive is **synthetic field -> normal view/interaction -> patched sink observes HTML parsing where a text-only or structured-attribute sink was expected**. Do not execute script; do not generalize one fixed renderer to every alternate table, tooltip, popup, or saved configuration path.

### Export and mutation authorization matrix

Create two users, one visible conversion, one public synthetic comment, and one private synthetic comment. Use random comment IDs and marker-only author names. Replace report serialization and reaction writes with record-and-deny sinks.

1. Compare interactive comment listing with Markdown export, PDF export, and any queued/report-preview path for the same principal and object.
2. Record conversion visibility, comment privacy, owner, author, administrator state, selected report ID, and the exact comment IDs handed to the serializer.
3. For reactions, compare readable public comment, unreadable private comment, nonexistent/deleted comment, another conversion's comment, and corrected behavior.
4. Require every alternate operation to call the same policy with the active principal and parent conversion before serialization or mutation.

A bounded export positive is **user may view the conversion but not the private comment -> affected report builder selects the private marker -> denied serializer records it -> corrected path omits it**. A bounded reaction positive is **authenticated user cannot view the comment -> direct ID reaches the denied reaction mutation -> corrected path returns the authorization denial before mutation**. Never retrieve private comments or retain another user's author data; the synthetic marker and denied sink are sufficient.

### State-changing GET and CSRF follow-up

Map `/account/follow`, `/account/delete_notification`, `/account/mark_notification_read`, and `/account/mark_all_read` across GET, POST, DELETE, form, fetch, redirect, and prefetch/navigation contexts. Use a disposable user, synthetic notifications, a same-site recorder, and denied follow/delete/read-state mutation sinks. Capture method, cookies, `Origin`, `Referer`, CSRF token source, SameSite behavior, selected object, and whether authorization ran before mutation.

A bounded positive is **cross-site top-level or subresource GET -> ambient authenticated cookie -> denied mutation sink receives the synthetic target without a per-request CSRF proof**. Test each route because a fix can convert one verb while leaving aliases or frontend helpers. Do not change follow state, delete notifications, mark retained items, or weaken browser protections merely to obtain a stronger result.

## Desktop updating: verify every binding before process start

The eParakstītājs record describes a compound failure: the XML descriptor was fetched over TLS while a permissive `TrustManager` and always-true hostname verifier accepted any certificate; the descriptor was not signed; and the selected installer was executed without an Authenticode or checksum decision. Prove these as separate links rather than collapsing them into “updater RCE.”

### Isolated updater harness

1. Snapshot an isolated Windows VM containing the affected application. Disable access to real credentials, documents, smart-card material, network shares, and production DNS.
2. Redirect the updater authority only inside the lab using a hosts-file entry or a DNS/proxy harness you own. Do not alter shared DNS and do not intercept another user's traffic.
3. Present a locally generated certificate that is untrusted, hostname-mismatched, or both. Capture the TLS decision and stop the first run before returning an update descriptor.
4. For the next run, serve a synthetic XML descriptor whose version and download URL point to the owned lab service. Change only one field at a time and retain the raw descriptor plus parsed URL decision.
5. Serve an inert test executable that performs no action. Replace or instrument process creation so the evidence is an argv/hash recorder rather than execution. The file should contain no shell, network, persistence, credential, or filesystem behavior.
6. Test the bindings independently:
   - trusted certificate and matching hostname;
   - certificate-chain failure;
   - hostname mismatch;
   - descriptor signature absent, invalid, and valid where supported;
   - installer checksum mismatch;
   - installer signer absent, wrong, and expected where supported; and
   - descriptor URL authority differing from the original update authority.
7. Affected behavior is established only if the fake TLS identity is accepted, the unsigned descriptor controls the installer URL, and the untrusted installer reaches the process-start recorder without an independent integrity decision.
8. Repeat on the fixed version. Require failure at the earliest invalid binding and confirm that an expected signer or pinned digest is checked over the exact bytes handed to the execution sink.

The bounded chain is **local network/DNS redirection in an approved lab -> unauthenticated TLS peer -> unsigned descriptor selects owned executable -> missing installer integrity check -> inert process-start recorder**. Do not execute arbitrary code merely to prove that the updater would launch the selected file.

## Reporting checklist

- [ ] Exact affected and fixed product versions are recorded.
- [ ] Report author, report generator, field, representation, and final renderer dispatch are shown separately.
- [ ] Stored value, escaped response, parsed DOM, Vue mount root, configured delimiters, and patched compiler decision are preserved separately.
- [ ] Client-template proof uses an inert compiler recorder plus `v-pre`, unmounted, and fixed-revision controls rather than executing JavaScript.
- [ ] SSRF proof uses owned callbacks, a synthetic local service, and a patched file opener rather than production/internal targets or real files.
- [ ] Redirect behavior records both initial and final authorities.
- [ ] Updater evidence separates certificate-chain, hostname, descriptor authenticity, installer checksum/signature, and process-start decisions.
- [ ] DNS or proxy redirection is confined to a disposable VM.
- [ ] No real update traffic, credentials, documents, smart-card material, host files, or executable payloads appear in evidence.
- [ ] Claims stop at the first callback, opener, or process-start recorder and do not overstate downstream code execution or data access.

## October 14 15:3xZ follow-up: Report One MyReport Updater — unauthenticated gRPC re-points a SYSTEM service's update source, "integrity" is an attacker-computable MD5 (c58m/CVE-2026-110632 critical + www7/CVE-2026-110633 LPE, ≤2.1.1)

The MyReport Updater service (runs as SYSTEM on Windows hosts with SAP Business One reporting) exposes a **gRPC listener on TCP 9095 with no authentication**; invoking `UpdateConfigReferent` overwrites the updater's reference-server configuration. The attacker points it at their own server, which serves "modified module archives **with matching MD5 digests**" — the digest check is satisfied because the attacker recomputes MD5 over their own payload. Result: file write + code execution as SYSTEM. The sibling advisory covers a local privilege escalation in the same updater.

Durable axes (extends this page's updater-binding checklist):

- **The update *source* is itself an unauthenticated write target on many Windows sidecar services.** Before attacking the download/verify path, enumerate the service's management surface (gRPC reflection on non-HTTP ports is one `grpcurl` away: `grpcurl -plaintext <host>:9095 list`). If config that selects the update URL is writable pre-auth, the entire TLS/signature chain downstream is moot — this is the "descriptor authenticity" binding in this page's checklist failing at the *storage* layer, not the parse layer.
- **MD5 "verification" of attacker-supplied artifacts is not integrity — it's formatting.** Any updater whose check is `hash(served_bytes) == hash_shipped_with_pointer` where the attacker controls both sides validates nothing. During authorized reviews, compute the digest yourself and confirm match to prove the check is post-hoc; the real bindings are signature-over-digest by a pinned key or digest pinned in a protected store.
- Fingerprint for red-team recon: Windows hosts with vendor reporting stacks exposing 9095 (default gRPC-ish band) or any high port answering gRPC reflection; banner = reflection list output. Proof stops at a synthetic module served from an owned fake reference server into a lab VM — never push archives at production updaters.
