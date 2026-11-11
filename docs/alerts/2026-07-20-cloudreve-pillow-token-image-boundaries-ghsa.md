# Cloudreve OAuth/remote-download and Pillow path/image boundary checks

Sources: hourly offensive-security scan, 2026-07-20 GitHub Security Advisory feed. Primary entries: Cloudreve [GHSA-vgj4-345g-jcf8](https://github.com/advisories/GHSA-vgj4-345g-jcf8) / CVE-2026-54560 and [GHSA-x756-g4x3-c64m](https://github.com/advisories/GHSA-x756-g4x3-c64m) / CVE-2026-54562, Pillow [GHSA-4x4j-2g7c-83w6](https://github.com/advisories/GHSA-4x4j-2g7c-83w6) / CVE-2026-55798, [GHSA-62p4-gmf7-7g93](https://github.com/advisories/GHSA-62p4-gmf7-7g93) / CVE-2026-54058, and [GHSA-fj7v-r99m-22gq](https://github.com/advisories/GHSA-fj7v-r99m-22gq) / CVE-2026-59198.

These advisories expose five reusable operator boundaries: OAuth metadata deciding whether scope checks run at all, remote-download URLs reaching a final server-side destination, a filename crossing into a Windows shell command, image-header geometry crossing into a memory-mapped row layout that may later be returned as decoded pixels, and packed image rows crossing into a TGA RLE output disclosure. The common workflow is to prove the exact source-to-sink transition with synthetic identities, URLs, paths, and media rather than treating a package version as proof.

!!! warning "Authorized validation only"
    Use disposable Cloudreve users/clients, redacted canary tokens, a Windows VM with marker-only paths, and an isolated Pillow worker with synthetic media. Never use a real user's OAuth grant, execute a production command, collect process memory, upload malformed files to shared services, or preserve leaked bytes in wiki/report evidence.

## What changed

| Advisory | Boundary | Preconditions | Operator value |
| --- | --- | --- | --- |
| [GHSA-vgj4-345g-jcf8](https://github.com/advisories/GHSA-vgj4-345g-jcf8) / CVE-2026-54560 | Cloudreve OAuth access-token `client_id`/scope claims -> request context -> `RequiredScopes(...)` | A real user authorizes an OAuth client; affected access tokens carry scopes but omit `client_id`, causing scope metadata not to enter request context | Test whether minimal-consent tokens are treated as unscoped first-party sessions across route families. This is a consent/scope bypass, not anonymous authentication bypass. |
| [GHSA-x756-g4x3-c64m](https://github.com/advisories/GHSA-x756-g4x3-c64m) / CVE-2026-54562 | Cloudreve user URL -> remote-download worker -> imported file readback | Authenticated non-admin belongs to a group with remote download enabled; this is not enabled for default ordinary users | Test whether initial, redirect, IPv4/IPv6, and hostname forms preserve an owned external-only policy through the final downloader request. |
| [GHSA-4x4j-2g7c-83w6](https://github.com/advisories/GHSA-4x4j-2g7c-83w6) / CVE-2026-55798 | Pillow `WindowsViewer` file path -> `cmd.exe` command built for `shell=True` | Windows; an application invokes the image-show path with an attacker-influenced existing filename | Add shell-metacharacter filenames to local viewer/helper reviews and distinguish command construction from reachability. |
| [GHSA-62p4-gmf7-7g93](https://github.com/advisories/GHSA-62p4-gmf7-7g93) / CVE-2026-54058 | McIdas AREA header dimensions/stride -> Pillow mmap row pointers -> pixel read/re-encode | Image opened from a filesystem path, default plugin available, and decoded pixels subsequently read, converted, saved, or returned | Test parser geometry as a data-disclosure boundary when the application returns transformed pixels, not only as a crash condition. |
| [GHSA-fj7v-r99m-22gq](https://github.com/advisories/GHSA-fj7v-r99m-22gq) / CVE-2026-59198 | mode `1` packed row -> TGA RLE encoder treats pixels as bytes -> adjacent heap bytes serialized into output | Application accepts or constructs a mode `1` image and returns/saves TGA with RLE enabled | Test output-file disclosure with a tiny synthetic heap canary and bounded widths; do not collect arbitrary process memory. |

Pillow `12.3.0` contains the fixes identified by both Pillow advisories. Confirm Cloudreve's fixed release from its advisory/release record at test time; do not infer deployment state from a UI footer or container tag alone.

## Cloudreve minimal-scope decision matrix

### Preconditions

- a disposable Cloudreve instance with one normal test user and, only if explicitly needed, a separate test administrator;
- an OAuth client controlled by the tester;
- a harmless resource in each enabled route family, such as a synthetic file, share, workflow, user-setting field, or WebDAV device row;
- one access token authorized only for `openid` and comparison tokens with the exact required read/write scope;
- a way to decode JWT claims locally without sending tokens to a third-party service.

### Workflow

1. Complete the authorization-code flow for the normal user while requesting only `openid`. Record consent text, requested scope, granted scope, client ID, and redacted token fingerprint.
2. Decode the access token locally. Record whether `scope`/`scopes` and `client_id` are present; do not treat claim absence alone as impact.
3. Call a harmless read endpoint requiring a scope that was not granted. Then try a reversible write against a synthetic object and immediately restore it.
4. Repeat with a correctly scoped token, a session-authenticated request, no token, a malformed token, and the fixed release.
5. If the assessment explicitly covers administrator consent, use a separate disposable admin and stop at a harmless `Admin.Read` status/list decision. Do not invoke administrative writes merely to increase severity.

Use a decision table:

| Credential | Granted scope | Required scope | Expected secure result | Evidence |
| --- | --- | --- | --- | --- |
| none/malformed | none | read | authentication failure | status and error code |
| session | n/a | read | first-party session policy | status only |
| OAuth token | `openid` | file read/write | insufficient scope | synthetic object unchanged |
| OAuth token | exact required scope | matching action | allowed | canary read or reversible update |

Positive evidence is **valid low-scope OAuth token -> missing client binding prevents scope context initialization -> higher-scope route accepts the request as the same user**. Report the user authority separately from OAuth client authority: the flaw broadens what the third-party client may do as its consenting user, but it does not grant permissions the user lacks.

## Cloudreve remote-download final-destination check

1. Confirm the test user is non-admin and record whether its group has remote download enabled. The default ordinary-user denial is an important negative control.
2. Run two researcher-owned HTTP services: an externally permitted source and a synthetic destination that represents a restricted address class in an isolated lab network. Return only random canary bodies.
3. Submit direct, hostname, IPv6-equivalent, and owned redirector URLs to `POST /api/v4/workflow/download`. Never use cloud metadata, localhost services containing real data, production private ranges, or third-party hosts.
4. Correlate the queued workflow, final callback log, imported filename, and canary body read through the ordinary file API. A callback alone proves server-side fetching; imported canary readback proves the full confidentiality path.
5. Repeat with remote download disabled, an external-to-external redirect, an external-to-restricted redirect, and Cloudreve `4.16.1` or later.

Report this as **non-admin group capability -> user-controlled URL -> downloader final destination -> imported response readable by the same user**. Keep direct and redirect checks separate, and state the permission precondition rather than calling the route anonymously reachable.

## Pillow Windows viewer path-to-shell check

1. Confirm that target application code reaches `Image.show()`, `ImageShow.WindowsViewer.show_file()`, or an equivalent viewer helper on Windows. Uploading or processing an image without invoking a viewer does not satisfy this precondition.
2. In a disposable Windows VM, use an existing benign image whose filename contains one inert shell separator canary. The only side effect should be creation of a marker file under the same temporary lab directory.
3. First call `WindowsViewer.get_command()` without executing it and capture the generated command with the path redacted to the lab root. This proves whether the filename remains data or changes command structure.
4. If execution is authorized, invoke the real application path once and verify only the marker. Monitor child-process argv and filesystem changes; block network access.
5. Repeat with a normal quoted filename and Pillow `12.3.0` or later. The fixed control should preserve the filename as one argument and create no marker.

Report this as **attacker-influenced existing filename -> Windows image viewer helper -> shell command structure -> inert local marker**. Do not claim a remote upload-to-command chain unless the application preserves the relevant filename characters, stores the file on Windows, and actually invokes the viewer path.

## Pillow mmap row-layout disclosure check

This issue has a useful application-level distinction: malformed geometry may crash a worker, but it becomes a disclosure workflow only when out-of-bounds bytes survive a pixel operation and are returned or stored by the application. Keep the test bounded to that decision; do not seek secrets.

1. Build an isolated worker with an affected Pillow release and a fixed `12.3.0+` control. Give the worker a dedicated temp directory, no credentials, no network, and no unrelated user data.
2. Place a synthetic McIdas AREA fixture on disk. Use small, bounded dimensions and a deliberately inconsistent positive row stride generated by a local harness; do not embed copied exploit archives in assessment artifacts.
3. Exercise the same target path used by the application: `Image.open(path)` followed by the relevant `load`, `getpixel`, `convert`, `tobytes`, thumbnail, or save operation.
4. Seed an unmistakable non-secret canary buffer in the isolated worker. If output includes bytes beyond the fixture's declared pixel region, preserve only offsets, lengths, hashes, and a short canary match,not arbitrary surrounding bytes.
5. Repeat with an in-memory stream rather than a filename, a normal AREA fixture, no pixel-consuming operation, and the fixed release. These controls distinguish the mmap path and downstream disclosure sink from parser recognition alone.
6. Stop on the first controlled canary match or bounded fault. Do not increase dimensions to force a crash and do not inspect heap content for credentials or cross-request data.

Report this as **attacker-controlled AREA geometry -> filename-backed mmap row layout -> downstream pixel consumer -> synthetic adjacent canary returned**. A parser exception or worker crash proves availability impact only; a disclosure claim requires controlled canary bytes in transformed output.

## Pillow TGA RLE output-disclosure check

1. Use an affected Pillow build and `12.3.0+` in isolated one-shot workers with no credentials, network, unrelated files, or prior user data.
2. Confirm the application reaches TGA output with RLE enabled (`compression="tga_rle"`, or the older equivalent) and a mode `1` image. Merely decoding an uploaded TGA is not this path.
3. Start with a two-pixel-wide synthetic image and an instrumented/ASAN build to prove the row-buffer over-read. Increase width only enough to recover a researcher-seeded adjacent marker; do not use the maximum width or search arbitrary heap content.
4. Capture the returned TGA, parse packet payload offsets offline, and preserve only canary-match offsets, output hashes, and lengths. Discard all non-canary out-of-bounds bytes.
5. Repeat with non-RLE output, an 8-bit mode, a normal width control, a fresh worker without the seeded marker, and Pillow `12.3.0+`.

Report this as **mode `1` packed row -> TGA RLE byte-per-pixel mismatch -> synthetic adjacent heap marker serialized into generated image**. Do not call a crash or ASAN read a disclosure unless canary bytes are present in the application-returned artifact.

## Evidence and reporting checklist

- [ ] Exact package/application versions and vulnerable-versus-fixed controls
- [ ] Cloudreve OAuth client, user role, requested/granted/required scopes, route family, and redacted token claim presence
- [ ] Proof that the user already possessed the underlying Cloudreve authority
- [ ] Pillow call path showing viewer invocation or filename-backed mmap selection
- [ ] Synthetic filename/media fixture and bounded marker/canary evidence
- [ ] Child-process argv or output-byte offsets without commands, secrets, memory dumps, or live tokens
- [ ] Negative controls that isolate reachability from a version-only finding

## Not promoted from the same wave

[GHSA-phj9-mv4w-65pm](https://github.com/advisories/GHSA-phj9-mv4w-65pm), [GHSA-45hq-cxwh-f6vc](https://github.com/advisories/GHSA-45hq-cxwh-f6vc), [GHSA-5x94-69rx-g8h2](https://github.com/advisories/GHSA-5x94-69rx-g8h2), [GHSA-8v84-f9pq-wr9x](https://github.com/advisories/GHSA-8v84-f9pq-wr9x), [GHSA-pg7v-jwj7-p798](https://github.com/advisories/GHSA-pg7v-jwj7-p798), and [GHSA-jjj6-mw9f-p565](https://github.com/advisories/GHSA-jjj6-mw9f-p565) are Pillow decompression/parser resource issues. [GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp) is an exponential-time brace-expansion issue. [GHSA-6r8x-57c9-28j4](https://github.com/advisories/GHSA-6r8x-57c9-28j4) and [GHSA-xj96-63gp-2gmr](https://github.com/advisories/GHSA-xj96-63gp-2gmr) expose public-API native writes but did not add a bounded application exploit path beyond isolated memory-safety harnessing. They were marked processed without standalone offensive guidance.

## July 24 Cloudreve scope, share-event, WOPI, and directory follow-up

Four Cloudreve findings extend the existing OAuth and file fixture:

- [GHSA-hq88-5x99-x3gf](https://github.com/advisories/GHSA-hq88-5x99-x3gf) / CVE-2026-55502: an OAuth token with `Admin.Read` but not `Admin.Write` can reach the OneDrive policy `oauth/signin` handler, which persists caller-supplied app ID and secret. Use a fake policy and reversible marker values; 4.17.0 is the fixed control.
- [GHSA-w8x7-h2px-xmq8](https://github.com/advisories/GHSA-w8x7-h2px-xmq8) / CVE-2026-55499: opening the event stream for a single-file share can subscribe the recipient to the owner's parent-folder topic, leaking unshared sibling activity metadata.
- [GHSA-49h3-cwhj-4737](https://github.com/advisories/GHSA-49h3-cwhj-4737) / CVE-2026-55495: WOPI `PUT_RELATIVE` treats `X-WOPI-SuggestedTarget` as path segments and normalizes them before basename validation, allowing a token bound to one file to create a file elsewhere in the same owner's drive.
- [GHSA-8r7f-r8hj-r3rv](https://github.com/advisories/GHSA-8r7f-r8hj-r3rv) / CVE-2026-55496: `SearchActive` lacks an active-status predicate, so a logged-in user can find inactive/banned synthetic accounts and their email field.

### Consolidated Cloudreve lab

1. Create an admin OAuth client with separate read-only and write tokens, a fake OneDrive policy, two ordinary users, one parent folder with a shared marker file and unshared sibling, one WOPI-enabled marker document, and active/inactive/banned synthetic directory users.
2. With the read-only admin token, submit only fake app credentials to the policy OAuth-signin route. Record the scope decision and marker fields before/after, then restore them. Do not connect a real OneDrive tenant.
3. As the single-file share recipient, subscribe using the bare share-root URI. Rename one unshared sibling to another synthetic name. Evidence is the event type/path/hash only; do not retrieve sibling contents. Compare an explicit shared-file URI and a folder share.
4. With a WOPI token for `folder/current.docx`, compare a plain suggested filename, an extension-only target, a child path, and a traversal-shaped target that resolves only to another disposable folder in the same lab account. Evidence is the final URI and marker-file placement; never overwrite an existing file.
5. Search a two-character canary prefix as an ordinary user and compare active, inactive, banned, anonymous, and fixed-build results. Preserve only synthetic email values.

Keep claims bounded: the event issue exposes activity metadata, not file bytes; WOPI escapes per-file/directory scope but remains in the same owner's drive; the OAuth issue requires an already-authorized read-admin token; and directory search is an authenticated PII oracle rather than account access.

### Admin.Read node-test SSRF follow-up

[GHSA-v6w6-358x-2433](https://github.com/advisories/GHSA-v6w6-358x-2433) adds an action-vs-scope mismatch: an OAuth token with `Admin.Read` but not `Admin.Write` could submit caller-controlled node definitions to `/api/v4/admin/node/test` and `/api/v4/admin/node/test/downloader`, causing outbound operational requests. Cloudreve `4.17.0` is the fixed control.

Extend the lab with an owned callback and a synthetic node definition containing fake keys. Establish that the token cannot create/update a node, then call each test route and record only callback receipt, request class, and redacted marker headers. Never target metadata, internal services, or real storage nodes. Report **read-only admin OAuth scope -> node test action -> server-side network request**, not anonymous SSRF.

## August 24 remote-download path-escape and context-hint revocation follow-up

Two Cloudreve `v4` findings (no fixed release published at scan time; treat every `<= 4.0.0-20260606032813-26b6b1044b02` checkout as in range) add two new operator boundaries to this page: a downloader-reported file path that escapes the user-selected destination, and a cached share-navigator state that skips share revalidation.

- [GHSA-w8j7-39hp-8x59](https://github.com/advisories/GHSA-w8j7-39hp-8x59): the remote-download master/slave transfer path joins the user-selected destination URI with the downloader-reported filename via `URI.JoinRaw()`, and `sanitizeFileName()` does not strip `/`, `.`, or `..`. For aria2, `TaskFile.Name` is derived from `tellStatus().files[].path`, so a downloader that reports `<saveDir>/../../escaped.txt` places the downloaded file above the selected destination folder.
- [GHSA-vx2m-jpxr-xv7w](https://github.com/advisories/GHSA-vx2m-jpxr-xv7w): file-listing responses hand the client a `context_hint` UUID. Replaying it on `file/url` / `file/thumb` makes DBFS restore a cached `shareNavigatorState` whose `shareRoot` is already loaded, so `To()` skips `Root()`, the only place that re-runs `IsValidShare` (expiry, remaining downloads, owner status) and the share-password check. A recipient who prewarms the hint while access is valid can keep minting signed URLs for already-known shared file paths for up to the hint TTL (`5 * 60` = 300 s) after the share is deleted, expires, or hits zero remaining downloads, plus the life of any signed URL minted in that window.

### Remote-download destination-escape check

This extends the [remote-download final-destination check](#cloudreve-remote-download-final-destination-check) with a *downloader-metadata* input class instead of an HTTP URL input class: the traversal arrives in the downloader's own reported path, not in the URL the user typed.

1. Stand up the official Cloudreve Docker image (PostgreSQL, Redis) with remote download enabled and the aria2 provider pointed at a fake aria2 JSON-RPC service you control.
2. In the file manager create `My files / victim / safe /`. Create a remote-download task for any URL inside `victim/safe`.
3. The fake aria2 service answers `aria2.tellStatus` with `files[0].path = <saveDir>/../../escaped.txt` (a sibling above the selected destination). Do not target a real downloader; the vulnerable input is the downloader's metadata, so a local fake is the correct oracle.
4. The expected secure result is the file landing at `cloudreve://my/victim/safe/...`. The vulnerable result is a file at `cloudreve://my/escaped.txt`, it escapes both the selected destination and its parent.
5. Note the boundary honestly: the escape is still subject to Cloudreve's normal upload and permission checks, so it moves the file into an *accessible* location above the chosen folder rather than arbitrary system paths. Report it as **downloader-reported file path -> `JoinRaw` segment join -> destination URI above the selected folder**, distinct from the URL-SSRF destination finding.

### Context-hint share revocation-bypass check

This is a revocation/expiry bypass, not a way to discover unknown share contents: the tester must already have had access to the share and must know the target file URI from a prior listing.

1. Lab setup: one share owner and one recipient (a second free account, or anonymous if the default anon group keeps share download). The recipient knows the share URL (and password, if any).
2. While the share is valid, the recipient lists it (`GET /api/v4/file?uri=<share-uri>`) and records the returned `context_hint` and each file's `path`.
3. Prewarm the cache for one known file: `POST /api/v4/file/url` with header `X-Cr-Context-Hint: <context_hint>` and body `{"uri":["<known-shared-file-uri>"]}`. This is a cache MISS, so `Root()` runs and `PersistState` arms, writing `shareNavigatorState` to KV under `navigator_state_<hint>_share`.
4. The owner deletes the share (or lets it expire / hit zero remaining downloads).
5. Within 300 s, the recipient repeats the same `file/url` request with the same hint. Expected secure result is `ErrShareNotFound` / `ErrShareLinkExpired`. The vulnerable result is a signed, downloadable URL, cache HIT, `RestoreState` sets `shareRoot`, `To()` skips `Root()`, and `IsValidShare` never runs.
6. Confirm the signed content endpoint `file/content/:id/...` then serves the file under `SignRequired` alone.

Report it as **listing response context_hint -> replayed X-Cr-Context-Hint -> DBFS cached shareNavigatorState -> `To()` skips `Root()`/`IsValidShare` -> signed URL after revocation**. Keep the claim bounded: it defeats owner revocation, time expiry, the remaining-download limit, and password revalidation on cached state, but only for files the recipient already knows. Do not use it to read shares or files the recipient never saw.

### Not promoted from this wave

- [GHSA-fx4f-mhw4-qm7j](https://github.com/advisories/GHSA-fx4f-mhw4-qm7j), `vibeio-http` DoS in the HTTP/1.x chunked-encoding parser: a resource-exhaustion parser issue, no durable operator exploit path.
- [GHSA-w67g-5rqw-f597](https://github.com/advisories/GHSA-w67g-5rqw-f597), Gorilla WebSocket uses a weak PRNG for the WebSocket mask key (fixed `1.5.3`): a cryptographic-quality issue with no standalone replayable chain; revisit only if paired with an active-exploitation signal.
- [GHSA-4ph6-mjv7-3fq6](https://github.com/advisories/GHSA-4ph6-mjv7-3fq6), netfoil improper handling of untrusted DoH response data (low, fixed `0.5.0`): unverified-response log/memory hygiene, no operator exploit path beyond the existing [netfoil boundary coverage](2026-07-07-better-auth-aider-netfoil-ckan-mcp-boundaries-ghsa.md).

## August 27 WebDAV scoped-credential escape follow-up

[GHSA-w5fv-7x5q-g8qp](https://github.com/advisories/GHSA-w5fv-7x5q-g8qp) / CVE-2026-54563 (Cloudreve `v4`, fixed in `4.0.0-20260606032813-26b6b1044b02`) adds a **scoped-account root escape** through the WebDAV endpoint, the same input class as the earlier remote-download destination-escape but arriving in the HTTP request path instead of downloader metadata.

A WebDAV account stores a `uri` that is its root folder. The `/dav` handler (`stripPrefix` in `pkg/webdav/webdav.go`) trims the `/dav` prefix, joins the remainder to that root with `fs.URI.JoinRaw`, and **never checks the joined URI stays inside the root**. Go's `net/http` decodes `%2e%2e`→`..` and `%2f`→`/` in `r.URL.Path` before the handler sees it, and `JoinRaw` resolves `..` through `url.URL.JoinPath`, so `GET /dav/%2e%2e/outside.txt` against a credential rooted at `cloudreve://my/restricted` resolves to `cloudreve://my/outside.txt`, the sibling above the account root.

### Check

1. Lab: a Cloudreve `v4` instance with two WebDAV accounts. Account A is rooted at `cloudreve://my/restricted`; `outside.txt` is seeded at `cloudreve://my/outside.txt` (sibling, outside A's root).
2. As account A, issue `GET /dav/%2e%2e/outside.txt` (and the PROPFIND/OPTIONS variants). Expected secure result: 404/403 confined to `restricted/`. Vulnerable result: the sibling's contents/properties return, the scoped credential escaped its configured account root.
3. Note the boundary honestly: the escape is still subject to Cloudreve's normal file-permission checks, so it moves access to *accessible* sibling paths rather than arbitrary system paths. Report it as **WebDAV request path → `stripPrefix` → `JoinRaw` → URI above the account root**, distinct from the remote-download downloader-metadata finding above.

Keep the proof to a sibling marker file the second account can read; do not target real user data or the admin/`/` root.
