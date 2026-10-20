# ApostropheCMS coordinated wave: `.permission(false)` REST dumps, projection-key prototype deletion, `<noscript>` sanitizer discard escape, and URL-carried session tokens

**Signal:** GitHub Security Advisories published a coordinated **thirteen-advisory ApostropheCMS wave** on **2026-10-20 18:03–18:18Z** (CVE-2026-113654–113671 band). This is the largest public ApostropheCMS dump to date and doubles as a complete attack map for the framework: anonymous full-site content disclosure, a single-request process-wide prototype deletion, a sanitizer/browser parser differential, Host-header SSRF, session-token-in-URL takeover, and three unauthenticated resource primitives.

Advisories in scope:

| GHSA | CVE | Leg |
|---|---|---|
| [GHSA-2j32-q6rx-h844](https://github.com/advisories/GHSA-2j32-q6rx-h844) | CVE-2026-113670 | Page REST API `getOne` + `?all=1` tree dump run `.permission(false)` — unauthenticated read of private/admin-only pages |
| [GHSA-gqh3-7856-rjjg](https://github.com/advisories/GHSA-gqh3-7856-rjjg) | CVE-2026-113668 | `GET /api/v1/<type>/:_id/locales` omits the `publicApiCheckAsync` gate its gated siblings enforce |
| [GHSA-j5rq-xfvr-p969](https://github.com/advisories/GHSA-j5rq-xfvr-p969) | CVE-2026-113666 | `db-connect` projection-exclusion key walks to `Object.prototype` and `delete`s a shared method — one GET, process-wide persistent DoS |
| [GHSA-m2m5-rw3w-cwmj](https://github.com/advisories/GHSA-m2m5-rw3w-cwmj) | — | Client-side `apos.http.parseQuery()` prototype pollution from `window.location.search`, escalated to DOM XSS by Vue's property write on mount; no patch, 3.x/4.x all affected |
| [GHSA-x3q4-9hxx-gx8m](https://github.com/advisories/GHSA-x3q4-9hxx-gx8m) | CVE-2026-113654 | `sanitize-html` ends the `nonTextTags` discard region on htmlparser2's **implied** close; browsers parse `<noscript>` as raw text — sanitizer emits elements the page itself would not render |
| [GHSA-cv27-6wvh-8x7j](https://github.com/advisories/GHSA-cv27-6wvh-8x7j) | CVE-2026-113661 | Incomplete CVE-2026-53606: `meta http-equiv=refresh` `content="0;url=javascript:…"` never passes `naughtyHref()` because the URL lives inside an attribute *value* |
| [GHSA-527g-ff96-x6wj](https://github.com/advisories/GHSA-527g-ff96-x6wj) | CVE-2026-113671 | `@apostrophecms/ai-helper` accept-PATCH derives its server-side fetch origin from `req.baseUrl`, which falls back to the `Host` header when `apos.baseUrl` is unset |
| [GHSA-hhvr-8m24-qqr3](https://github.com/advisories/GHSA-hhvr-8m24-qqr3) | CVE-2026-113669 | Cross-domain session token delivered as `?aposCrossDomainSessionToken=` query parameter; presenting it silently adopts the victim's full session |
| [GHSA-2jrp-qc93-h2j8](https://github.com/advisories/GHSA-2jrp-qc93-h2j8) | CVE-2026-113655 | `page.move()` destination-parent authorization is gated on cross-parent move; a **same-parent reorder** short-circuits the check and a raw `updateMany` re-ranks restricted siblings |
| [GHSA-653j-g8j7-gh54](https://github.com/advisories/GHSA-653j-g8j7-gh54) | — | Self-service password-change endpoint calls `verifyPassword` directly, bypassing the login module's attempt counter/throttle entirely |
| [GHSA-qhcq-9pm2-c9w9](https://github.com/advisories/GHSA-qhcq-9pm2-c9w9) | CVE-2026-113658 | Unauthenticated CSV import: Multer writes to `os.tmpdir()` **before** the extension check; rejection path never unlinks |
| [GHSA-89mh-mm8c-mv7f](https://github.com/advisories/GHSA-89mh-mm8c-mv7f) | CVE-2026-113656 | `@apostrophecms/form` submit mounts `multer({dest: os.tmpdir()}).any()` before auth/CSRF/size checks — anonymous unbounded disk write |
| [GHSA-44qr-rrjg-2cqq](https://github.com/advisories/GHSA-44qr-rrjg-2cqq) | CVE-2026-113667 | CAPTCHA token interpolated unencoded into the server-side reCAPTCHA/hCaptcha verify URL/body — query-parameter injection into the verify request |

## 1. Anonymous full-site disclosure: `.permission(false)` and config-presence "authorization"

`getOne` and the `all=1` tree handler in `@apostrophecms/page` build `getRestQuery(req).permission(false)` — the query layer's per-document permission enforcement is switched off, `viewRole` and `visibility` (`private`, `loginRequired`) are never applied, and `publicApiCheckAsync` **only checks that a `publicApiProjection` config exists** — it performs no authorization at all. The correct sibling (`piece-type` `getOne`) uses `getRestQuery(req)` without `.permission(false)` and enforces `viewRole`.

Operator shape (authorized lab first, then scoped targets):

```bash
# Anonymous private/admin-only page, full document incl. protected fields:
curl "https://target/api/v1/@apostrophecms/page/<_id>:en:published"
# Anonymous full site tree incl. private + loginRequired pages and visibility metadata:
curl "https://target/api/v1/@apostrophecms/page?all=1"
```

The `all=1` dump makes `_id`s enumerable, which chains into the gated-by-`_id` reads. Control probes that should deny on a patched build: contributor autocomplete search on a private type (`403`) and draft-locale read (`403`) — the advisory's own decision table shows these correctly enforced while the `getOne`/`all` legs serve 200.

**Rules:**
- A guard function whose body is "does config X exist" is not an authorization gate. Read the guard's implementation, not its name — `publicApiCheckAsync` has been the same no-op the whole time the framework was advisoried around it.
- Grep `.permission(false)` (or the framework's query-builder permission-disable flag) across every REST handler, not just the ones with advisories. Same-module sibling asymmetry (gated `getAll` vs ungated `getOne`/`all`/`locales`) is the fingerprint.
- Any tree/sitemap/list dump endpoint is an `_id` enumerator for adjacent gated routes — test the dump anonymous first, then feed its IDs into every `:_id` verb.

## 2. One GET kills the process: projection **keys** are never laundered

On SQLite/PostgreSQL/multipostgres adapters (`@apostrophecms/db-connect` >= 1.0.0 <= 1.0.2), the REST projection builder launders projection **values** only; an exclusion key survives verbatim to `unsetNestedField`, which walks dotted segments with no guard and executes `delete` on the resolved property:

```http
GET /api/v1/@apostrophecms/article?project[constructor.prototype.hasOwnProperty]=0
Cookie: <any view-draft role user (or any logged-in user with guestApiAccess)>
```

`qs` parses the bracketed key as a single literal-dotted own key; `finalize` skips falsy values before inspecting keys; `unsetNestedField` resolves `constructor` → global `Object` and deletes `Object.prototype.hasOwnProperty` **process-wide** — every subsequent `hasOwnProperty` call across app, dependencies, and driver throws until restart. The sibling `setNestedField` blocks a literal `__proto__`; `unsetNestedField` blocks nothing, and `constructor.prototype.<member>` bypasses even the partial sibling guard. The earlier seed prototype-pollution fix hardened `apos.util.set/get` in the `apostrophe` package; the `db-connect` helpers were never touched. Default MongoDB adapter is not affected — **adapter choice is a fingerprint** (`/api/v1/@apostrophecms/*` behavior quirks + deployment metadata).

**Rules:**
- Prototype-traversal batteries must include `constructor.prototype.<member>`, not just `__proto__` — where a partial `__proto__` block exists, the constructor chain is the first probe.
- Sibling-hardening-drift grep: when a repo fixed pollution in one helper, diff every sibling that walks untrusted path segments (`set` vs `unset`, include vs exclude branches).
- Query-builder **key** injection is its own class: for every parameter that accepts `param[<key>]=value`, test whether the key or only the value is validated. Persistent-process-corruption DoS (survives request end, requires restart) is materially different from CPU/memory pressure — treat as an integrity finding.

## 3. Client-side pollution → Vue DOM XSS with an always-on trigger

`apos.http.parseQuery()` deserializes `window.location.search` into a nested object with no `__proto__`/`constructor`/`prototype` key filtering; the admin UI calls it on **every authenticated page load** (context-bar `data()` initializer), and Vue's element-mount routine writes polluted enumerable `Object.prototype` properties onto DOM elements — pollution becomes DOM XSS in the victim's session, guest-up-to-admin, via one crafted URL. No patched version at scan time (3.x and 4.x all affected); distinct side and code path from the server-side CVE-2026-53609 fixed in 4.31.0.

**Rule:** the server-side/client-side split of a known bug class is a fresh hunting axis — when a framework ships a server-side pollution fix, immediately grep the client-bundle helpers (`ui/public/*.js`, anything touching `location.search`/`postMessage` data) for the same unsanitized descent. The escalation gadget need not be novel; the unsanitized source plus privileged trigger is the reportable defect.

## 4. `sanitize-html` ends discard regions on implied closes — the browser never saw your markup

`nonTextTags` discards element *content* using htmlparser2 close events and **ignores the `isImplied` flag** htmlparser2 passes:

```js
sanitizeHtml('<div><noscript></div><img src="http://evil.test/t.gif"></noscript>', {
  allowedTags: ["div","img"], allowedAttributes: { img: ["src"] },
  nonTextTags: ["script","style","textarea","option","noscript"],
});
// => '<div></div><img src="http://evil.test/t.gif" />'   (img SURVIVES)
```

Closing a still-open ancestor inside `<noscript>` makes htmlparser2 unwind its stack and emit a synthetic implied close that ends the discard region early; a scripting-enabled browser parses `<noscript>` as **raw text** and renders no `<img>` at all. The sanitizer emits elements the page itself would never have parsed. A `<![CDATA[` variant hides the `<noscript>` opening tag from the sanitizer while the browser ends its bogus comment at the first `>`:

```html
<p>Hi</p><![CDATA[ x > <noscript>]]><a href="…">Reset your password</a><img src="…beacon.gif"></noscript>
```

**Rules:**
- Sanitizer/browser parser-differential battery, now three legs deep on this package (May `xmp` raw-text passthrough, July `formaction` scheme-skip, this implied-close escape): for each discard/raw-text tag, probe ancestor-close, implied-close, and CDATA/bogus-comment desynchronization, then diff sanitizer output against headless-browser DOM under scripting-on.
- The differential direction here is notable: sanitizer *drops more* than the browser, yielding markup the input never deserved. Report framing: sanitizer output ≠ input as-parsed; validate with a detached-DOM/AST recorder, script-inert, per the July 31 sanitize-html harness.

## 5. Scheme checks keyed by attribute name miss URLs inside attribute values

CVE-2026-53606's fix routed named URL attributes through `naughtyHref()`; `meta http-equiv=refresh` nests its destination inside the `content` value (`0;url=javascript:alert(1)`), so no attribute-name-listed gate ever fires. Under the same non-default config (allow `meta` + `http-equiv`/`content`), `javascript:`/`data:`/attacker-`https:` refresh destinations survive while the 53606 `formaction` leg is correctly stripped.

**Rule:** after any scheme-validation fix, enumerate attributes whose *values embed URLs* beyond the attribute-name list: `meta[content]` refresh, `style` `url()`, `<base href>` semantics, `action`/`formaction` (fixed), frame/iframe `srcdoc`, and SVG `xlink:href` variants. Validation surfaces keyed on names miss structure-nested destinations.

## 6. Host-derived fetch origin, again (ai-helper) and the sibling-route authorization asymmetry

With `apos.baseUrl` unset (default), `req.baseUrl` = `req.protocol://Host-header`. The ai-helper image accept route builds its server-side fetch target as `new URL(<relative /uploads path>, req.baseUrl)` — with the record's `url` absent (base64-generation path), the origin comes entirely from the attacker's `Host:`:

```http
PATCH /api/v1/@apostrophecms/image/ai-helper/<_id>
Host: 169.254.169.254
{"accepted": true}
```

Second root-cause detail: the **generate** route enforces edit capability; the **accept** route does `findOne({_id})` with no permission or ownership check — verb-sibling gate asymmetry inside one feature. Path is fixed (`/uploads/ai-helper-images/<id>.png`), so this is an origin-constrained SSRF (host/port/scheme only), with image-parseable responses viewable as attachments — semi-blind. This is the third ApostropheCMS Host-header boundary on the wiki (May password-reset page, July 31 pretty-URL fetch page); the common precondition is unset `baseUrl`.

**Rules:**
- On any ApostropheCMS target, unset-canonical-baseUrl is a single precondition unlocking a whole family: reset-link poisoning, pretty-URL fetch, ai-helper SSRF. Check it first (behavioral tell: absolute URLs echoed in responses/emails track your `Host`).
- Inside one feature, enumerate every verb's gate separately (generate vs accept; POST vs PATCH); ownership checks on one leg say nothing about siblings.

## 7. Session token in a query parameter is a session in every log

`?aposCrossDomainSessionToken=` carries a single-use token that `Object.assign`s the stored session (cookie + `passport.user`) onto the presenter's session with zero credentials. Exposure vectors are inherent to URL placement: server/proxy logs, browser history, and `Referer` on the cross-host hop that is the feature's intended use case. Single-use consumption narrows but does not close the window. Operator probe: hunt token-named query parameters on any auth-adjacent flow (`grep -iE 'token|key|auth|session|magic'` against route tables), present a captured/replayed value once against a lab account, and check whether middleware runs on all URLs (Apostrophe registers it without `before:`, verified via `APOS_LOG_ALL_ROUTES=1`).

**Rule:** session-migration/bridge features ship bearer-grade capability into URL space — treat any credential in a query parameter as log/Referer/history-exposed and time-boxed testable; the `APOS_LOG_ALL_ROUTES`-style middleware-scope audit (does the token handler run on every path?) belongs on every framework.

## 8. Authorization condition gated on the operation being "interesting"

`move()`'s destination-parent `create`-authority check leads with the conjunct `(oldParent._id !== parent._id)` — for a same-parent reorder it is false, the whole conditional short-circuits, and the sink is a raw `updateMany` sibling re-rank that bypasses the per-document `beforeUpdate` edit check entirely. The insert path enforces `parent._create` unconditionally — fix-shaped contrast proves intent. Precondition: an editor-editable page already nested under a restricted-parent type (config drift when a type gains `editRole` after children were placed).

**Rule:** when a guard's condition includes "did the operation change anything structurally," probe the no-change variant of the same operation — reorders, self-moves, no-op edits, and zero-delta updates routinely skip the sibling's authorization branch while still reaching bulk-write sinks. Raw `updateMany`/`bulkWrite` calls that never pass the ORM's per-document hook chain are a grep target.

## 9. Throttle is per-route, not per-credential

The login route runs `checkLoginAttempts`/`addLoginAttempt`; the self-service password-change route calls `verifyPassword` directly with no counter, delay, or lockout — an authenticated (even guest-tier) session can brute-force the *current* password without limit. The password appears in an unrelated verb family (settings PATCH) whose guard set was copied minus the rate limiter.

**Rule:** enumerate every endpoint that consumes a password/OTP/passkey factor — login, password-change, re-auth step-up, SSO linking, sensitive-action confirmation — and test throttling **independently per endpoint**. A lockout on login proves nothing about the settings verb.

## 10. Middleware-before-validation disk writes: the unauthenticated disk-exhaustion pair

Two legs, one root cause (body-parsing middleware mounted ahead of every check): the CSV import route runs Multer into `os.tmpdir()` before the extension check and never unlinks on the rejection path (anonymous, CSRF gate is a fixed-value double-submit cookie obtainable on any GET); the form submit route mounts `multer().any()` with no size/count/rate limits ahead of auth and existence checks — 200 MB staged to `/tmp` per request before the 500, orphaned on abort.

**Rule:** for any multipart endpoint, measure when bytes land on disk: send a small oversized/rejected-shape upload and diff `df`/tmp listings mid- and post-response. Staged-before-validated = an unauthenticated disk primitive even when the endpoint otherwise 400s correctly. The fixed-value double-submit "CSRF" cookie pattern (same constant for all visitors, set on any GET) is itself a probe target — it gates nothing against anonymous automation.

## 11. CAPTCHA token parameter injection into the verify request

`response=${input.recaptcha}` string interpolation lets a crafted token (`x&secret=INJECTED&something=1`) append parameters to the outbound siteverify call — verification denial against captcha-gated login/form flows, plus an automated-bypass probing channel. Small, but it is the captcha leg of the standing rule: **server-side outbound requests assembled by string interpolation accept parameter injection from every interpolated untrusted value**; build with `URL`+`searchParams` is the fix shape, so test `&key=` shapes on any token/value the server forwards to a third-party verify endpoint.

## October 20 18:2xZ follow-up legs: SAS credential in every public URL, literal-substring tar guard, and the "general public" subject that skips role checks

Three enrichment/late legs landed after this page's main wave, all same product family:

**12. Credential-bearing client URL reused as public base URL** — [GHSA-hhph-8536-gfq5 / CVE-2026-113652, `uploadfs`](https://github.com/advisories/GHSA-hhph-8536-gfq5) (fixed 1.28.0). With the Azure backend configured `sas: true`, `createContainer()` builds the `BlobServiceClient` from a URL embedding the full SAS query string, and Azure SDK v12 derived clients **inherit that query string** — so `getUrl()` returns a base URL carrying an account/container-level SAS signature, and `attachment.url()` prepends it to every public attachment link. Every anonymous visitor gets a (commonly `sp=rwdlac`, read/write/delete/list) container credential valid for the SAS lifetime, propagating through page source, logs, Referer headers, and CDN logs. The companion broken-URL bug (blob path appended *after* the query string) is itself a fingerprint that the code path was never exercised end-to-end. Durable rule: **on any storage-backend product, request one public asset URL and diff it against the credential material you'd expect** — grep `getUrl`/`baseUrl` derivations that call `.url` on a client constructed from a connection string; the "broken URL in the same path" is the dead-code tell that a signing/credential mode ships untested. Passive, unconditional leak: recon needs only page view.

**13. Extraction guard is a literal substring test, not a containment test** — [GHSA-97wv-p4xx-c7mg / CVE-2026-113664, `@apostrophecms/import-export`](https://github.com/advisories/GHSA-97wv-p4xx-c7mg) (fixed 3.7.0). The guard added for the earlier GHSA-mwxc-m426-3f78 tests `name.includes('../')` on the raw tar entry name — `./..` and `..` miss it, `path.join` normalizes to the parent directory, and the `fs.WriteStream` opened on a directory with **no `error` listener** crashes the whole Node process (unhandled `'error'` event). Precondition: any account that can import. Durable rules: (a) **guard-the-joined-path, never guard-the-raw-segment** — the spelling matrix for traversal guards is `../`, `./..`, `..`, `a/./..`, URL-encodings, and each guard implementation gets all of them; (b) this fix's own guard is the second substring-layer miss in the same wave (cf. the Azure SAS inheritance above — layer the security check where the sink consumes the value, not where the string is produced); (c) **missing stream `error` handlers turn any EISDIR/EACCES into a full process kill** — unhandled-error crashers in Node import/export paths are free availability proofs for a lab-authenticated account.

**14. Role checks applied per-subject-class, and "the public" was left out** — [GHSA-xf6w-q65w-4f2w / CVE-2026-113653, `apostrophe`](https://github.com/advisories/GHSA-xf6w-q65w-4f2w) (fixed 4.33.0). `viewRole` is correctly applied to guests/contributors but **not to the general public**, so a piece with a relationship to `@apostrophecms/user` renders user objects to anonymous visitors through any exposed REST or JSON-serialized template path. Durable rule: when a product's authorization model enumerates subject classes (`guest`, `contributor`, `editor`, ...), **test the unauthenticated request as its own subject** — role/visibility enforcement written per-class routinely omits the anonymous default; pair with the wave's `.permission(false)` leg (§1): same product, two independent ways the "public" subject escapes the read-restriction model.

**15. sanitize-html SMIL protection bypassed by namespace-prefixed tag names** — [GHSA-374f-7chj-9948 / CVE-2026-113657](https://github.com/advisories/GHSA-374f-7chj-9948) (fixed 2.18.0, same sanitizer as §4/§5). The 2.17.7 `animatesUrlAttribute()` block matches animation tag names (`animate`, `set`, ...) against a bare-local-name list — but htmlparser2 passes `svg:animate` verbatim, so **any namespace prefix** (`svg:`, `xlink:`, `xml:`, uppercase) walks past the tag lookup while the browser still parses it as SMIL, retargeting a parent `<a>` `href` to `javascript:` after load. The killer detail: the same function *does* strip the prefix for the `attributeName` target value — the fix author fixed one of the two lookups. Durable rule: **deny-list lookups must normalize the same way the parser/serializer does on every field they touch**; when auditing a sanitizer fix, feed the namespace-prefixed spelling of every blocked tag/attribute the guard enumerates (this is the iteration-structure/normalization mismatch class from the Oct 6 Coraza and Oct 20 projection legs, spelled in XML-namespace grammar), and remember SMIL retargeting as a click-armed XSS sink when `allowedTags: false` preserves SVG.

## Validation boundaries

- Run all sanitizer/projection probes in local harnesses with synthetic content; parse sanitizer output into detached DOM/AST recorders, never a production browser.
- The prototype-deletion and disk-exhaustion legs are destructive — lab instances only, never shared hosts; proof is a canary marker (deleted `__pocMarker` member, `df` delta), not real capacity loss.
- Session-token and SSRF legs: owned redirect/callback infrastructure, lab accounts, redacted tokens; never target cloud metadata on customer production without explicit written scope.
- `sanitize-html` and `@apostrophecms/db-connect` are transitive dependencies across a large npm ecosystem — inventory grep (`sanitize-html`, `db-connect`, `apostrophe`) is the recon first step wherever Node CMS/low-code stacks are in scope.

## Sources

- GitHub Advisory Database: [CVE-2026-113670](https://github.com/advisories/GHSA-2j32-q6rx-h844), [CVE-2026-113668](https://github.com/advisories/GHSA-gqh3-7856-rjjg), [CVE-2026-113666](https://github.com/advisories/GHSA-j5rq-xfvr-p969), [CVE-2026-113654](https://github.com/advisories/GHSA-x3q4-9hxx-gx8m), [CVE-2026-113661](https://github.com/advisories/GHSA-cv27-6wvh-8x7j), [CVE-2026-113671](https://github.com/advisories/GHSA-527g-ff96-x6wj), [CVE-2026-113669](https://github.com/advisories/GHSA-hhvr-8m24-qqr3), [CVE-2026-113655](https://github.com/advisories/GHSA-2jrp-qc93-h2j8), [CVE-2026-113658](https://github.com/advisories/GHSA-qhcq-9pm2-c9w9), [CVE-2026-113656](https://github.com/advisories/GHSA-89mh-mm8c-mv7f), [CVE-2026-113667](https://github.com/advisories/GHSA-44qr-rrjg-2cqq), [GHSA-m2m5-rw3w-cwmj](https://github.com/advisories/GHSA-m2m5-rw3w-cwmj), [GHSA-653j-g8j7-gh54](https://github.com/advisories/GHSA-653j-g8j7-gh54), [GHSA-hhph-8536-gfq5](https://github.com/advisories/GHSA-hhph-8536-gfq5), [GHSA-97wv-p4xx-c7mg](https://github.com/advisories/GHSA-97wv-p4xx-c7mg), [GHSA-xf6w-q65w-4f2w](https://github.com/advisories/GHSA-xf6w-q65w-4f2w), [GHSA-374f-7chj-9948](https://github.com/advisories/GHSA-374f-7chj-9948), [GHSA-vwwx-px9w-crrc](https://github.com/advisories/GHSA-vwwx-px9w-crrc), [GHSA-gmfx-5g6x-rr72](https://github.com/advisories/GHSA-gmfx-5g6x-rr72)
- Related wiki pages: [Apostrophe host-header password-reset boundary](2026-05-19-apostrophe-host-header-password-reset-boundary-ghsa-gf43-24g3-5hw2.md), [Template/CMS/token/model/proxy boundaries (sanitize-html 53606 + pretty-URL fetch)](2026-07-31-template-cms-token-model-proxy-boundaries-ghsa.md), [Apostrophe SEO stored XSS](2026-04-30-apostrophecms-seo-fields-stored-xss-ghsa-855c-r2vq-c292.md)
