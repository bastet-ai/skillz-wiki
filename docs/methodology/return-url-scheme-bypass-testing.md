---
title: Return URL scheme-bypass testing
---

# Return URL scheme-bypass testing

Return/continue/back URL parameters are small, high-value targets because they often cross three contexts: request input, session storage, and final HTML rendering. A filter that removes tags is not enough when the sink is an `href`, redirect, or post-login navigation target.

Use this playbook during authorized web testing when an app accepts `returnUrl`, `next`, `continue`, `redirect`, `back`, `return_to`, `destination`, or `url`-like parameters.

## Operator signal

Craft CMS [GHSA-fvwq-45qv-xvhv / CVE-2026-31859](https://github.com/advisories/GHSA-fvwq-45qv-xvhv) is the pattern to remember: a previous fix sanitized return URLs with PHP `strip_tags()`, but `strip_tags()` only removes HTML tags. It does not reject executable URL schemes, `data:` documents, or protocol-relative off-origin URLs before the value is stored and rendered into an `href`.

CakePHP Authentication [GHSA-hhpq-7wg4-36jm / CVE-2026-55590](https://github.com/advisories/GHSA-hhpq-7wg4-36jm) adds the adjacent open-redirect pattern: post-login redirect helpers that try to allow only local targets can still be bypassed with backslash-normalization quirks if they validate before converting `\` into URL path separators.

Gogs [GHSA-xxhq-69mf-w8cr / CVE-2026-52802](https://github.com/advisories/GHSA-xxhq-69mf-w8cr) is the same bug class in a Git forge: `redirect_to` values such as `/a/../\example.com` passed a leading-slash same-site check, then browser normalization turned the destination into a protocol-relative off-origin URL.

The reusable lesson is broader than any one framework: URL sinks need URL parsing, canonicalization, and origin decisions made in the same representation the browser or redirect client will follow.

## Preconditions

- You have explicit permission to test the application.
- The app accepts a user-controlled navigation target and later uses it in one of these sinks:
  - `Location` redirect
  - HTML `href` / `src` attribute
  - JavaScript navigation assignment
  - login/logout/session timeout “return” link
- You can observe the rendered page, response headers, or browser navigation without targeting real users.

## Recon checklist

Search request and client-side routes for navigation parameters:

```text
returnUrl
return_url
returnTo
return_to
next
continue
redirect
redirect_uri
back
destination
url
ref
referer
```

Prioritize flows that store the value across a session boundary:

- login required → unauthenticated request supplies return target → post-login link or redirect uses it
- forced reauthentication → original destination stored in session → “continue” link renders it
- logout/session-expired pages → `returnUrl` controls a visible anchor
- control-panel/admin CMS paths where XSS impact includes privileged actions

## Safe probe set

Use harmless marker payloads first and confirm where the value lands.

```text
/expected/local/path?bastet_marker=1
//example.invalid/bastet-marker
/\\example.invalid/bastet-marker
\\example.invalid\bastet-marker
javascript:alert(1)
data:text/html,bastet-marker
%2f%2fexample.invalid%2fbastet-marker
%5c%5cexample.invalid%5cbastet-marker
JaVaScRiPt:alert(1)
%6a%61%76%61%73%63%72%69%70%74:alert(1)
```

Do not send payloads that steal cookies, make privileged changes, or call external collection endpoints unless the rules of engagement explicitly allow it. For most reports, proving that an executable scheme or off-origin target survives into the sink is enough.

## Validation workflow

1. **Find the setter.** Send a navigation request with a unique marker in the candidate parameter.
2. **Trace persistence.** Check whether the marker survives across login, logout, session timeout, or an error page.
3. **Identify the sink.** Capture whether the value appears in:
   - response `Location`
   - an anchor such as `<a href="...">Continue</a>`
   - inline JavaScript
   - a client-side router state blob
4. **Classify the bug.**
   - `javascript:` / `data:` in `href` → reflected or stored-in-session XSS, depending on persistence
   - protocol-relative `//host` or absolute foreign origin → open redirect / phishing aid
   - backslash or encoded separator accepted before normalization → parser-differential open redirect
   - encoded scheme accepted after decode → canonicalization bypass
   - mixed-case scheme accepted → case-normalization miss
5. **Prove with minimum impact.** Use a benign `alert(1)` or visible DOM marker in a lab account, and record the request, response, rendered DOM, and click/navigation result.

### Concourse post-login double-decode redirect update

- Test only your own lab or explicitly authorized Concourse web endpoint and account. Do not send crafted login links to other users.
- Seed the login flow with a harmless owned destination such as `/sky/login?redirect_uri=/%252Fexample.invalid/\` and complete login in your own browser session.
- Positive evidence is the final `Location` or browser navigation resolving to the off-origin canary host after authentication, while a normal local `redirect_uri` remains on the Concourse origin.
- Capture the raw parameter, server response chain, browser-normalized destination, Concourse version, and patched negative control. Do not claim credential theft: the advisory notes the redirect happens after login completes and no credentials are leaked by the redirect alone.

## What to report

A strong bug-bounty report should include:

- vulnerable parameter and route
- exact affected version or build if known
- the context where the value is rendered or redirected
- whether the value is one-shot, session-persistent, or account-persistent
- minimal payload used for proof
- screenshot or HAR showing the value reaching the sink
- impact scoped to the actual user context, such as admin-session XSS, account action CSRF assist, or trusted-origin phishing

## Heuristics that catch weak fixes

Flag fixes that rely only on string stripping or HTML cleanup:

```text
strip_tags(...)
replace("<", "") / replace(">", "")
escapeHtml(returnUrl) before placing the value in href
blacklist("javascript:") without canonicalization
startsWith("/") without rejecting "//"
allowing encoded slashes or backslashes before normalization
checking for a leading slash before replacing "\\" with "/"
```

Useful regression cases:

```text
//example.invalid/path
///example.invalid/path
/\\example.invalid\\path
\\example.invalid\path
%2f%2fexample.invalid%2fpath
%5c%5cexample.invalid%5cpath
javascript:alert(1)
java%0d%0ascript:alert(1)
 data:text/html,bastet
https://allowed.example.invalid.evil.example/
https://allowed.example.invalid@evil.example/
```

## Safe boundaries

- Keep testing in accounts and environments covered by authorization.
- Prefer `example.invalid` and visible markers over live attacker infrastructure.
- Stop at proof of controllable navigation or script execution unless the program explicitly permits deeper impact demonstration.
- Never test against real users; use your own browser session and lab account.

## Sources

- [GitHub Advisory Database: Craft CMS GHSA-fvwq-45qv-xvhv / CVE-2026-31859](https://github.com/advisories/GHSA-fvwq-45qv-xvhv)
- [Craft CMS fix commit](https://github.com/craftcms/cms/commit/cc9921c14897ee2b592a431c2356af8a04ce4cfe)
- [GitHub Advisory Database: CakePHP Authentication GHSA-hhpq-7wg4-36jm / CVE-2026-55590](https://github.com/advisories/GHSA-hhpq-7wg4-36jm)
- [GitHub Advisory Database: Gogs GHSA-xxhq-69mf-w8cr / CVE-2026-52802](https://github.com/advisories/GHSA-xxhq-69mf-w8cr)
- [GitHub Advisory Database: Concourse GHSA-8w27-c4vc-88q9 / CVE-2026-49826](https://github.com/advisories/GHSA-8w27-c4vc-88q9)
