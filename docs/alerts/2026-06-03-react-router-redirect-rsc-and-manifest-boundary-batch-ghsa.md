# React Router redirect, RSC, manifest, and deserialization boundaries

**Sources:** [GHSA-49rj-9fvp-4h2h / CVE-2026-42211](https://github.com/advisories/GHSA-49rj-9fvp-4h2h), [GHSA-8646-j5j9-6r62 / CVE-2026-33245](https://github.com/advisories/GHSA-8646-j5j9-6r62), [GHSA-f22v-gfqf-p8f3 / CVE-2026-33244](https://github.com/advisories/GHSA-f22v-gfqf-p8f3), [GHSA-2j2x-hqr9-3h42 / CVE-2026-40181](https://github.com/advisories/GHSA-2j2x-hqr9-3h42), [GHSA-8x6r-g9mw-2r78 / CVE-2026-42342](https://github.com/advisories/GHSA-8x6r-g9mw-2r78)  
**Affected packages:** npm `react-router` v7 Framework Mode ranges called out by the advisories; `react-router` v6.7.0-6.30.3 for the `redirect()` protocol-relative URL issue; `@remix-run/server-runtime` v2.10.0-2.17.4 for the `__manifest` resource issue.  
**Operator value:** source-assisted validation of framework-mode redirect sinks, pre-render output, RSC redirect handling, manifest resource amplification, and prototype-pollution-to-deserialization reachability.

## Why this matters

GitHub published a cluster of React Router advisories on June 3, 2026. The durable lesson for operators is not only "upgrade React Router"; it is that framework routing helpers can turn small boundary mistakes into higher-impact web findings when untrusted input reaches redirect helpers, pre-rendered redirect HTML, RSC redirect handling, or serialized server data.

Prioritize authorized targets where React Router or Remix is server-side reachable rather than static client-only routing:

- React Router v7 **Framework Mode** applications;
- Remix applications using `@remix-run/server-runtime` in the affected range;
- applications with route loaders/actions that call `redirect()` using request-controlled path or URL material;
- pre-rendered route output where redirects are represented as generated HTML;
- experimental or unstable React Server Components paths;
- codebases with a known or suspected prototype pollution primitive plus React Router v7 Framework Mode server rendering.

The advisories explicitly state that several issues do not affect purely Declarative Mode (`<BrowserRouter>`) or Data Mode (`createBrowserRouter` / `<RouterProvider>`) applications. Treat routing mode and server reachability as first-class triage evidence.

## Advisory-to-boundary map

| Boundary | Advisory | Affected surface | What to validate |
| --- | --- | --- | --- |
| Deserialization after prototype pollution | [GHSA-49rj-9fvp-4h2h](https://github.com/advisories/GHSA-49rj-9fvp-4h2h) | React Router v7 Framework Mode | Whether a separate prototype pollution primitive can influence data later deserialized by the vendored `turbo-stream` path. |
| RSC redirect XSS | [GHSA-8646-j5j9-6r62](https://github.com/advisories/GHSA-8646-j5j9-6r62) | React Router v7 unstable RSC APIs | Whether untrusted redirect targets can reach RSC redirect handling, especially `javascript:` style targets. |
| Pre-rendered redirect HTML XSS | [GHSA-f22v-gfqf-p8f3](https://github.com/advisories/GHSA-f22v-gfqf-p8f3) | React Router v7 Framework Mode with pre-rendering | Whether untrusted `Location` values are embedded unescaped in generated redirect HTML. |
| Protocol-relative open redirect | [GHSA-2j2x-hqr9-3h42](https://github.com/advisories/GHSA-2j2x-hqr9-3h42) | React Router v6/v7 `redirect()` | Whether validation treats `//attacker.example/path` as same-origin path material before browser reinterpretation. |
| `__manifest` path expansion resource issue | [GHSA-8x6r-g9mw-2r78](https://github.com/advisories/GHSA-8x6r-g9mw-2r78) | React Router Framework Mode and Remix v2.10.0-2.17.4 | Whether crafted manifest requests create disproportionate server work. Validate only with owner-approved rate and volume limits. |

## Recon workflow

### 1. Identify package and routing mode

Use source review first. In a target-owned repo or authorized assessment bundle:

```bash
# Package reachability.
grep -R '"react-router"\|"@remix-run/server-runtime"' -n package.json package-lock.json pnpm-lock.yaml yarn.lock 2>/dev/null
npm ls react-router @remix-run/server-runtime --depth=4 2>/dev/null

# Server/framework-mode and route entry points.
grep -R 'from "react-router"\|from "@remix-run' -n app src routes server 2>/dev/null
grep -R 'redirect(\|unstable_\|prerender\|__manifest' -n app src routes server vite.config.* react-router.config.* 2>/dev/null
```

Record the exact dependency version, whether the app is server-rendered, and which mode is in use. Do not report an advisory match from a lockfile alone.

### 2. Trace redirect sinks

For each loader/action or server route using `redirect()`:

- identify the source of the target string (`next`, `returnTo`, `redirect_uri`, path parameter, header, cookie, form field);
- note whether validation uses URL parsing, origin checks, path-prefix checks, or string-only checks;
- test canonical edge cases in a lab or approved test tenant:
  - `//example.invalid/rr-open-redirect-canary`
  - `/\\example.invalid/rr-backslash-canary`
  - percent-encoded protocol-relative variants only if the owner permits encoded bypass testing.

A strong open-redirect finding needs a browser-observable redirect to an attacker-controlled origin or a downstream security consequence such as OAuth/state token leakage. Keep canary domains inert and under your control.

### 3. Validate pre-rendered redirect HTML safely

If pre-rendering is enabled, build a local copy or use an approved staging environment. Look for generated HTML files that represent redirect responses and inspect whether the `Location` value is HTML-escaped and JavaScript-context-safe.

```bash
npm run build
find . -type f \( -path '*dist*' -o -path '*build*' -o -path '*public*' \) -name '*.html' -print | xargs grep -n 'Location\|redirect\|javascript:' 2>/dev/null
```

Use non-executing canaries where possible, such as `javascript:alert('rr-canary')` only in an isolated browser profile or local static build. Do not inject payloads into production content unless the program explicitly allows XSS proof-of-concept execution.

### 4. Check unstable RSC redirect paths

RSC exposure is narrower. Confirm it before testing:

```bash
grep -R 'unstable_.*RSC\|RSCHydratedRouter\|react-server' -n app src routes server 2>/dev/null
```

If unstable RSC APIs are reachable and redirect targets come from user-controlled input, validate with a harmless canary target and capture the redirect serialization path. Avoid credential-bearing sessions during XSS checks.

### 5. Treat deserialization RCE as a chained finding

GHSA-49rj-9fvp-4h2h requires an existing prototype pollution primitive before the React Router deserialization path becomes a remote-code-execution chain. Evidence should therefore show both halves:

1. a reachable prototype pollution source in the application; and
2. a React Router v7 Framework Mode server path that later consumes polluted state through the affected serialized stream handling.

Do not claim unauthenticated RCE from package presence alone. Use inert markers for pollution proof, such as a non-sensitive property canary visible only in a local/staging response. Escalate to command execution only with explicit authorization.

### 6. Handle `__manifest` resource testing conservatively

The manifest issue is useful for exposure mapping, but resource-exhaustion proof can harm shared systems. Prefer:

- source and version evidence;
- a single low-rate request in staging showing the endpoint and route shape;
- local reproduction against a developer build with CPU/memory observation;
- owner-approved load limits if any live validation is required.

Do not run repeated or high-cardinality manifest probes against production.

## July 23 navigation, RSC, and hydration follow-up

GitHub's July 23 wave adds four adjacent checks: [GHSA-wrjc-x8rr-h8h6 / CVE-2026-53669](https://github.com/advisories/GHSA-wrjc-x8rr-h8h6), [GHSA-jjmj-jmhj-qwj2 / CVE-2026-53668](https://github.com/advisories/GHSA-jjmj-jmhj-qwj2), [GHSA-h8fp-f39c-q6mh / CVE-2026-53667](https://github.com/advisories/GHSA-h8fp-f39c-q6mh), and [GHSA-337j-9hxr-rhxg / CVE-2026-53666](https://github.com/advisories/GHSA-337j-9hxr-rhxg).

They extend the original boundary map:

| Boundary | Required reachability | Positive signal | Negative control |
| --- | --- | --- | --- |
| mixed separators | attacker-controlled string reaches `<Link>`, `useNavigate()`, or a redirect location | router and browser disagree whether `\\`, `/\\`, or `\\/` begins an external URL | local `/marker` stays in-origin; React Router `7.18.0+` normalizes mixed separators consistently |
| colon-bearing route | application places attacker-controlled destination into navigation and an open-redirect condition is present | a value intended as a route path gains URL-scheme semantics at the browser sink | ordinary `foo:bar` remains an in-origin path on the fixed build |
| RSC error redirect | unstable RSC APIs are enabled and attacker influence reaches a redirect thrown through the RSC error/render path | unsupported scheme survives into `window.location`, `Location`, or a meta-refresh target | ordinary local and HTTPS redirects still work; `7.18.0+` rejects the unsupported scheme |
| hydration constructor | Framework Mode or Data Mode manual SSR/hydration plus application code lets attacker input overwrite serialized error type metadata | hydration invokes a browser-global constructor selected by serialized `__subType` | Declarative Mode is unaffected; fixed builds reconstruct only supported built-in error types |

### Affected configurations

- **Mixed-separator bypass:** `react-router >= 6.0.0, < 7.18.0`.
- **Colon/open-redirect path:** `react-router-dom 6.30.2-6.30.4` and `react-router 7.9.6-7.12.0`; the advisory identifies `react-router 7.13.0` as the first patched v7 release. Validate the exact maintained line rather than assuming every 6.x build has an available patched package.
- **RSC error redirect:** `react-router >= 7.11.0, < 7.18.0`, only when unstable RSC APIs are used.
- **Hydration constructor:** `react-router >= 6.4.0, < 7.18.0`, only Framework Mode or Data Mode applications doing manual SSR/hydration. Declarative Mode is not affected by the advisory.

### Navigation representation matrix

Search application code for untrusted values flowing into `<Link to={value}>`, `navigate(value)`, `useNavigate()(value)`, `redirect(value)`, or `throw redirect(value)`. Also find wrappers such as `safeRedirect()`, login `next` parameters, CMS navigation fields, and server-provided action results. Record where decoding, slash replacement, route resolution, origin checks, and browser assignment occur.

Use a local target route and an owned second origin. Exercise each sink independently:

| Input class | Example fixture value | Decision to record |
| --- | --- | --- |
| local baseline | `/bastet-local` | remains on the application origin |
| double forward slash | `//owned.invalid/bastet` | consistently treated as external or rejected according to application policy |
| double backslash | `\\\\owned.invalid\\bastet` | not classified as local before browser normalization |
| mixed separators A | `/\\owned.invalid/bastet` | same decision before and after normalization |
| mixed separators B | `\\/owned.invalid/bastet` | same decision before and after normalization |
| relative colon | `bastet:marker` | remains a route path or is rejected; it must not gain scheme semantics after validation |
| dotted colon | `./bastet:marker` | same representation at policy and navigation sinks |
| parent colon | `../bastet:marker` | same representation at policy and navigation sinks |

For each row, capture the raw input, value passed to React Router, router-resolved pathname or absolute URL, final browser URL, and whether the owned second origin received a request. A vulnerable result is a decision mismatch, not merely the presence of unusual separators.

If the authorized lab requires executable-scheme confirmation, use only a visible local marker such as `javascript:document.body.dataset.bastet='1'`. Stop after the dataset change and do not access cookies, storage, DOM content, or network APIs. Do not call the colon case XSS unless script execution is independently observed in the application's actual sink.

The mixed-separator fix centralizes `//host`, `\\host`, `/\\host`, and `\\/host` as protocol-relative candidates, then replaces backslashes before URL parsing or collapses repeated slash/backslash runs for route paths. The colon-path fix makes relative strings such as `foo:bar`, `./foo:bar`, and `../foo:bar` resolve as pathnames instead of preserving them as absolute URLs. Re-run the same matrix on `7.18.0+`.

### Unstable RSC error-redirect replay

This check does not apply to applications that do not use unstable RSC APIs.

In a disposable RSC fixture:

1. create one route that throws a local redirect, one that throws an HTTPS redirect to an owned origin, and one that throws an unsupported-scheme marker such as `about:blank#bastet`;
2. exercise direct render, suspended/lazy render, and client-side RSC error handling separately;
3. capture the response `Location`, generated meta-refresh element, and client navigation event; and
4. repeat on `react-router 7.18.0+`.

Expected secure behavior is that local and policy-approved HTTPS redirects preserve their intended behavior while the unsupported scheme is rejected or omitted from browser navigation. The fix adds protocol validation at the RSC error handler and server render/streaming branches, so testing only a normal loader redirect is not enough.

### Manual SSR hydration constructor replay

All of these preconditions must be demonstrated:

1. the application uses Framework Mode or Data Mode with manual SSR/hydration;
2. serialized route errors reach browser hydration state;
3. application code lets attacker-controlled input overwrite error type fields, rather than only the message; and
4. the affected client bundle invokes React Router's error deserialization path.

The advisory describes the application-layer overwrite requirement as specific and unlikely. Do not infer remote reachability from package presence or from an attacker-controlled error message alone.

In a disposable browser fixture, register a harmless test constructor on `window` that increments a counter and returns an `Error`. Seed the application's normal hydration object with a synthetic route error whose `__type` is `Error` and whose `__subType` names that constructor. Hydrate through the same API and state path used by the application.

| Case | Error metadata | Expected result |
| --- | --- | --- |
| baseline | built-in `TypeError` | normal supported error reconstruction |
| negative | message controlled, subtype server-owned | no attacker-selected constructor |
| reachability test | synthetic subtype reaches hydration | marker counter changes only on affected build |
| fixed control | same state on `7.18.0+` | plain/supported error; marker counter unchanged |
| mode control | Declarative Mode | affected deserializer not reached |

Do not use constructors that fetch URLs, import code, read browser state, or mutate anything beyond the counter. The finding is **attacker-controlled serialized subtype -> `window[subtype]` lookup -> unexpected constructor invocation during hydration**. Outbound traffic is possible according to the advisory, but a counter proves constructor reachability without creating network effects.

The patch removes the undocumented custom Framework Mode error-deserialization path and restricts remaining Data Mode reconstruction to a fixed set of built-in error types. Confirm behavior through the deployed application path rather than by editing a global hydration object the target never exposes to attacker influence.

### Follow-up sources

- [React Router mixed-separator fix PR #15176](https://github.com/remix-run/react-router/pull/15176)
- [React Router colon-path fix PR #14718](https://github.com/remix-run/react-router/pull/14718)
- [React Router RSC protocol-validation fix PR #15177](https://github.com/remix-run/react-router/pull/15177)
- [React Router hydration-error fix PR #15175](https://github.com/remix-run/react-router/pull/15175)
- [React Router 7.18.0 release](https://github.com/remix-run/react-router/releases/tag/react-router%407.18.0)

## Reporting heuristic

Frame reports around the violated boundary, not just the CVE:

- **Expected boundary:** routing helpers must treat user-controlled redirect and route material as untrusted until canonicalized, origin-checked, escaped, and bounded.
- **Observed bypass:** a specific route/action/pre-render/RSC/manifest path accepts a canary input and produces cross-origin redirect, executable redirect HTML, unsafe RSC redirect serialization, disproportionate manifest work, or a prototype-pollution-assisted deserialization path.
- **Impact:** account-flow abuse, phishing-grade open redirect, stored/reflected XSS in generated redirect output, SSRF/resource pressure from manifest expansion, or chained RCE only when a separate prototype pollution primitive is proven.
- **Evidence:** dependency version, routing mode, route source snippet, exact canary request, redacted response headers/body, browser or local build observation, and patched-version or safe-mode control.

## Scope and safety notes

- Keep validation inside authorized scopes, staging tenants, or local builds.
- Do not run volumetric `__manifest` tests on production.
- Do not execute JavaScript in victim sessions or collect tokens while testing redirect/XSS behavior.
- Do not claim React Router RCE unless prototype pollution reachability and the affected deserialization path are both demonstrated under authorization.
