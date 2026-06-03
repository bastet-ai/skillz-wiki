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
