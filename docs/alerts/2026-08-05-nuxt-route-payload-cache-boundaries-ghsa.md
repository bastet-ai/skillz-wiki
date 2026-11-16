---
title: Nuxt route-rule and SSR payload-cache authority boundaries
---

# Nuxt route-rule and SSR payload-cache authority boundaries

Two reviewed Nuxt advisories expose the same durable testing rule: authorization must be evaluated on the exact normalized route and for the current request, not inherited from a mismatched route-rule key or a prior user's shared payload-cache entry.

Primary sources:

- shared SSR payload cache disclosure: [GHSA-wm8w-6qjm-cv43](https://github.com/advisories/GHSA-wm8w-6qjm-cv43), affecting Nuxt `4.4.0` through `4.5.0` and fixed in `4.5.1`; and
- mixed-case route-rule bypass: [GHSA-hxvh-4h3w-prp9](https://github.com/advisories/GHSA-hxvh-4h3w-prp9), affecting Nuxt `4.4.7` through `4.5.0` and `3.21.7` through `3.21.9`, fixed in `4.5.1` and `3.21.10` respectively.

!!! warning "Two-user synthetic fixtures only"
    Use a local disposable Nuxt application, two fake users or tenants, random non-secret markers, and patched data-return sinks. Never request production payloads, collect cookies or bearer tokens, test another customer's route, or seed real profile, billing, token, or tenant data into SSR state.

## 1. Inventory the full route-to-payload surface

For each page protected by middleware or a page guard, record:

- source filename and configured route-rule key;
- router case-sensitivity setting;
- requested raw path, normalized path, and matched page;
- `cache`, `swr`, or `isr` route-rule state;
- whether runtime payload extraction exposes `/<page>/_payload.json`;
- middleware and page-guard decisions for the HTML request and payload request separately;
- payload cache namespace and effective key dimensions; and
- the identity or tenant that generated the cached value.

Do not assume the HTML response and extracted payload use the same authorization or cache path. Test them as distinct resources.

## 2. Test symmetric route normalization

The route-rule regression lowercased lookup paths while leaving mixed-case compiled keys unchanged. Vue Router could still resolve the page case-insensitively, but Nuxt could omit the rule and its `appMiddleware` gate.

Create synthetic pages and rules covering lowercase, PascalCase, camelCase, wildcard, and nested route keys. Exercise exact-case and case-variant requests while recording both router and route-rule matcher output:

| Route-rule key | Request variants | Required invariant |
| --- | --- | --- |
| `/admin` | `/admin`, `/Admin`, `/ADMIN` | either all variants resolve and receive the same rule, or disallowed variants do not route |
| `/Admin/dashboard` | exact, lower, upper, mixed | key and lookup use the same normalization policy |
| `/Dashboard/**` | nested exact and case variants | wildcard expansion cannot drop `appMiddleware` |
| page-derived mixed-case key | direct navigation and payload URL | derived rule remains attached to the page selected by the router |

Patch the protected handler to return only `AUTH-CANARY-<uuid>` after recording the middleware decision. A bounded positive is **router resolves the protected page -> route-rule matcher omits the mixed-case key -> auth middleware does not run -> no-op protected handler is reached**. Do not expose account data or perform a privileged action.

Include `router.options.sensitive: true` as a control. When case-sensitive routing is intentional, both key compilation and lookup must preserve case and nonmatching variants must fail at routing rather than silently losing policy.

## 3. Test cache identity and authorization order

For the payload-cache issue, create one cached protected page whose `useAsyncData` or `useFetch` result contains only a random marker derived from the current synthetic user. Use user A to warm the page, then request both the HTML route and `/<page>/_payload.json` as:

1. user A;
2. unauthenticated client;
3. user B in the same tenant;
4. user B in a different tenant; and
5. user A after logout or permission revocation.

Capture cookie/header presence as booleans or hashes, never raw credentials. Record route middleware and page-guard invocation counts, cache lookup timing, cache key, hit/miss, marker origin, response status, and marker hash.

A bounded positive is **user A warms protected cached route -> later payload request returns A's marker from a path-only runtime cache before current-request middleware or guards run**. The HTML response remaining protected is an important differential, not a negative result.

Repeat across `cache`, `swr`, and `isr`, and include:

- uncached route control;
- public cached route control containing only globally public data;
- route with explicit `cache.varies` dimensions;
- payload request with no prior HTML navigation;
- cold and warm server processes; and
- affected-versus-fixed Nuxt versions.

The secure outcome is current-request authorization before payload return. For private state, either avoid shared runtime payload caching or bind every cache entry to all identity and tenant dimensions that affect the result.

## 4. Chain the two boundaries without retrieving data

A useful regression fixture combines a mixed-case protected route with payload extraction:

1. configure a mixed-case page and `appMiddleware` rule;
2. warm its cache with user A's random marker;
3. request exact-case and case-variant HTML and payload paths as no-user and user B;
4. record router match, rule match, middleware execution, cache lookup, and response-marker hash; and
5. deny any serializer output other than the known marker.

This distinguishes two independent failures:

- **policy attachment failure**: the router selects a page but normalization causes its route rule to disappear; and
- **policy replay failure**: a cached payload is returned without re-running authorization for the current request.

Do not collapse them into a generic “auth bypass.” Report which transition failed and whether the proof reached a protected handler, a foreign marker, or both.

## Evidence template

```text
Nuxt version and deployment mode:
Router case-sensitivity:
Configured route-rule key:
Raw / normalized / matched path:
HTML or _payload.json request:
cache / swr / isr configuration:
Current synthetic principal and tenant:
Route middleware / page guard invocation:
Cache namespace, redacted key, hit or miss:
Marker creator and returned marker hash:
Affected-versus-fixed result:
Strongest bounded claim:
Excluded data-access or action claims:
```

Keep response bodies to random markers. A cache hit, route match, or skipped hook alone is not proof of cross-user disclosure; bind the current principal, marker creator, cache decision, and returned marker in one trace.

## August 5 follow-up: server-island component and DevTools RPC authority

Three later reviewed records add two distinct Nuxt control planes:

| Advisory | Boundary | Affected / fixed range |
| --- | --- | --- |
| [GHSA-9473-5f9j-94wq](https://github.com/advisories/GHSA-9473-5f9j-94wq) | request-supplied server-island props reach Vue dynamic-component resolution and, when `vue.runtimeCompiler: true`, an attacker-supplied template can reach the Nitro server-side compiler | Nuxt `3.4.0` through `3.21.9` and `4.0.0` through `4.5.0`; fixed in `3.21.10` and `4.5.1` |
| [GHSA-48hr-524c-v5w3](https://github.com/advisories/GHSA-48hr-524c-v5w3) | a plain string in a forwarded island prop can instantiate a globally registered component or native element without requiring the runtime compiler | Nuxt `3.1.0` through `3.21.9` and `4.0.0` through `4.5.0`; fixed in `3.21.10` and `4.5.1` |
| [GHSA-279x-mwfv-vcqv](https://github.com/advisories/GHSA-279x-mwfv-vcqv) | an unauthenticated Vite HMR RPC client can change the persisted editor command and then reach `openInEditor()` on a developer host | `@nuxt/devtools < 3.3.1`; fixed in `3.3.1` |

!!! warning "Instrument compilers, constructors, and process launchers"
    Use a disposable Nuxt project, harmless test components, inert template and element markers, a patched Vue compiler/component resolver, and a denied process-spawn recorder. Never compile attacker code, launch an editor or command, expose a developer's real HMR listener, inspect source files, or use a component whose setup performs network, filesystem, credential, or database operations.

### Server-island prop-to-component matrix

Inventory every server island that forwards caller-controlled values into `<component :is>`, `resolveDynamicComponent()`, `h()`, or a polymorphic `as`/`asChild` prop. Record whether `vue.runtimeCompiler` is active in the server and client bundles and enumerate globally registered components by name only; do not invoke unknown components.

Build a synthetic island whose only allowed target is `SafeCard`. Patch the component resolver and runtime compiler so they log their inputs and return inert placeholders. Exercise:

- the expected `SafeCard` identifier;
- an unknown component string;
- the name of a harmless globally registered canary component;
- native-element strings such as an inert `div` and blocked network-capable element classes; and
- an object containing a `template` key, with runtime compilation disabled and enabled.

Capture raw props, schema decision, resolved target kind, compiler invocation count, and placeholder output. The two positives are different:

- **component authority expansion**: a caller-controlled string resolves a global component or native element outside the island's explicit allowlist; and
- **compiler authority expansion**: a caller-controlled object reaches the server runtime compiler when runtime compilation is enabled.

Do not claim server code execution from component selection alone. For the compiler path, stop at the patched compiler receiving the inert marker; do not run generated render functions. Test affected and fixed releases with the same fixture and include direct, encoded, nested, array, and alternate forwarded-prop shapes so validation cannot be bypassed by moving the value one level deeper.

### DevTools WebSocket RPC matrix

Treat Nuxt DevTools as a developer-host control plane, not as an ordinary browser debugging widget:

1. Start a disposable affected Nuxt development server in a container or VM with no repository credentials and bind HMR only to the lab interface.
2. Replace `launch-editor` or the final child-process constructor with a recorder that logs redacted argv and always denies execution.
3. From an owned second client, connect to the Vite HMR WebSocket using the `vite-hmr` subprotocol and record whether the `nuxt:devtools:rpc` channel requires a token or validates `Origin` before accepting calls.
4. Invoke only an ordinary read-only RPC baseline, then attempt `updateOptions`, `clearOptions`, and `openInEditor` with an inert command-name marker and a known synthetic file path.
5. Record RPC identity, origin, auth decision, persisted option transition, method result, and denied spawn argv. Repeat on `@nuxt/devtools 3.3.1+` and with remote HMR exposure removed.

A bounded positive is **unauthenticated client reaches the DevTools RPC channel -> changes the editor-command option -> `openInEditor` sends the inert marker to the denied process-launch sink**. WebSocket reachability or option mutation alone is not command execution. Keep the exact command-bearing RPC body out of public evidence.

### August 7 DevTools workspace metadata and peer-identity follow-up

[GHSA-7c4v-fwgw-9rf7](https://github.com/advisories/GHSA-7c4v-fwgw-9rf7) covers Nuxt `4.4.7` through `4.5.0` and `3.21.7` through `3.21.9`, fixed in `4.5.1` and `3.21.10`. When a development server is reachable beyond loopback and default-enabled `experimental.chromeDevtoolsProjectSettings` is active, the Chrome DevTools workspace endpoint can return the absolute project root and persistent workspace UUID. The reported local-request gate trusted missing browser metadata plus a caller-selected `Host`; the fix also binds the decision to the connected TCP peer being loopback.

Add this as a bounded recon check beside the RPC matrix:

1. Run the disposable dev server on a lab interface with a synthetic project path and UUID. Send requests from loopback and a second lab network namespace.
2. Vary `Host`, `Origin`, `Referer`, and `Sec-Fetch-Site` independently, including their absence. Capture the connected peer address from the socket separately from every request header.
3. Request only `/.well-known/appspecific/com.chrome.devtools.json`; record status and whether the two synthetic metadata fields are present. Do not use a disclosed path to request source files or feed a real editor/HMR action.
4. Compare the feature enabled/disabled, loopback/non-loopback bind and peer, affected/fixed Nuxt, and production build controls.

The bounded positive is **non-loopback peer -> forged or absent request metadata is classified as local -> workspace endpoint returns only the synthetic root/UUID marker**. This is metadata disclosure, not file read, write, or execution. Keep any possible chain to the separate HMR RPC finding hypothetical unless the same authorized lab independently reaches its denied process sink.

### Follow-up evidence fields

```text
Nuxt / @nuxt/devtools version:
Development or production mode:
Server-island component and forwarded prop:
vue.runtimeCompiler server/client state:
Raw prop and schema/allowlist decision:
Resolved component or native-element kind:
Runtime-compiler recorder invocation:
HMR bind address and WebSocket Origin:
RPC authentication / origin decision:
Persisted editor-option transition:
Denied process argv recorder:
Connected peer / request-header localness decision:
Workspace metadata endpoint result:
Affected-versus-fixed result:
Strongest bounded claim and excluded execution claims:
```

## November 16 follow-up: `%2F` route-rule bypass (incomplete fix), island-prop hash collision, and SSR error payload leakage (3 GHSAs, Nuxt < 4.6.4)

The 14:59-15:02Z Nuxt batch re-attacks both boundaries this page exists for, plus one new disclosure leg:

- **Encoded-slash route-rule bypass on catch-all pages** ([GHSA-f3x9-2chm-73c8](https://github.com/advisories/GHSA-f3x9-2chm-73c8) / CVE-2026-128071, medium, < 4.6.4): route rules are matched against the path with `%2F` still encoded, while the page router decodes it into the catch-all param. `/admin%2Fsecret` renders the `[...slug].vue` page while the `/admin/**` redirect, `appMiddleware`, `headers`, `proxy`, `ssr`, and `noScripts` rules never fire. The prior fix (GHSA-6gq8-jgmh-3ffp) deliberately left reserved escapes encoded, so it never covered this shape. Durable axes: (1) the **encoded-separator battery belongs on every route-rule/middleware gate you meet**, `%2F`, `%5C`, double-encode, plus the case-variant battery this page already ships (same family as the Oct 28 LabStack `%2F` middleware bypass and the Nov 10 Rack dot-segment mismatch); (2) **incomplete-fix tell**: when an advisory names a predecessor CVE, fuzz the normalizations the fix intentionally preserved, the fix's design decision is the bypass inventory; (3) decision-table probe: request the protected path in each spelling, record matched page, rules applied, and whether the page's param handling (`slug.join('/')` vs segment array) still enforces its own authz, pages that re-check inside the component may survive, pages that trusted the rule do not.
- **Island prop hash collision via `ohash` serialization ambiguity** ([GHSA-hf59-9xwc-2g4p](https://github.com/advisories/GHSA-hf59-9xwc-2g4p) / CVE-2026-128076, low, incomplete fix for CVE-2026-46342): the `/__nuxt_island/<Name>_<hash>.json` binding hashes `(name, props, context, source)` over `ohash` serialization, which does not escape quotes in strings or delimiters in keys, so two different prop objects collide on one path. Crafted props pass validation for another island's path. Impact rides the **path-keyed cache** layer: prerender crawler priming writes the colliding response into the generated page, and any CDN/reverse proxy caching `/__nuxt_island/*` by path only (ignoring query) serves the primed response. Operator rule: **any hash-based binding built by a serializer that treats structural characters as data is collision surface**; test with quote/delimiter-shifted prop pairs where you control at least one prop string (stored comment/profile field shapes), then verify whether the serving cache keys on path only. Same canonicalization-differential doctrine as this page's payload-cache section: the hash input normalization and the cache key are two different representations to compare.
- **Unhandled SSR errors leak `message` and `data` to the client** ([GHSA-96x6-fvhx-49hg](https://github.com/advisories/GHSA-96x6-fvhx-49hg) / CVE-2026-128075, medium, < 4.6.4): non-HTTP errors thrown during server rendering are wrapped as deliberate app errors, so in production their `message` and `data` ship in `__NUXT_DATA__` and JSON error responses; a failing `$fetch` exposes the requested URL **including its query string** (tokens in query params) plus the upstream error body. Recon value: force render exceptions (garbage params, malformed shapes) on any Nuxt SSR target and grep error payloads for upstream URLs, internal hostnames, and query-string credentials; treat every surfaced upstream error body as a blind-callback oracle for what the server can reach.
- Tracked from the same batch, no new axis: payload-URL quadratic slash DoS (r9jc/128074, ReDoS-in-path class), dev-server DNS-rebinding source disclosure (x2wv/128072, DNS-rebinding class already covered across this wiki's dev-server pages).
