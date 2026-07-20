# Parser, dev-server, HTTP-client, CMS-cache, and RAG boundary checks

Sources: hourly offensive-security scan, 2026-07-20 GitHub Security Advisory feed. Primary entries: protobufjs [GHSA-jfj6-75fj-8934](https://github.com/advisories/GHSA-jfj6-75fj-8934), webpack-dev-server [GHSA-f5vj-f2hx-8m93](https://github.com/advisories/GHSA-f5vj-f2hx-8m93), Guzzle [GHSA-g446-98w2-8p5w](https://github.com/advisories/GHSA-g446-98w2-8p5w), [GHSA-94pj-82f3-465w](https://github.com/advisories/GHSA-94pj-82f3-465w), [GHSA-h95v-h523-3mw8](https://github.com/advisories/GHSA-h95v-h523-3mw8), and [GHSA-wm3w-8rrp-j577](https://github.com/advisories/GHSA-wm3w-8rrp-j577), Directus [GHSA-c6w9-5g5j-jh2p](https://github.com/advisories/GHSA-c6w9-5g5j-jh2p) and [GHSA-j5h6-vqc3-phqh](https://github.com/advisories/GHSA-j5h6-vqc3-phqh), LightRAG [GHSA-f4vv-55c2-5789](https://github.com/advisories/GHSA-f4vv-55c2-5789) and [GHSA-6x6h-qqr7-855w](https://github.com/advisories/GHSA-6x6h-qqr7-855w), and Mistune [GHSA-r4rv-85jg-w4mf](https://github.com/advisories/GHSA-r4rv-85jg-w4mf), [GHSA-g97x-gvcm-x72h](https://github.com/advisories/GHSA-g97x-gvcm-x72h), and [GHSA-8c25-4j27-2rv3](https://github.com/advisories/GHSA-8c25-4j27-2rv3).

This batch exposes reusable integration boundaries: parsed map keys becoming inherited properties, browser pages reaching local developer controls, client state crossing host/proxy authorities, authorization-dependent responses sharing cache keys, URL guards disagreeing with the operating system, documented API-key modes falling through to guest JWT trust, and Markdown directives crossing into files, attributes, and browser URL parsing.

!!! warning "Authorized validation only"
    Use isolated applications, fake credentials, two-user fixtures, owned browser origins and callbacks, synthetic files, and local mock proxies/services. Never collect real cookies, proxy credentials, CMS records, RAG documents, source files, tokens, or localhost service data.

## Boundary map

| Advisory | Preconditions | Durable operator check |
| --- | --- | --- |
| protobufjs GHSA-jfj6-75fj-8934 | `protobufjs/ext/textformat`, attacker-controlled Text Format, string-keyed map, and downstream inherited-property use | Trace a special map key into one returned object's prototype, then prove whether authorization/config logic consumes inherited values. This is per-object mutation, not global `Object.prototype` pollution. |
| webpack-dev-server GHSA-f5vj-f2hx-8m93 | Developer visits an untrusted page while an affected dev server is browser-reachable | Test cross-origin `GET` access to state-changing editor/invalidate endpoints with a harmless project file and rebuild nonce. Opening a file does not disclose its content to the web origin. |
| Guzzle GHSA-g446-98w2-8p5w | Shared `CookieJar` spans authorities and holds an IP-literal or bare-numeric Domain cookie | Compare exact-IP and suffix-lookalike hosts in an owned split-DNS lab; record cookie send/store decisions without real sessions. |
| Guzzle GHSA-94pj-82f3-465w | First-class `Proxy-Authorization` header and cURL/stream routing that becomes direct, no-proxy, SOCKS, or changes on redirect | Capture whether a fake proxy credential reaches the mock origin when route selection differs from header classification. |
| Guzzle GHSA-h95v-h523-3mw8 / GHSA-wm3w-8rrp-j577 | Redirects carry a fragment-bearing source URI or a shared jar stores a host-only cookie without preserving host-only scope | Check whether fake fragment data enters `Referer`, and whether a host-only cookie crosses to an owned subdomain/sibling authority. |
| Directus GHSA-c6w9-5g5j-jh2p | Response cache enabled and active share records | Use two shares plus anonymous traffic to test whether the same URL/query cache entry is segmented by share/role/policy rather than only `user: null`. |
| Directus GHSA-j5h6-vqc3-phqh | Authenticated user can import files from URLs; affected host treats unspecified addresses as loopback | Use a synthetic loopback canary service to compare literal unspecified, loopback, IPv6, and owned redirect forms; never probe real internal services. |
| LightRAG GHSA-f4vv-55c2-5789 | `LIGHTRAG_API_KEY` set and `AUTH_ACCOUNTS` unset | Check whether public auth bootstrap or a known fallback signing configuration yields a guest identity that bypasses the API-key branch. Use only an inert status/list route. |
| LightRAG GHSA-6x6h-qqr7-855w | Browser can attach a credential accepted by the target and arbitrary origins are echoed with credential support | Build a browser decision table for preflight, actual response, credential type, and readable canary response. Do not assume bearer tokens are attached automatically. |
| Mistune GHSA-r4rv-85jg-w4mf | Untrusted Markdown file is processed with `md.read()` and `Include` enabled | Resolve an include only to a synthetic sibling canary outside the document root and compare affected with `3.3.0+`. |
| Mistune GHSA-g97x-gvcm-x72h / GHSA-8c25-4j27-2rv3 | Admonition or Markdown URL reaches HTML output consumed by a browser | Use inert attribute and percent-encoded-scheme markers to compare source text, rendered bytes, parsed DOM, and browser navigation decision. |

## 1. Parser-object and Markdown checks

### protobuf Text Format map prototype

1. Confirm the target imports the optional Text Format extension; binary decode, `fromObject`, and ProtoJSON are not the advisory path.
2. Build a schema with one string-keyed map and parse ordinary and special-key fixtures.
3. Record own keys, `Object.getPrototypeOf(map)`, `Object.hasOwn(map, key)`, direct access, and `key in map`.
4. Feed the parsed object only into a synthetic policy consumer that deliberately contrasts own-property and inherited-property checks.
5. Repeat with protobufjs `8.6.5+`.

Positive evidence is **untrusted Text Format map key -> returned map prototype changes -> a reachable downstream decision consumes the inherited canary**. Prototype change alone is a primitive; report application impact only when the downstream gadget is proven.

### Mistune include and render context

Create a temporary tree containing a Markdown root, an allowed include, and one non-sensitive sibling canary. Process the same directive with an affected release and Mistune `3.3.0+`; record resolved paths and output hashes. Stop after the sibling canary and never target `/etc`, home directories, application source, or environment files.

For rendering, test ordinary values first, then one non-executable `:class:` delimiter canary and one percent-encoded URL-scheme canary. Capture raw HTML and the parsed DOM in a disposable browser page. A strong report distinguishes:

- directive option -> unescaped HTML attribute structure;
- Markdown URL bytes -> renderer's URL decision -> browser's normalized navigation target;
- legacy/custom protocol acceptance from proven execution in the target browser, not from a renderer string alone.

## 2. Browser-to-local developer-control check

Run webpack-dev-server in a disposable project with a harmless source file and a rebuild counter. From an owned second origin, try image/navigation/fetch forms against `/webpack-dev-server/open-editor` and `/webpack-dev-server/invalidate`; record whether the browser sends the request, whether the endpoint acts, and whether JavaScript can read the response.

Use an editor wrapper that logs only the selected canary path rather than launching a real editor. Positive proof is **untrusted web origin -> browser sends cross-origin GET -> local dev endpoint opens the existing canary or increments rebuild state**. Do not claim file disclosure: the advisory action opens an existing local path but does not return its contents to the attacker page. Compare with webpack-dev-server `5.2.6+`.

## 3. Guzzle authority and route matrices

### IP-domain cookie matching

Use one `CookieJar`, fake cookie values, and owned DNS/hosts entries representing an exact IP authority and a suffix-lookalike hostname. Test set and send direction separately for IPv4, bracketed IPv6, and bare-numeric Domain forms. Record cookie domain, origin authority, destination authority, and whether the fake cookie appears. Guzzle `7.12.3+` should require exact matching for these domain forms.

Report **cookie Domain parsed as IP/numeric -> suffix matching applied -> shared jar crosses host authority**. Public DNS exploitability is not implied; document split-horizon, container, or development name-resolution control.

### Proxy credential routing

Use a fake `Proxy-Authorization` value, one mock HTTP proxy, two owned origins, and no external egress. Exercise direct, ordinary HTTP proxy, `NO_PROXY`, SOCKS, and redirect-to-direct cases across the cURL and stream handlers used by the target. Capture headers independently at proxy and origin.

Positive evidence is **first-class proxy credential -> Guzzle predicts one route/header channel -> libcurl or stream handler takes another route -> origin receives the fake credential**. Guzzle does not invent this header, so confirm application reachability. Compare with `7.14.2+` and redact even fake values in shared screenshots to preserve evidence habits.

### Redirect-fragment and host-only cookie checks

Use two owned HTTP origins, one subdomain, a shared `CookieJar`, and fake marker values. For redirects, place a canary only in the initial URI fragment and have the second origin record `Referer`; browsers do not normally send fragments, so positive evidence is **source URI fragment -> generated redirect Referer -> owned destination receives canary**. For cookies, set one cookie without `Domain`, then request the origin, subdomain, and sibling authority; positive evidence is **host-only Set-Cookie -> jar loses host-only provenance -> cookie sent outside the exact origin host**. Hold scheme, port, path, and redirect policy constant, and compare fixed releases. Never use real reset links, OAuth fragments, sessions, or third-party destinations.

## 4. Directus cache and final-destination checks

### Share-cache segmentation

Enable caching only in a disposable Directus instance. Create Share A and Share B with different roles/scoped synthetic records, plus an anonymous client. Hold path and query constant while varying request order and identity:

| Cache state | Request identity | Expected secure result |
| --- | --- | --- |
| cold | Share A | only A canary; populate A-specific entry |
| warm from A | Share B | only B canary or denial |
| warm from A | anonymous | anonymous policy; never A payload |
| cold | anonymous then A | A must not receive anonymous cached representation |

Record cache hit headers/log nonces and synthetic field markers. Positive evidence is **share/anonymous accountability collapses to the same key -> cached authorization-filtered A response -> B or anonymous receives A canary without permission evaluation**. The issue requires `CACHE_ENABLED=true`, is read-only, and Directus `12.0.0` is the fixed control identified by the advisory.

### File-import URL classification

Use a local canary HTTP service that returns random marker bytes and no sensitive data. As a disposable user with `directus_files` create permission, compare textual loopback, unspecified IPv4/IPv6, and an owned external URL. Correlate the import request, callback, stored file, and marker readback. A callback proves fetch; stored marker readback proves full-read behavior. Never substitute metadata endpoints, databases, caches, admin panels, or production localhost services.

## 5. LightRAG authentication and browser-origin checks

### API-key-only deployment

Start a disposable LightRAG instance with a fake `LIGHTRAG_API_KEY` and no `AUTH_ACCOUNTS`. Build a route matrix for no credential, wrong API key, correct API key, public `/auth-status` or login bootstrap output, malformed JWT, and a guest JWT accepted by the affected configuration. Test only status or an empty synthetic document list; do not delete/upload/query documents.

Positive evidence is **documented API-key-only mode -> public/fallback guest token trust -> `combined_auth` accepts guest before evaluating `X-API-Key`**. Do not publish the fallback signing value or a reusable token. LightRAG `1.5.4+` is the fixed control.

### CORS decision table

Host an owned browser origin and use fake data only. Record preflight and actual response headers for credentialed and non-credentialed requests. Separate cookie, HTTP authentication, and explicitly supplied bearer token cases: `credentials: include` does not cause a browser to discover or attach a bearer token held elsewhere. Claim cross-origin data access only when the target application genuinely stores/attaches a credential and the browser exposes the canary response to the foreign origin.

## Evidence checklist

- [ ] Exact affected and fixed versions and target feature/configuration reachability
- [ ] Synthetic identities, files, cookies, headers, records, documents, and callbacks only
- [ ] Source value, intermediate representation, final sink, and negative controls
- [ ] Separate browser request delivery from response readability
- [ ] Separate SSRF callback from response-body readback
- [ ] Separate parser primitive from downstream policy/DOM gadget
- [ ] Redacted tokens, cookies, proxy headers, cache keys, local paths, and record IDs

## Not promoted from the same wave

Resource-exhaustion-only entries for protobufjs, webpack-dev-server, node-tar, Socket.IO, shell-quote, and Mistune were marked processed without standalone offensive guidance. The Mistune predictable TOC identifier and legacy/chained-scheme records were also not promoted as independent exploit paths: identifier collision needs a separate raw-HTML/DOM gadget, and unusual scheme impact must be proven in the target user agent. The workflows above retain the stronger file, trust, cache, route, and browser-parser boundaries without treating speculative or availability-only behavior as demonstrated impact.
