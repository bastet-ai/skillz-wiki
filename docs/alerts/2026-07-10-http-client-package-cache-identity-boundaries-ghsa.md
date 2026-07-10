---
title: HTTP client, package cache, identity, API serializer, access-log, proxy-token, and APK package-integrity checks from July 10 GHSA updates
---

# HTTP client, package cache, identity, API serializer, access-log, proxy-token, and APK package-integrity checks from July 10 GHSA updates

This update promotes late July 9 / early July 10 GHSA records into reusable operator checks for authorized assessments. The shared pattern is caller-controlled protocol, artifact, package, DNS, URL, identity, serializer-cache, log-field, proxy-injected token, or package-index metadata crossing a trusted boundary after a library or platform has already decided the operation is safe: redirect-following clients forward credentials, multipart builders serialize unescaped header material, package metadata becomes a filesystem path, smart-object filenames drive extraction paths, DNS answers poison reusable resolver caches, reconstructed framework URLs drift away from routed paths, cross-organization tokens are exchanged without rebinding the user to the target application, long-lived API normalizers reuse privileged response shapes, access-log identity fields can forge request evidence, reverse proxies leak their own management trust tokens to upstream applications, and APK package clients verify signed control metadata while installing substituted data payloads.

Sources:

- [GHSA-9m9w-gxf7-rh8m / CVE-2026-48595: Tesla `FollowRedirects` leaks `Authorization` on cross-origin redirects via case-sensitive filtering](https://github.com/advisories/GHSA-9m9w-gxf7-rh8m)
- [GHSA-28jh-g32x-v9v4 / CVE-2026-48598: Tesla multipart `Content-Disposition` values allow part/header smuggling](https://github.com/advisories/GHSA-28jh-g32x-v9v4)
- [GHSA-q7jx-v53g-848w / CVE-2026-48596: Tesla multipart `Content-Type` parameters allow CRLF header injection](https://github.com/advisories/GHSA-q7jx-v53g-848w)
- [GHSA-h74c-q9j7-mpcm / CVE-2026-48597: Tesla Mint adapter interns untrusted URL schemes as BEAM atoms](https://github.com/advisories/GHSA-h74c-q9j7-mpcm)
- [GHSA-2rmg-vrx8-9j2f / CVE-2026-49836: `psd-tools` smart-object filenames can write outside the extraction root](https://github.com/advisories/GHSA-2rmg-vrx8-9j2f)
- [GHSA-h672-p7h7-97v9 / CVE-2026-53956: `rattler_cache` / `py-rattler` package cache traversal through conda build strings](https://github.com/advisories/GHSA-h672-p7h7-97v9)
- [GHSA-h5g6-xmh4-hc37 / CVE-2026-55252: OpenRun redirect validation bypass with network-path references](https://github.com/advisories/GHSA-h5g6-xmh4-hc37)
- [GHSA-c9w5-qp6m-m395 / CVE-2026-9094: Casdoor token exchange misses cross-organization binding](https://github.com/advisories/GHSA-c9w5-qp6m-m395)
- [GHSA-9vcr-p3rj-q5q6 / CVE-2026-49834: `sigstore-go` multi-log threshold counted witnesses instead of log authorities](https://github.com/advisories/GHSA-9vcr-p3rj-q5q6)
- [GHSA-676x-f7gg-47vc / CVE-2026-45674: Netty DNS resolver caches out-of-bailiwick CNAME records](https://github.com/advisories/GHSA-676x-f7gg-47vc)
- [GHSA-5pvg-856g-cp85 / CVE-2026-47691: Netty DNS resolver accepts out-of-bailiwick NS records for parent domains](https://github.com/advisories/GHSA-5pvg-856g-cp85)
- [GHSA-86qp-5c8j-p5mr / CVE-2026-48710: Starlette malformed `Host` reconstruction can desynchronize `request.url.path` from the routed path](https://github.com/advisories/GHSA-86qp-5c8j-p5mr)
- [GHSA-wf93-45jw-7689 / CVE-2026-8643: `pip` console/gui script entry-point names can traverse outside the script installation directory](https://github.com/advisories/GHSA-wf93-45jw-7689)
- [GHSA-pjhx-3c3w-9v23 / CVE-2026-49858: API Platform Core JSON:API and HAL normalizers can leak cross-user attribute structure from a shared component cache](https://github.com/advisories/GHSA-pjhx-3c3w-9v23)
- [GHSA-4vj7-5mj6-jm8m / CVE-2026-5078: `morgan` logs Basic-auth `:remote-user` values without neutralizing control characters](https://github.com/advisories/GHSA-4vj7-5mj6-jm8m)
- [GHSA-48rx-c7pg-q66r / CVE-2026-54171: Excon redirect follower fails to strip additional sensitive headers on redirects](https://github.com/advisories/GHSA-48rx-c7pg-q66r)
- [GHSA-rqq5-2gf9-4w4q / CVE-2026-54163: `secure_headers` CSP directive injection through `sandbox`, `plugin_types`, and `report_to`](https://github.com/advisories/GHSA-rqq5-2gf9-4w4q)
- [GHSA-g936-7jqj-mwv8: TSDProxy forwards its internal management auth token to proxied backend services](https://github.com/advisories/GHSA-g936-7jqj-mwv8)
- [GHSA-fpg8-7664-jc5q / CVE-2026-54174: `melange` / `apko` package verification checked APK control hashes but not installed data hashes](https://github.com/advisories/GHSA-fpg8-7664-jc5q)

!!! warning "Authorized validation only"
    Keep proofs in disposable HTTP-client harnesses, upload/extraction sandboxes, owned package indexes/channels, lab identity realms, fake signing infrastructure, two-user API Platform labs, local access-log harnesses, lab TSDProxy deployments, and owned APK repositories. Use fake bearer tokens, owned redirectors, inert multipart fields, marker-only PSD/conda/APK package files, synthetic users and organizations, disposable trust roots, canary-only resource attributes, fake Basic-auth usernames, and fake proxy-management tokens. Do not capture live credentials, hit internal services, write outside lab-owned temp directories, exchange real user tokens, weaken production supply-chain verification, expose real private API properties, poison production logs, replay real proxy tokens, or install substituted package payloads on production hosts.

## Operator use

Use these checks when a scope includes:

- Elixir services using Tesla for webhook relays, link previews, OAuth/OIDC discovery, file uploads, API integrations, or redirect-following fetches;
- multipart client builders that accept user-controlled filenames, field names, disposition parameters, content-type parameters, or charset values;
- image/design-processing pipelines that extract PSD smart objects or save embedded files from untrusted creative assets;
- conda-compatible package managers, private channels, build caches, or CI workers that consume repository-controlled `repodata`;
- login, invite, callback, or referrer flows that validate a redirect as same-origin but then redirect to the path component alone;
- Casdoor or similar multi-organization identity brokers that exchange JWTs for application tokens;
- signature-verification harnesses where a policy claims multiple independent transparency logs are required;
- Java services using Netty's async DNS resolver for outbound service discovery, webhook delivery, proxying, API clients, or cacheable resolver pools;
- Starlette/FastAPI middleware, dependency hooks, or route guards that make security decisions from `request.url` or `request.url.path` instead of the raw ASGI `scope` path;
- Python package installation paths where repository-controlled wheel metadata can define `console_scripts` or `gui_scripts` entry-point names;
- API Platform deployments that expose JSON:API or HAL resources with per-user `#[ApiProperty(security: ...)]` predicates under long-running PHP workers such as FrankenPHP, RoadRunner, Swoole, or ReactPHP;
- Express/Node services that use `morgan` built-in formats or custom formats containing `:remote-user`, especially where access logs are used as report evidence, audit trails, rate-limit evidence, or downstream parser input.
- Ruby services using Excon redirect middleware for server-side fetches, webhook delivery, SSO/OIDC discovery, link previews, API relays, or file-download helpers where caller or tenant data can influence redirects;
- Rails/Ruby applications that build per-route CSP overrides from request, tenant, content, plugin, report-endpoint, or sandbox values through `secure_headers` `sandbox`, `plugin_types`, or `report_to` directives.
- TSDProxy or similar identity-injecting reverse proxies where upstream applications receive proxy headers and can reach the proxy's management listener from localhost, host networking, or a shared network namespace;
- APK-based package build/install pipelines using `melange`, `apko`, mirrors, shared caches, or registry proxies where signed index/control metadata is trusted before package data is materialized.

## Recon checklist

| Boundary | What to look for | Safe canary |
| --- | --- | --- |
| Redirected credentials | Redirect middleware that strips `authorization` only by case-sensitive header name or preserves `Host` variants | Fake `Authorization: Bearer canary` header to an owned first hop that redirects to an owned second hop |
| Multipart header serialization | Filenames, field names, disposition opts, or `Content-Type` params serialized into HTTP headers without quote, semicolon, CR, or LF rejection | Harmless multipart request captured by a local test server; no upstream production service |
| URL scheme normalization | Fetchers passing untrusted URL schemes through atom/string interning or adapter dispatch before allow-list validation | Small fixed set of bogus schemes in a local harness; do not run exhaustion loops |
| Smart-object extraction | PSD embedded-object names used as default output filenames or external smart-object paths opened directly | Synthetic PSD fixture and marker path under a lab temp directory |
| Conda cache materialization | Package record `build`, name, version, subdir, or archive metadata joined into cache paths without final-root checks | Owned test channel and package with a marker build string in a disposable cache |
| Network-path redirects | Validation checks full same-origin URL, then redirects only to a path that may begin with `//host` or encoded equivalents | Owned redirect target and a browser/client decision table |
| Token exchange tenant binding | JWT signature is valid, but user organization/tenant is not checked against the target application/client | Two synthetic organizations, disposable users, and fake app tokens |
| Multi-log threshold semantics | Verification policy counts entries, paths, or SCTs rather than distinct log authorities | Local fake log authorities and unsigned/inert test artifacts only |
| DNS bailiwick drift | Resolver accepts CNAME, NS, or additional-section data from a zone that is not authoritative for the cached name | Lab-only authoritative DNS server for an owned subdomain and canary records under owned domains |
| Host-to-URL parser split | Raw routing path and framework-reconstructed `request.url.path` diverge after malformed `Host` parsing | Local Starlette harness with harmless allow/deny path canaries |
| Entry-point script traversal | Package metadata names become script paths without final containment under the install scripts directory | Disposable virtualenv or install root and a wheel with marker-only entry-point names |
| API serializer cache reuse | Per-user hidden properties appear in JSON:API or HAL structures after a higher-privilege request warms a long-lived normalizer cache | Two synthetic users, a canary property guarded by `#[ApiProperty(security: ...)]`, and a local long-running PHP worker |
| Access-log line forging | Basic-auth usernames containing CR/LF-like control characters break one-request-per-line assumptions in `morgan` logs | Local Express app, fake username canaries, and disposable log files only |
| Expanded redirect header relay | Redirect-following clients strip only a narrow sensitive-header list while preserving other credential-bearing or risky headers | Fake `X-Api-Key`, `Cookie`, proxy, or custom auth headers through two owned origins |
| CSP directive injection | Untrusted directive values insert `;`, CR, or LF before the legitimate `script-src` directive | Local Rails harness and harmless inline-script/report-endpoint canaries only |
| Proxy management-token relay | Reverse proxy injects an internal management auth token into backend requests; backend can replay it to localhost management APIs with forged identity headers | Lab TSDProxy plus disposable backend that records only fake token presence and route-decision results |
| APK data-section substitution | Signed package index/control hash verifies, but installed file data is not checked against the expected data hash | Owned APK repository/cache fixture and a harmless marker file diff in a disposable rootfs |

## Validation patterns

### Tesla redirect credentials and multipart protocol boundaries

The Tesla advisories are useful for any assessment where a server-side HTTP client turns user, tenant, or third-party data into outbound requests.

1. Build a local harness with two owned origins: `origin-a` returns a 302 to `origin-b`; `origin-b` records only fake headers and request framing.
2. Send the request through the application code path that uses Tesla redirect following. Include both lowercase and canonical-case fake headers, for example `authorization` and `Authorization` with canary values.
3. Record whether sensitive headers cross host, scheme, or port changes. A strong proof is a table of redirect type vs leaked fake header, not a real token capture.
4. For multipart flows, pass only inert filename, field-name, and content-type-parameter canaries that contain quotes, semicolons, or CRLF-like test strings. Capture raw bytes on a local listener and show whether extra part parameters or headers appear.
5. For URL schemes, test allow-list order with a small fixed set of bogus schemes. Do not attempt atom-table exhaustion; the finding is **untrusted scheme -> atom/adapter dispatch before scheme allow-list**, not process crash.

Report these as separate boundaries: **cross-origin redirect -> credential forwarding**, **multipart value -> request header/part smuggling**, **content-type parameter -> CRLF request header injection**, and **URL scheme -> permanent atom creation before validation**.

### PSD smart-object path traversal

Design-file ingestion often trusts embedded filenames because the parser has already accepted the outer file. Treat every embedded object name as an archive-entry path.

1. In a disposable workspace, run the exact extraction path used by the target product: preview worker, asset converter, CLI helper, or upload post-processor.
2. Use a synthetic PSD fixture with one embedded object whose filename attempts an absolute or `../` path to a lab-owned sibling directory.
3. Confirm whether `SmartObject.save()` or product wrapper code writes outside the intended output root. Evidence should be pre/post file existence for a marker file only.
4. If external-kind smart objects are in scope, keep read tests to a file you placed yourself, then route the content to a controlled marker output. Never read application config, home directories, SSH keys, cloud credentials, or customer assets.

A good report says **PSD smart-object filename -> default save path -> outside-root marker write** and includes the extraction root, effective user, and patched negative control.

### Conda channel metadata to package-cache path

The `rattler_cache` advisory is a package-manager trust-boundary check: a repository/channel record that looks like metadata becomes part of a local filesystem path during cache materialization.

1. Use an owned conda channel or local static channel fixture. Do not point production CI at an untrusted public channel for testing.
2. Publish or simulate `repodata` where a package record has a build string containing traversal syntax or path separators.
3. Install or cache the package into a disposable cache root and check only for lab-owned marker paths outside that root.
4. Capture the normalized path decision: package record fields, intended cache root, computed cache key/path, and final write location.

Keep the proof to **untrusted channel metadata -> cache path join -> outside-cache write**. Do not overwrite shell startup files, package-manager config, credentials, or shared runner paths.

### Network-path redirect validation bypass

OpenRun's `//host` bypass is a compact browser/client parser-differential pattern and belongs with return-URL testing.

1. Find routes that validate a full URL's scheme and host, then later use only `URL.Path`, `redirect_to`, `Referer`, or a decoded callback value for the actual redirect.
2. Test path values that begin with `//owned.example`, `%2f%2fowned.example`, backslash variants, and mixed decoded/encoded separators.
3. Use an owned destination and record status code, `Location`, and actual browser navigation.
4. Do not combine the redirect with credential capture. The authorized proof is **same-origin validation -> path-only redirect -> browser treats network-path reference as external authority**.

### Casdoor token exchange organization binding

Token exchange bugs are most useful when reported as tenant-binding failures, not generic authentication bypass.

1. Create two synthetic organizations and two disposable users in a lab Casdoor deployment.
2. Obtain a valid JWT for a user in organization A and attempt token exchange for an application/client in organization B.
3. Record only token metadata needed to prove the mismatch: source org, target app org, user ID prefix, scopes/audience, and response decision. Redact token bodies.
4. Compare with a patched or policy-enforced negative control where signature validity is not enough unless the user belongs to the target app's organization.

Report as **valid JWT signature -> token exchange -> missing source-user to target-application organization check**.

### Sigstore multi-log threshold authority counting

Use this only for lab verification policy reviews where the program owner explicitly wants supply-chain validation testing.

1. Build a local verifier harness with fake transparency-log or CT-log authorities and a policy that claims `N > 1` independent logs are required.
2. Attempt to satisfy the threshold with multiple entries, paths, or SCTs from the same fake authority.
3. Evidence should show whether the verifier counts distinct log authorities or merely counts verified witnesses.
4. Do not test against production Rekor/CT infrastructure or real release artifacts. Use inert artifacts and disposable keys.

The operator lesson is **policy says multiple independent logs -> verifier counts same authority multiple times -> threshold bypass**.

### Netty DNS resolver bailiwick cache poisoning

Treat DNS resolver cache entries as authority-bound data, not just parser output. These Netty updates are useful when a Java service performs attacker-influenced outbound lookups and reuses an in-process DNS cache across tenants, requests, callbacks, webhooks, or service-discovery decisions.

1. Build a lab resolver setup with an owned parent test zone and an owned delegated subdomain. Do not test against production recursive resolvers or unrelated public domains.
2. Trigger the application or a small Netty harness to resolve a name below the attacker-controlled subdomain.
3. From the authoritative lab server, return CNAME or NS/additional-section records that try to cache authority or address data for a parent/sibling canary name.
4. Query the canary name through the same resolver instance and record whether the cached answer came from the out-of-bailiwick response.
5. Keep evidence to packet captures, Netty resolver debug logs, cache-key decisions, and canary domains you own.

Report the boundary as **authoritative subdomain response -> resolver accepts out-of-bailiwick CNAME/NS data -> shared DNS cache steers later lookups**. Do not probe random resolvers, poison shared infrastructure, or route traffic to third-party services.

### Starlette `Host` reconstruction vs routed path

The Starlette advisory is a framework parser-differential check: the router uses the raw request path, while application code may make authorization decisions from a URL object reconstructed with an attacker-supplied `Host` value.

1. Identify middleware, dependencies, decorators, or endpoint code that checks `request.url`, `request.url.path`, `startswith()` path prefixes, admin route names, callback paths, or tenant paths.
2. In a local or authorized lab deployment, send a request where the raw path targets a protected route but `Host` contains path/query/fragment delimiters such as `/`, `?`, or `#`.
3. Capture a decision table with: raw request target, `Host`, routed endpoint, observed `scope["path"]`, observed `request.url.path`, and whether the guard allowed the request.
4. Repeat through any front-end proxy in scope only if the program owner approves proxy-level header tests; many proxies reject or normalize malformed `Host` values before the app sees them.

The safe proof is **malformed `Host` -> URL reconstruction boundary shift -> guard sees benign path while router dispatches protected path**. Do not combine this with credential theft or cross-user actions; use inert endpoints and route markers.

### `pip` entry-point name to script path traversal

The `pip` entry-point issue is a package metadata to filesystem boundary: a wheel's `console_scripts` or `gui_scripts` name is expected to be a filename, but vulnerable installers may treat it as a path.

1. Create a disposable virtualenv or install root with an empty, lab-owned scripts directory.
2. Build a minimal wheel from a scratch package where the entry-point name includes traversal or path-separator canaries. Keep the target path inside a temporary lab directory you control.
3. Install from a local file or owned package index and record the computed script path, actual written file path, and a negative control using a patched installer.
4. Scope CI testing to dry-run or throwaway runners; do not overwrite shell startup files, repository hooks, credentials, shared tool shims, or production runner paths.

Report as **repository-controlled package metadata -> entry-point script writer -> outside-script-dir marker file**. The finding is stronger when the vulnerable install path is reachable from lockfiles, internal indexes, plugin systems, or dependency-update automation.

### API Platform JSON:API/HAL per-user serializer-cache leak

This API Platform issue is useful beyond one framework: it is a repeatable way to test whether response-shape caches include every security-relevant input in their key. The vulnerable paths compute JSON:API/HAL component structures for one request and can reuse them for a later request whose `#[ApiProperty(security: ...)]` predicate should hide a property.

1. Build or request an authorized two-user lab with one resource exposed through JSON:API or HAL. Add a harmless canary property guarded by a per-user `#[ApiProperty(security: ...)]` predicate, for example visible to `user_high` and hidden from `user_low`.
2. Run the app under a long-lived PHP runtime that keeps normalizer instances alive across requests, such as FrankenPHP worker mode, RoadRunner, Swoole, or ReactPHP. Treat classic per-request `php-fpm` behavior as a weak or negative control unless the same worker can serve both requests.
3. Warm the cache with the higher-privilege user, then request the same resource and format as the lower-privilege user through the same worker process.
4. Evidence should be a compact matrix: format (`application/vnd.api+json` or HAL), worker/runtime, warm-up user, follow-up user, expected canary-property visibility, and observed property/relationship/link structure. Use only synthetic resource fields.
5. Repeat in the opposite order and on a patched version or runtime that does not persist the normalizer cache to prove the leak is stateful, not a static authorization mistake.

Report this as **higher-privilege request -> long-lived serializer component cache -> lower-privilege JSON:API/HAL response shape includes hidden canary property**. Do not use real sensitive properties, customer records, or production worker pinning tricks.

### `morgan` `:remote-user` access-log forging

Log-forging findings are strongest when the program relies on access logs as an investigation, billing, abuse, or rate-limit evidence source. Keep the proof to log integrity, not credential capture.

1. Confirm the target code path uses `morgan` `combined`, `common`, `default`, `short`, or a custom format containing `:remote-user`.
2. In a local or explicitly authorized lab, send Basic-auth usernames with harmless control-character canaries that attempt to terminate the current log line and start a fake one. Use fake passwords and no real user credentials.
3. Capture the raw request, the emitted raw log bytes, and the parsed line count from the same disposable log file.
4. Show whether downstream parsers, dashboards, import jobs, or evidence exports treat the forged line as a separate request or trusted actor. Avoid writing forged entries to production SIEM, audit, billing, or abuse-response systems.

Report as **Basic-auth username -> `:remote-user` log token -> unneutralized control characters -> forged access-log line**. If the target only stores logs for debugging and no downstream decision consumes them, document the lower impact rather than overstating exploitability.

### Excon redirect follower sensitive-header relay

The Excon advisory is the same operator pattern as the Tesla redirect issue, but with a broader lesson: do not test only `Authorization`. Many internal clients carry API keys, cookies, proxy credentials, service tokens, or vendor-specific auth headers that should not cross an authority change.

1. Build two owned HTTPS origins. The first origin receives the initial request and redirects to the second origin across host, scheme, or port.
2. Drive the application path that uses Excon `RedirectFollower` with only fake headers: `Authorization`, `Cookie`, `X-Api-Key`, `Proxy-Authorization`, and any app-specific credential header names in scope.
3. Capture which fake headers arrive at the second origin for same-host, cross-host, cross-scheme, and cross-port redirects.
4. Compare with Excon 1.5.0 or a custom strip-list middleware that removes all sensitive header names on authority change.

Report as **server-side Excon request -> redirect authority changes -> non-redacted sensitive header reaches attacker-controlled origin**. Do not test with production tokens or redirect real integrations to your listener.

### `secure_headers` CSP directive injection

This is useful when an application claims CSP prevents XSS but also lets tenants, plugins, markdown/frontmatter, report collectors, or route parameters influence CSP directive values.

1. Confirm the app uses `secure_headers` and appends or overrides `sandbox`, `plugin_types`, or `report_to` from non-static input.
2. In a local or authorized lab route, inject harmless directive separators such as `; script-src 'unsafe-inline' https://canary.invalid` into only those directive values.
3. Capture the raw `Content-Security-Policy` header and browser interpretation. The key evidence is whether the injected directive appears before the legitimate `script-src` and wins under first-occurrence parsing.
4. If report endpoints are in scope, point only to an owned callback and collect synthetic CSP violation reports from a lab page. Do not harvest victim-internal URLs or source snippets.
5. Add a negative control using `secure_headers` 7.3.0 or a builder that rejects `;`, CR, and LF in every directive value.

Report as **untrusted CSP directive value -> raw policy serialization -> earlier injected `script-src`/report directive -> CSP backstop bypass**. Pair it with a separate reflected/stored content sink before claiming executable XSS.

### TSDProxy identity-header management-token relay

This is a reverse-proxy confused-deputy check: the proxy injects headers that are meant to let trusted internal components assert identity, but an untrusted backend can receive and reuse the same management token.

1. Build a lab TSDProxy deployment with `identityHeaders` enabled and a disposable backend service under your control. Keep the management listener reachable only inside the lab host or network namespace.
2. Send an unauthenticated and an authenticated request through the proxy to the backend. Record whether `x-tsdproxy-auth-token` or equivalent internal trust headers are forwarded alongside user identity headers.
3. From the backend's network position, attempt only a harmless management-route decision with a fake `x-tsdproxy-id` value and the received canary token. Do not create users, change proxy config, or invoke state-changing management APIs.
4. Capture the topology precondition: same host, Docker host-network mode, shared network namespace, or any route from backend to `127.0.0.1:8080` / the management listener.
5. Add negative controls where identity headers are disabled, the backend cannot route to management localhost, or the proxy strips internal auth headers before upstream forwarding.

Report as **proxy identity middleware -> internal management auth token forwarded to backend -> backend-local replay to management API with forged identity header**. Avoid testing against production Tailscale identities, real management tokens, or customer backends.

### `melange` / `apko` APK data-section integrity substitution

This is a package-index trust-boundary check: a client verifies signed package metadata but fails to bind the installed file payload to the signed digest that represents the data section.

1. Use an owned APK repository or cache fixture with one benign package and a disposable rootfs/install target. Do not insert this into production build images or shared CI caches.
2. Build two variants with identical control metadata expectations but different installed data for a harmless file such as `/usr/share/skillz-canary.txt` inside the disposable rootfs.
3. Simulate the attacker capability explicitly: mirror compromise, poisoned shared cache, or package-fetch MITM inside a lab. Keep signatures, package names, and versions synthetic.
4. Run the vulnerable `apko` / `melange` consumer path and record whether the signed `APKINDEX` / `.PKGINFO` check passes while the installed data file contains the substituted marker.
5. Compare with a patched verifier that checks the data-section hash before installation, then include a concise table of package digest, expected marker, observed marker, and verifier decision.

Report as **signed package index/control metadata -> incomplete data-section verification -> substituted installed files accepted**. Do not publish malware-like packages, overwrite runner tools, or claim registry-wide compromise without an authorized mirror/cache proof.

## Reporting notes

Lead with the failed trust boundary:

- **redirect-following HTTP client -> case-sensitive header filter -> fake credential relay**;
- **multipart parameter -> raw header serialization -> protocol smuggling**;
- **untrusted URL scheme -> adapter normalization before allow-list -> process-level resource risk**;
- **embedded PSD filename -> default extractor path -> outside-root write**;
- **conda package metadata -> cache key/path -> outside-cache write**;
- **same-origin URL validation -> path-only `Location` -> network-path external redirect**;
- **signed JWT -> token exchange -> missing organization binding**;
- **multi-log policy -> per-entry counting -> single-authority threshold satisfaction**;
- **attacker-controlled authoritative DNS answer -> missing bailiwick enforcement -> poisoned shared resolver cache**;
- **malformed `Host` header -> reconstructed URL path drift -> path guard bypass**;
- **wheel entry-point metadata -> script path join -> outside-install-root write**;
- **privileged API request -> long-lived response-shape cache -> lower-privilege JSON:API/HAL structure leak**;
- **Basic-auth username -> unescaped access-log token -> forged request evidence**.
- **redirect-following Excon client -> incomplete sensitive-header strip list -> fake credential relay**;
- **untrusted `secure_headers` directive value -> CSP separator injection -> policy backstop bypass**;
- **proxy-injected identity headers -> management token leaked to backend -> backend replays trust token locally**;
- **signed APK control metadata -> unchecked data payload -> substituted installed files**.

Include version, route/tool/library path, required attacker control, lab harness design, synthetic canary evidence, and a negative control. Avoid claiming production token theft, internal SSRF, arbitrary file overwrite, or supply-chain compromise unless the authorized lab evidence reaches that exact sink without sensitive data or irreversible side effects.
