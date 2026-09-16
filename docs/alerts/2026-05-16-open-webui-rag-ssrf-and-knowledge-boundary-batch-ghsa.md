# Open WebUI RAG, redirect-hop SSRF, and knowledge-boundary checks

Sources: GitHub Security Advisories updates on 2026-05-15, with redirect-following details refreshed on 2026-05-28, Playwright loader coverage added on 2026-06-18, image-edit blind SSRF coverage added on 2026-07-07, and browser, NAT64, DNS-rebinding, direct-model, and cleanup-scope coverage added on 2026-08-04.

This Open WebUI-heavy wave is durable because it shows how RAG, file attach, vector-search, web-fetch, image-load, chat-completion image inlining, and social-card image generation features collapse separate trust zones when URL validation, object ownership, and collection routing are not enforced at the final use site. Treat every retrieval object, redirect, vector collection, knowledge-base identifier, and model-message URL as attacker-controlled until the exact worker that dereferences it revalidates ownership and destination.

## Advisories covered

- **Open WebUI: Cross-User File Access via Unchecked file_id in Folder Knowledge and Knowledge-Base Attach Endpoints** — [GHSA-r472-mw7m-967f](https://github.com/advisories/GHSA-r472-mw7m-967f) / CVE-2026-45402 (high).
- **Open WebUI has a SSRF Bypass via HTTP Redirect Following in Web-Fetch and Image-Load Endpoints (not addressed by CVE-2025-65958)** — [GHSA-rh5x-h6pp-cjj6](https://github.com/advisories/GHSA-rh5x-h6pp-cjj6) / CVE-2026-45401 (high).
- **Open WebUI has a Server-Side Request Forgery (SSRF) bypass in `validate_url`** — [GHSA-8w7q-q5jp-jvgx](https://github.com/advisories/GHSA-8w7q-q5jp-jvgx) / CVE-2026-45400 (high).
- **Open WebUI Vulnerable to IDOR: Retrieval API Bypasses Knowledge Base Access Controls** — [GHSA-4g37-7p2c-38r9](https://github.com/advisories/GHSA-4g37-7p2c-38r9) / CVE-2026-45398 (high).
- **Open WebUI Vulnerable to Unauthenticated RAG Configuration Disclosure** — [GHSA-65pg-qhhw-mxwg](https://github.com/advisories/GHSA-65pg-qhhw-mxwg) / CVE-2026-45397 (medium).
- **Open WebUI has a full SSRF Vulnerability in the RAG Web Search Feature** — [GHSA-4v7r-f4w8-8972](https://github.com/advisories/GHSA-4v7r-f4w8-8972) / CVE-2026-45331 (high).
- **Open WebUI has Unauthorized File and Knowledge Base Content Access via RAG Vector Search** — [GHSA-h36f-rqpx-j5wx](https://github.com/advisories/GHSA-h36f-rqpx-j5wx) / CVE-2026-44560 (medium).
- **Open WebUI vulnerable to Global Knowledge Base Enumeration via knowledge-bases Meta-Collection** — [GHSA-6c2x-gcp3-gp73](https://github.com/advisories/GHSA-6c2x-gcp3-gp73) / CVE-2026-44557 (medium).
- **Open WebUI has Knowledge Base Destruction and RAG Poisoning via Unauthorized Collection Overwrite** — [GHSA-7r82-qhg4-6wvj](https://github.com/advisories/GHSA-7r82-qhg4-6wvj) / CVE-2026-44554 (high).
- **Open WebUI: SSRF Protection Bypass in Playwright Web Loader via HTTP Redirects** — [GHSA-jrfp-m64g-pcwv](https://github.com/advisories/GHSA-jrfp-m64g-pcwv) / CVE-2026-54018 (high).
- **Open WebUI has Blind Server Side Request Forgery in its Image Edit Functionality** — [GHSA-jgx9-jr5x-mvpv](https://github.com/advisories/GHSA-jgx9-jr5x-mvpv) / CVE-2026-34225 (medium; `open-webui` `<= 0.7.2`, no patched version listed in the advisory at publication time).
- **Open WebUI NAT64-encoded destination bypass** — [GHSA-8x5v-cpv7-8jjp](https://github.com/advisories/GHSA-8x5v-cpv7-8jjp) / CVE-2026-70485 (high).
- **Open WebUI Playwright subresource SSRF** — [GHSA-w2rx-84hp-gg95](https://github.com/advisories/GHSA-w2rx-84hp-gg95) / CVE-2026-70479 (high).
- **Open WebUI Vega/Vega-Lite browser-side request proxy** — [GHSA-rffm-9q57-q649](https://github.com/advisories/GHSA-rffm-9q57-q649) / CVE-2026-70480 (medium).
- **Open WebUI DNS-rebinding SSRF bypass** — [GHSA-h6x2-583h-x99r](https://github.com/advisories/GHSA-h6x2-583h-x99r) / CVE-2026-54020 (medium).
- **Open WebUI direct-model knowledge metadata crosses file ownership** — [GHSA-6xhv-rxhv-pwm4](https://github.com/advisories/GHSA-6xhv-rxhv-pwm4) / CVE-2026-70487 (medium).
- **Open WebUI knowledge-sync cleanup accepts foreign directory/file IDs** — [GHSA-jxc9-xmc4-gr23](https://github.com/advisories/GHSA-jxc9-xmc4-gr23) / CVE-2026-70488 (medium).
- **nuxt-og-image SSRF — bypass of GHSA-pqhr-mp3f-hrpp / v6.2.5 fix (IPv6 + redirect)** — [GHSA-c2rm-g55x-8hr5](https://github.com/advisories/GHSA-c2rm-g55x-8hr5) / CVE-2026-44589 (low).

## Operator triage

1. Prioritize internet-facing or multi-tenant Open WebUI deployments with RAG, web search, image loading, chat image inputs, uploaded files, shared folders, or knowledge bases enabled.
2. Audit access logs and task traces for unexpected file IDs, knowledge-base IDs, collection overwrites, private-address fetches, redirect chains, `image_url` message parts, and RAG vector-search hits across tenant/user boundaries.
3. Use a low-privilege test account to verify that file attach, folder knowledge, retrieval, meta-collection, web-search, image-load, image-edit, and chat-completion image paths cannot read, overwrite, poison, or enumerate objects outside that account.
4. If exploitation is plausible, rotate API keys and secrets exposed through retrieved files, internal HTTP targets, cloud metadata, or poisoned RAG content; preserve logs before cleanup.

## May 28 redirect-hop update

GitHub Advisory [GHSA-rh5x-h6pp-cjj6](https://github.com/advisories/GHSA-rh5x-h6pp-cjj6) was refreshed with a useful operator lesson: Open WebUI's redirect SSRF is not just a web-fetch issue. `validate_url()` checked the caller-supplied URL once, while downstream clients followed `3xx` responses without revalidating the final hop. Regression tests should cover every helper that dereferences URLs, not only the endpoint named in the first report.

Replay the boundary safely with an authenticated low-privilege account and an owned redirector that first points to a benign callback listener, then to an authorized internal canary service. Confirm that these paths reject or stop at redirects before any private, loopback, link-local, or metadata host is fetched:

- `SafeWebBaseLoader` / LangChain `WebBaseLoader` sync scraping in retrieval web processing.
- `get_content_from_url` in retrieval/file-ingestion flows such as `/api/v1/retrieval/process/web`.
- Image edit URL loading through `/api/v1/images/edit`.
- Chat-completion image inlining through `/api/chat/completions` messages containing an `image_url` content part.
- Any async `aiohttp` or shared session-pool helper that accepts a URL from user, model, tool, or connector-controlled content.

Report the bug as a *per-hop validation failure* when the first URL passes policy but a followed `Location` reaches `127.0.0.1`, RFC1918 space, link-local cloud metadata such as `169.254.169.254`, internal DNS, or VPN-only services. Strong evidence is a response body or timing/content-length difference from an authorized internal canary; avoid reading real metadata or secrets during validation.

## June 18 Playwright loader update

[GHSA-jrfp-m64g-pcwv](https://github.com/advisories/GHSA-jrfp-m64g-pcwv) extends the same redirect-hop lesson to Open WebUI's Playwright-backed RAG web loader. The advisory states that `SafePlaywrightURLLoader` validated the initial URL with `_safe_process_url_sync(url)`, then called `page.goto(url)`. Playwright follows HTTP redirects by default, so an attacker-controlled public URL could return a `302` to an internal destination after the initial validation had already passed. The affected configuration called out by the advisory is `RAG_WEB_LOADER_ENGINE=playwright` with `ENABLE_RAG_LOCAL_WEB_FETCH=False`.

For operators, this is a durable browser-loader SSRF pattern: any headless-browser fetcher that validates only the starting URL but lets the browser follow redirects, load subresources, or resolve navigations can cross from public web content into loopback, container DNS, RFC1918 ranges, or cloud metadata.

Safe validation workflow:

1. Confirm the target Open WebUI deployment is in scope and uses the Playwright web loader. Do not assume every Open WebUI RAG endpoint uses Playwright.
2. Use a low-privilege test user and an owned redirector. The first hop should be a public URL you control; the redirected destination should be a synthetic internal canary service in an authorized lab or customer-approved test network.
3. Submit the public redirector through Web Search or URL Loader. Positive proof is the Playwright loader reaching the internal canary even though direct local fetching is disabled.
4. Repeat with negative controls: a direct private-address URL, a public URL with no redirect, and a patched build or route interceptor that validates every request URL before `continue_()`.
5. Capture only canary evidence: request timestamps, callback path, loader configuration, version, and response metadata. Do not fetch instance metadata, real internal admin panels, notebooks, model files, credentials, or container service APIs.

Report this as **Playwright redirect-chain SSRF in RAG URL loader**, not as generic SSRF. The important boundary is that validation occurred before browser navigation rather than on each redirect and subrequest.

## July 7 image-edit blind SSRF update

[GHSA-jgx9-jr5x-mvpv](https://github.com/advisories/GHSA-jgx9-jr5x-mvpv) adds a separate image-edit fetch boundary: `/api/v1/images/edit` accepted a user-supplied `form_data.image` URL, passed it into `load_url_image`, and trusted `http://` / `https://` targets before calling `requests.get`. The advisory describes the result as blind SSRF: the caller does not read the response body, but request success/failure is enough to infer reachable hosts or open ports from the Open WebUI server's network position.

Safe validation workflow:

1. Test only in an owned lab or customer-approved Open WebUI deployment with a low-privilege account and a harmless image-edit prompt.
2. Use an owned callback listener and a synthetic internal canary service. Positive proof is a GET from the Open WebUI backend to the canary, or a controlled success/failure differential against explicitly authorized canary ports.
3. Exercise the exact image-edit path, not only generic RAG web-fetch endpoints. Include the Open WebUI version, route, request timestamp, and callback path in evidence.
4. Avoid broad port sweeps, cloud metadata, Kubernetes service discovery, admin panels, notebooks, model files, API keys, or any service that was not explicitly designated as a canary.

Report this as **image-edit URL-to-backend blind SSRF**. The reusable lesson is that AI media features often fetch user-controlled image inputs from backend workers; each image, avatar, citation, OCR, edit, and generation helper needs destination validation at the final HTTP client, even when the response body is not returned.

## Durable controls

- SSRF controls must bind validation to the socket destination after redirects, DNS resolution, IP normalization, and protocol upgrades; validating the original string is not enough.
- Disable automatic redirects or implement a manual redirect loop that validates every `Location` before the next request.
- For browser-based loaders, install a request/route interceptor and validate every navigation, redirect, and subresource URL before allowing the browser to continue.
- Treat media helper URLs as SSRF sinks even when they return only image bytes or a boolean success state. Blind success/failure, timing, and content-type differences are enough to prove backend reachability.
- Object authorization belongs at the dereference point: file IDs, collection names, RAG search results, folder knowledge entries, and attach endpoints must all re-check owner, workspace, and share grants.
- Vector-store collection names and metadata are security boundaries. Prefix by tenant/user, reject caller-supplied collection targets, and deny destructive operations unless the server resolved the object from an authorized parent.
- Unauthenticated configuration endpoints should never disclose retrieval providers, internal network targets, embedding settings, or storage layout that make SSRF/RAG attacks easier.

## August 4 follow-up: normalize transition addresses and intercept every browser request

The 0.11.0 advisories add three reusable differentials. First, an IPv6 address can be globally routed while embedding a non-global IPv4 destination that NAT64 translates. Second, validating a Playwright `document` request does not validate the page's fetch/XHR/image/WebSocket/service-worker traffic. Third, Vega specifications execute in the viewer's browser, so they bypass server-side URL policy entirely.

Use an isolated lab with an owned public redirector, a synthetic private canary service, a browser container on a test NAT64 network, and a browser profile with no real sessions. Never substitute cloud metadata, production loopback services, or internal admin APIs.

### Destination-class matrix

Record the submitted URL, parsed host, DNS answers, literal and unwrapped address, policy classification, redirect hop, browser resource type, and final socket peer. Compare:

- ordinary public IPv4/IPv6 controls;
- direct synthetic private/loopback addresses;
- IPv4-mapped IPv6 and NAT64 encodings of the same owned canary;
- an owned public page that issues document, fetch/XHR, image, font, WebSocket, and service-worker requests to the canary; and
- redirects between two owned public authorities before the canary.

A NAT64 positive is **literal IPv6 passes policy -> transport recorder shows its embedded IPv4 maps to the denied canary**. A Playwright positive is **top-level public document passes -> a non-document resource reaches the canary without the same destination decision**. Confirm the network actually provides NAT64 before attributing a failed/accepted string to reachability.

### Browser-renderer matrix

For Vega/Vega-Lite, post a harmless chart to a two-user shared lab channel. Use only an owned callback and a same-origin canary endpoint containing a random non-sensitive marker. Compare inline `data.values`, `data.url`, image-mark URLs, protocol-relative forms, redirects, and parser-normalized URLs. Capture the chart spec, browser network log, origin/CORS decision, and whether response bytes become chart data.

The report should distinguish **request-only browser proxying** from **response read**: a cross-origin GET may beacon without exposing its body, while a same-origin or permissive-CORS endpoint may become readable. Do not call this server-side SSRF, and do not use a victim browser with access to real internal services.

Open WebUI lists 0.11.0 as the first patched release for these three records. Compare the same fixtures on the affected and fixed build: corrected browser loading should validate every request/redirect, block service workers and outbound WebSockets where they cannot be validated, unwrap standardized transition encodings before policy checks, and restrict chart loaders to inline or explicitly same-origin resources.

## August 4 follow-up: bind DNS decisions, inline models, and cleanup children

Three more 0.11.0 fixes add final-use checks to the same fixture. The DNS record is a time-of-check/time-of-use differential: URL policy resolved a hostname and approved a public answer, but the HTTP client performed a second resolution when opening the socket. The direct-model record trusted request-scoped `model.knowledge` file references as though a saved model owner had already authorized them. The sync-cleanup record authorized the knowledge base in the URL but acted on directory and file IDs from the request body without proving parent membership.

### DNS-resolution binding

Use an authoritative zone and two isolated canary listeners that you own: one globally reachable validation endpoint and one lab-private final endpoint. Configure deterministic alternating answers with zero TTL, log every DNS response, and record the actual peer accepted by the HTTP transport. Exercise retrieval ingestion, content probing, chat `image_url`, image edit, and—only with a mock OIDC provider—profile-picture retrieval.

The bounded positive is **policy lookup receives the public canary -> connect-time lookup receives the private canary -> private listener records the request**. Do not target metadata, loopback admin services, or production internal hosts. If testing the OAuth picture path, use a fake bearer marker and report only whether the owned listener received the marker; never relay a real provider token. A corrected client must validate and connect to the same resolved address, or enforce the destination policy in its resolver/transport immediately before connection.

### Request-scoped knowledge and cleanup membership

Seed two users, two knowledge bases, one directory and one indexed marker file per owner. Use synthetic UUIDs shared through the test harness rather than enumeration. Replace file-content return, directory delete, association cleanup, and vector-drop operations with read/no-op recorders.

| Operation | Authorized parent | Caller-selected child | Secure result |
| --- | --- | --- | --- |
| inline model with native tools | caller-owned model context | caller-owned file | marker may reach read recorder |
| inline model with native tools | caller-owned model context | foreign file UUID | deny/drop before content retrieval |
| sync cleanup | caller-writable knowledge base A | directory in A | no-op cleanup control |
| sync cleanup | caller-writable knowledge base A | directory in B | deny before directory-delete recorder |
| sync cleanup | caller-writable knowledge base A | file in B | deny before vector/association recorder |

Capture principal, request-scoped versus saved model provenance, native/legacy tool mode, selected file ID, authorized knowledge-base ID, resolved child parent, and first sink reached. Strong positives stop at **foreign file marker reaches the read recorder** or **A-authorized request carries B child ID to a no-op cleanup sink**. Never retrieve another user's real file content, delete a directory, or drop vector collections. Keep UUID knowledge as an explicit precondition; these records do not establish ID enumeration.

## September 16 follow-up: the Playwright loader re-resolves DNS on its own (GHSA-4v28-j6q3-5m4r / CVE-2026-87996)

The August 4 DNS-binding fixture finally produced the confirmed browser-loader break. With `WEB_LOADER_ENGINE=playwright`, Open WebUI validated the address behind the submitted URL, then handed the same URL to the browser — and the browser resolved it a second time, unchecked. An attacker owning the zone with short-TTL alternating answers makes the check see a public address and the browser connect to an internal one. No timing race is required: the two lookups are separate queries the attacker answers differently, and connection-layer IP pinning cannot apply because the request runs inside the browser, not Open WebUI's own HTTP clients.

Preconditions to confirm first: Playwright engine enabled (not default), reachable local or `PLAYWRIGHT_WS_URL` browser, any authenticated non-admin user able to submit a URL or trigger web search, and browser-process network routes to internal space. Impact is a read primitive with response relay: the intercepted page becomes the ingestion/search result, IMDSv1 IAM credentials are reachable on cloud hosts, and because method and headers are forwarded, an attacker page can drive header-gated or non-GET metadata endpoints.

Operator notes:

1. This is the exact fixture the August 4 section specified — owned authoritative zone, alternating public/private answers, owned internal canary listener — now with a confirmed same-product positive. Record the per-query DNS log plus the final peer the browser recorded.
2. Distinguish engines in every report: default-loader deployments pin the validated IP and are unaffected; only the Playwright path breaks pinning by delegating fetch to the browser.
3. Fixed in 0.11.1. On a corrected build, re-run the alternating-answer fixture and confirm every browser request is intercepted/validated or the resolved address is pinned at browser transport level.
4. Scope to the deployment's own route map: if the browser container has no internal routes, report the precondition honestly; never probe unrelated internal services to find one.
