# Open WebUI RAG, redirect-hop SSRF, and knowledge-boundary checks

Sources: GitHub Security Advisories updates on 2026-05-15, with redirect-following details refreshed on 2026-05-28 and Playwright loader coverage added on 2026-06-18.

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

## Durable controls

- SSRF controls must bind validation to the socket destination after redirects, DNS resolution, IP normalization, and protocol upgrades; validating the original string is not enough.
- Disable automatic redirects or implement a manual redirect loop that validates every `Location` before the next request.
- For browser-based loaders, install a request/route interceptor and validate every navigation, redirect, and subresource URL before allowing the browser to continue.
- Object authorization belongs at the dereference point: file IDs, collection names, RAG search results, folder knowledge entries, and attach endpoints must all re-check owner, workspace, and share grants.
- Vector-store collection names and metadata are security boundaries. Prefix by tenant/user, reject caller-supplied collection targets, and deny destructive operations unless the server resolved the object from an authorized parent.
- Unauthenticated configuration endpoints should never disclose retrieval providers, internal network targets, embedding settings, or storage layout that make SSRF/RAG attacks easier.
