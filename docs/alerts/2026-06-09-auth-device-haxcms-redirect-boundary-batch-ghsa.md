# Auth parser, device-flow, HAXcms token, and redirect-cookie boundaries

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-gv94-wp4h-vv8p](https://github.com/advisories/GHSA-gv94-wp4h-vv8p) / CVE-2026-0707, [GHSA-cq3f-vc6p-68fh](https://github.com/advisories/GHSA-cq3f-vc6p-68fh) / CVE-2026-45337, [GHSA-m6vc-f87m-cc2h](https://github.com/advisories/GHSA-m6vc-f87m-cc2h) / CVE-2026-44476, [GHSA-6c8g-9hfh-pq5h](https://github.com/advisories/GHSA-6c8g-9hfh-pq5h) / CVE-2026-46395, [GHSA-x3x5-7h4h-gwxg](https://github.com/advisories/GHSA-x3x5-7h4h-gwxg) / CVE-2026-46511, [GHSA-jh3h-rpxg-fr36](https://github.com/advisories/GHSA-jh3h-rpxg-fr36) / CVE-2026-46396, [GHSA-2m6p-hm3w-6jm3](https://github.com/advisories/GHSA-2m6p-hm3w-6jm3) / CVE-2026-46496, and [GHSA-fmxf-pm6p-7xgm](https://github.com/advisories/GHSA-fmxf-pm6p-7xgm) / CVE-2026-45300.

This batch is durable because the advisories expose reusable operator patterns: permissive auth-scheme parsing, device-code ownership races, dynamic client registration trust confusion, client-side token aggregation chained to stored content injection, and cookie propagation across redirect boundaries.

## What changed

- **Keycloak bearer parser canonicalization** — Keycloak accepts non-standard separators such as tabs and tolerates case variations around the `Bearer` authentication scheme. This is useful as a parser-differential test where gateways, WAFs, libraries, and identity providers disagree about whether a request is authenticated.
- **Better Auth device authorization ownership gap** — Better Auth `>= 1.6.0, < 1.6.11` with the `deviceAuthorization()` plugin can let any authenticated session approve or deny a pending user code if the attacker observes the code before the legitimate user completes verification.
- **Doorkeeper OpenID Connect dynamic client registration confusion** — Doorkeeper OpenID Connect dynamic client registration can create public clients while returning a `client_secret` and advertising secret-based token endpoint auth. If only the public `client_id` is required at token exchange, client authentication is weaker than the registration response implies.
- **HAXcms token and stored-content chain** — HAXcms advisories describe a Node.js HMAC implementation that exposes signing material via `/system/api/connectionSettings`, plus stored XSS vectors through components such as iframe and `video-player`. The durable testing idea is whether client-visible bootstrap objects and component attributes let low-privilege content cross into tenant/session token control.
- **async-http-client redirect cookie leak** — async-http-client can strip `Authorization` and `Proxy-Authorization` on cross-origin redirects while leaving `Cookie` headers intact, forwarding session cookies to attacker-controlled redirect targets.

## Operator triage

1. **Group by boundary, not product.** These issues map to five common classes: auth header canonicalization, device-flow code ownership, OAuth dynamic registration, browser-token exposure through stored content, and redirect credential propagation.
2. **Prioritize internet-facing identity and integration paths.** Test login gateways, API gateways, OAuth/OIDC client registration, device-code workflows, CMS editors, webhook fetchers, backend HTTP clients, and SDKs that follow redirects automatically.
3. **Confirm feature preconditions.** Better Auth requires the device authorization plugin; Doorkeeper requires opt-in dynamic client registration; HAXcms impact depends on the Node/PHP implementation path and stored-content reachability; redirect leakage requires caller-supplied cookies and automatic redirect following.
4. **Use tester-owned canaries.** Prove parser differentials, account binding, token exposure, or redirect leakage with synthetic sessions, disposable clients, and callback endpoints that capture only canary identifiers.
5. **Avoid secret collection.** Do not exfiltrate real JWTs, cookies, private keys, tenant content, or internal data. A strong report shows that a synthetic marker crossed the boundary and explains what real data would be exposed.

## Replayable validation boundaries

### Auth parser canonicalization checks

- Send authorization headers that vary only by scheme case and separator whitespace to each layer in scope: CDN/WAF, reverse proxy, service mesh, app middleware, and identity provider.
- Record whether any layer treats a request as anonymous while a downstream component treats it as authenticated, or vice versa.
- Keep tokens synthetic and scoped to a test account. The finding is the parser disagreement, not access to production data.

### Device-code and dynamic-registration checks

- For device authorization, create two test accounts. Start a device flow with one account's code, then attempt approve/deny actions from the other authenticated account before legitimate completion. Capture whether the polling device binds to the wrong principal or the flow can be denied cross-account.
- For dynamic client registration, register a disposable client, inspect whether it is confidential or public, then attempt token exchange with only the public `client_id`. Report mismatches between advertised client authentication and what the token endpoint enforces.
- Include timing, account IDs, client IDs, scopes, and endpoint responses. Do not reuse real customer clients or codes.

### HAXcms client-token and component-attribute checks

- In a lab or authorized tenant, create low-privilege content using permitted rich components and verify whether dangerous URI schemes or same-origin script execution are accepted after save and render.
- Check whether bootstrap endpoints expose session-specific tokens, signing material, or tenant-scoped API credentials to browser JavaScript. Use a planted canary value where possible rather than reading live secrets.
- Demonstrate tenant/session boundary crossing only with disposable accounts and tester-owned callback endpoints. Avoid payloads that persist beyond the test page or run against uninvolved users.

### Redirect-cookie propagation checks

- Build a tester-controlled redirect chain from an in-scope origin to a tester-owned host. Trigger the in-scope backend or SDK path with a synthetic `Cookie` header and automatic redirects enabled.
- Confirm whether `Cookie` survives when `Authorization` is stripped across origin or scheme boundaries.
- Capture library version, redirect policy, initial host, final host, and the exact synthetic cookie name/value observed at the callback.

## Reporting heuristics

- Lead with the **principal or origin boundary crossed**: gateway-to-IdP parser disagreement, pending code to wrong user, public client to token endpoint, author-controlled content to victim tokens, or first-party cookie to third-party redirect target.
- State the preconditions in the first paragraph so triagers can reproduce quickly.
- Prefer screenshots or transcripts showing before/after ownership and canary movement over exploit payload drama.
- If a product advisory includes full PoC exploit code, link to the primary advisory and keep the wiki report focused on safe validation boundaries.

## Notes on skipped items from this scan

- `guardrails-ai` malicious package publication was treated as supply-chain incident material rather than a new offensive operator page for this run; existing wiki supply-chain testing guidance is a better fit unless a reusable canary workflow emerges.
- IDNA resource-exhaustion and HAX CMS import DoS entries were not promoted as standalone pages because they are availability-heavy and low signal for Skillz Wiki's current offensive taxonomy.
- Puma, Arc, File Browser, web3.py, Nebula Mesh, FUXA, and adjacent late GitHub advisory waves were already represented by earlier 2026-06-08 and 2026-06-09 pages.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, Disclosed, and CISA KEV had no separate new promotable deltas beyond items already represented in the wiki.
