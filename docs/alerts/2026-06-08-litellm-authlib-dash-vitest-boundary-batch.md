# LiteLLM, Authlib, Dash uploader, and Vitest boundary batch

Source: hourly offensive-security scan, 2026-06-08. Primary entries: CISA KEV [CVE-2026-42271](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for BerriAI LiteLLM command injection; GitHub advisories [GHSA-w8p2-r796-3vmq](https://github.com/advisories/GHSA-w8p2-r796-3vmq), [GHSA-3rf6-x59v-5jfv](https://github.com/advisories/GHSA-3rf6-x59v-5jfv), [GHSA-5xrq-8626-4rwp](https://github.com/advisories/GHSA-5xrq-8626-4rwp), and [GHSA-g868-j3qm-4j28](https://github.com/advisories/GHSA-g868-j3qm-4j28).

This batch is durable because the items share reusable operator patterns: AI gateway command surfaces, OAuth authorization endpoint redirect handling before client validation, resumable-upload path traversal into write-to-RCE primitives, exposed developer test APIs, and plugin-gated SQL injection.

## What changed

- **LiteLLM command injection entered CISA KEV** — CISA added CVE-2026-42271 for BerriAI LiteLLM command injection on 2026-06-08. Treat it as a high-priority validation target only where LiteLLM is an in-scope AI gateway, proxy, or model-routing component.
- **Authlib OAuth 2.0 open redirect** — Authlib authorization endpoints could return a `302 Location` to attacker-controlled `redirect_uri` when an unsupported `response_type` is supplied, before client lookup and redirect-URI validation.
- **dash-uploader path traversal** — unauthenticated `POST /API/dash-uploader` handling in `dash-uploader` can join attacker-controlled form values into filesystem paths. The advisory describes write primitives that can become RCE when a dropped `.pth`, WSGI module, web asset, SSH key, or similar interpreter-consumed file lands in a writable target.
- **Vitest UI/API exposure** — exposed Vitest UI or Browser Mode can allow arbitrary file read/write and script execution through privileged API features, with a Windows file-serving bypass involving `\\?\\..\\` path handling called out in the advisory.
- **TYPO3 news date-menu SQL injection** — the `georgringer/news` extension can expose unauthenticated SQL injection through a URL parameter on pages using the "Date Menu of news articles" plugin when the required plugin setting does not disable override demand.

## June 23 LiteLLM privilege-boundary update

GitHub Advisory Database added two LiteLLM authorization-boundary items: [GHSA-wpfp-gwwc-vwq6](https://github.com/advisories/GHSA-wpfp-gwwc-vwq6) / CVE-2026-47102 and [GHSA-qrc4-49gv-mv9m](https://github.com/advisories/GHSA-qrc4-49gv-mv9m) / CVE-2026-47101.

- **Self role mass assignment:** prior to 1.83.10, `/user/update` lets a reachable user update their own `user_role` field. An `org_admin` or other user who can access the endpoint can set `proxy_admin`, crossing from account profile editing into global proxy administration.
- **API key route inflation:** prior to 1.83.14, an authenticated `internal_user` can create keys with `allowed_routes` that exceed that user's role permissions. The generated key then authorizes routes the original session should not reach.

Operator validation: in an owned LiteLLM lab, create disposable users for each role, attempt only harmless role/route canaries, and compare direct-session denials against generated-key access. Do not read model provider keys, prompt history, team secrets, or production user records as evidence.

## Operator triage

1. **Map AI gateway surfaces:** look for `litellm`, LiteLLM proxy containers, `/chat/completions`-style model gateways, admin UIs for model routing, and internal agent platforms that accept model/provider configuration from users or tenants.
2. **Confirm OAuth library ownership:** identify Flask, Django, or custom OAuth authorization servers using Authlib. Prioritize public `/authorize` endpoints and products that expose Bring Your Own OAuth or identity-broker functionality.
3. **Fingerprint Dash upload endpoints:** search for Dash apps serving `/API/dash-uploader`, `dash-uploader` static assets, or Python dependency metadata for `dash-uploader` versions `0.1.0` through `0.7.0a2`.
4. **Find exposed dev/test APIs:** scan in-scope hosts and preview environments for Vitest UI routes such as `/__vitest__/`, `/__vitest_attachment__`, and browser-mode RPC endpoints. Prioritize hosts bound beyond localhost or reachable from shared VPN/build networks.
5. **Gate TYPO3 testing on plugin use:** confirm the `news` extension and the "Date Menu of news articles" plugin are active before spending time on SQLi validation. Version-only evidence is weaker than a reachable plugin route.

## Replayable validation boundaries

### LiteLLM command-injection checks

- Start with passive evidence: package manifests, container image tags, server banners, route names, or admin screenshots showing LiteLLM.
- Use a lab clone or explicitly authorized tenant before sending payloads to model/provider configuration, callback, tool, or command-adjacent fields.
- Prove execution with a benign marker such as `id`, `whoami`, DNS canary, or writing to a disposable temp path. Do not read real secrets, prompt logs, model API keys, or cloud metadata.
- Capture the exact feature path that crosses the boundary: user role, endpoint, parameter, model/provider/plugin setting, and whether execution occurs in the proxy, worker, or sidecar context.

### LiteLLM role and generated-key checks

- Preconditions: owned LiteLLM lab, affected version, disposable `internal_user`, `org_admin`, and `proxy_admin` accounts, and non-sensitive test routes.
- For `/user/update`, attempt to update only the current user's `user_role` field and record whether the API accepts a transition outside the user's assigned role envelope.
- For key generation, request an API key whose `allowed_routes` includes a harmless admin-only route the session cannot access directly, then compare direct-session and key-auth responses.
- Positive evidence: before/after user role, generated key metadata with redacted token value, route-decision table, and patched negative control.
- Stop before listing real users, teams, spend logs, provider keys, models with sensitive prompts, or production prompt history.

### Authlib authorization redirect checks

- Build a harmless request to the authorization endpoint using an unsupported `response_type` and a tester-controlled `redirect_uri`.
- Confirm whether the server returns a `302` to the unregistered redirect URI without requiring a valid client, login session, consent, or pre-registered callback.
- Preserve only the status line, `Location` header, request path, and synthetic domain. Avoid including real OAuth client secrets, authorization codes, or tokens.
- Impact is strongest when the redirect can be chained into phishing-resistant login confusion, OAuth mix-up, token-leak preconditions, or trusted-domain redirect allowlist bypasses.

### dash-uploader write-primitive checks

- First verify the endpoint exists with a non-destructive upload to the intended uploads directory.
- Test traversal only inside a disposable lab or a target-provided test path. Use a canary filename and content; do not overwrite application code or system files in production.
- If RCE validation is explicitly approved, prefer a controlled restart path in a clone and a single benign marker. Document whether `.pth`, WSGI overwrite, Dash `assets/` JavaScript, or another interpreter-consumed path created impact.
- Record the process user, destination permissions, traversal form fields, and cleanup steps.

### Vitest UI/API checks

- Treat exposed Vitest as a development-interface finding, not just a package-version finding. Validate network reachability and whether the API token can be recovered from `/__vitest__/`.
- For file-read checks, use synthetic files in the project or lab filesystem. On Windows targets, include the `\\?\\..\\` path-shape only when authorized.
- For write/execute checks, stay within test files and use the UI/API rerun path with a benign marker. Do not execute arbitrary payloads or read developer secrets.
- Include binding evidence (`localhost` versus network host), `allowWrite` / `allowExec` configuration if visible, and route transcripts.

### TYPO3 news SQLi checks

- Confirm the `news` extension, vulnerable version range, and Date Menu plugin route are present.
- Use low-impact boolean, timing, or error-differential probes against the documented URL parameter only after confirming scope.
- Avoid dumping table data. A single controlled predicate difference plus version/plugin evidence is enough for a high-quality bug-bounty report.
- Include the TypoScript/plugin setting evidence when available, especially whether `disableOverrideDemand` changes exploitability.

## Reporting heuristics

- Separate **reachability** from **impact**: exposed endpoint, vulnerable component, exact parameter, and role/session requirements first; command execution, file write, redirect abuse, or SQLi impact second.
- Prefer canaries and synthetic markers over sensitive reads. The best reports prove the boundary break without collecting secrets.
- Include negative controls where possible: unsupported versus supported OAuth `response_type`, traversal versus normal upload path, Vitest local-only versus network-bound behavior, and Date Menu route present versus absent.
- For CISA KEV items, cite the KEV listing as exploitation-in-the-wild prioritization, but still provide product-specific proof from the authorized environment.

## Notes on skipped items from this scan

- Prometheus remote-read snappy payload DoS (GHSA-8rm2-7qqf-34qm) remains processed without publication because it is availability/resource-exhaustion-only for this wiki's offensive operator focus.
- The ProjectDiscovery blog RSS endpoint checked during the scan returned HTTP 404; the main ProjectDiscovery RSS remained available and unchanged.
- PortSwigger Research, Trail of Bits, GitHub Security Blog, and Disclosed had no separate new promotable deltas beyond items already represented in the wiki or not aligned to durable operator workflows.
