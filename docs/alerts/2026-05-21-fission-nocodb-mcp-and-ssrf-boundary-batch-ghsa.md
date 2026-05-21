# Fission, NocoDB, MCP, and SSRF boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-21.

This batch is durable because it turns fresh advisories into replayable checks for serverless build/runtime privilege boundaries, shared-link persistence, OAuth/API-token scope drift, MCP tool execution controls, application SSRF, and PDF-render command/file fetch edges.

## What changed

- **Fission builder command execution** — [GHSA-7pjr-qpvh-m339](https://github.com/advisories/GHSA-7pjr-qpvh-m339): vulnerable `github.com/fission/fission <=1.22.0` passed `Environment.spec.builder.command` into `exec.Command(...)` after only `strings.Fields` splitting. A user with `create` or `update` on `Environment` objects could run arbitrary executables inside the builder pod and alter package deployment artifacts.
- **Fission runtime service-account token exposure** — [GHSA-85g2-pmrx-r49q](https://github.com/advisories/GHSA-85g2-pmrx-r49q): vulnerable Fission runtime pods used the `fission-fetcher` service account and exposed its automounted token inside user function containers, letting function code read namespace-wide secrets and configmaps rather than only `Function.spec.secrets`.
- **NocoDB shared-base persistence and token scope drift** — [GHSA-chqv-vrj7-qffp](https://github.com/advisories/GHSA-chqv-vrj7-qffp), [GHSA-m5qg-rvjq-727p](https://github.com/advisories/GHSA-m5qg-rvjq-727p), [GHSA-f76x-f9vj-92jv](https://github.com/advisories/GHSA-f76x-f9vj-92jv): vulnerable `nocodb <=0.301.3` let shared-base callers invite persistent members, let restricted OAuth tokens inherit the underlying user's broader ACL, and allowed deleted API tokens to keep authenticating until cache expiry.
- **NocoDB SSRF and upload-by-URL limits** — [GHSA-2c5x-4jgf-88mj](https://github.com/advisories/GHSA-2c5x-4jgf-88mj), [GHSA-8rwr-f68v-cvw6](https://github.com/advisories/GHSA-8rwr-f68v-cvw6), [GHSA-99vc-2jx2-688p](https://github.com/advisories/GHSA-99vc-2jx2-688p): vulnerable notification webhook plugins passed SSRF-filter agents in the request body rather than axios config, and upload-by-URL paths failed to enforce configured attachment-size limits before or during download.
- **NocoDB refresh-token and redirect XSS edges** — [GHSA-f74w-272x-mqcv](https://github.com/advisories/GHSA-f74w-272x-mqcv), [GHSA-9qgr-6vpg-9gh9](https://github.com/advisories/GHSA-9qgr-6vpg-9gh9): vulnerable refresh-token cookies lacked `secure` and `sameSite`, and the page-leaving warning accepted `javascript:` redirect URLs.
- **MCP Server Kubernetes tool-control bypass** — [GHSA-cr22-wjx7-2w6m](https://github.com/advisories/GHSA-cr22-wjx7-2w6m): vulnerable `mcp-server-kubernetes <3.6.0` enforced `ALLOW_ONLY_READONLY_TOOLS`, `ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS`, and `ALLOWED_TOOLS` only in `tools/list`, not `tools/call`, so clients that knew hidden tool names could invoke destructive or exec-capable Kubernetes tools directly.
- **FlaskBB avatar SSRF** — [GHSA-xq32-9g7q-7297](https://github.com/advisories/GHSA-xq32-9g7q-7297): vulnerable `flaskbb <=2.2.0` passed authenticated profile avatar URLs into `requests.get(..., stream=True)` without host, scheme, or IP filtering, enabling blind SSRF and internal port/API triggering.
- **Snappy PDF command and file-fetch boundaries** — [GHSA-vpr4-p6fq-85jc](https://github.com/advisories/GHSA-vpr4-p6fq-85jc), [GHSA-c5fp-p67m-gq56](https://github.com/advisories/GHSA-c5fp-p67m-gq56): vulnerable `KnpLabs/knp-snappy <=1.7.0` had a dead shell-escape branch for the binary path, and `knplabs/knp-snappy <=1.6.0` allowed attacker-influenced `xsl-style-sheet` values to drive local-file or SSRF fetches through `wkhtmltopdf`.
- **phpMyFAQ admin-boundary drift** — [GHSA-9r8r-x3vg-6xh4](https://github.com/advisories/GHSA-9r8r-x3vg-6xh4), [GHSA-rmqr-h98c-qg2m](https://github.com/advisories/GHSA-rmqr-h98c-qg2m): vulnerable `phpMyFAQ <4.1.2` let ordinary authenticated users reach admin-only API endpoints and let admins with `INSTANCE_DELETE` traverse out of the intended client folder for recursive directory deletion.

## Operator triage

1. Search target inventories for Fission `<=1.22.0`, `nocodb <=0.301.3`, `mcp-server-kubernetes <3.6.0`, FlaskBB `<=2.2.0`, Knp Snappy `<=1.7.0`, and phpMyFAQ `<4.1.2`.
2. For Fission, map who can create/update `Environment` CRDs, which namespaces host runtime pods, whether tenant-authored functions run there, and whether runtime containers can reach the Kubernetes API.
3. For NocoDB, enumerate shared-base links, OAuth clients/scopes, webhook plugin permissions, upload-by-URL features, deleted-token cache windows, and refresh-token cookie behavior under HTTPS.
4. For MCP Kubernetes servers, capture the configured tool restriction environment variables, exposed transport type, client population, and any network path that lets a client send raw `tools/call` requests.
5. For SSRF and renderer edges, identify user-controlled avatar URLs, webhook URLs, upload-by-URL fields, `wkhtmltopdf` binary configuration, and Snappy options that accept free-form URLs or file schemes.
6. For phpMyFAQ, distinguish frontend authenticated users from backend/admin users and collect exact API routes that expose backend-only operational data.

## Replayable validation boundaries

- **Fission builder proof:** in an authorized lab namespace, create a disposable `Environment` whose builder command writes a harmless marker into a package build output. Vulnerable result: the builder pod executes the configured executable instead of enforcing an expected builder entrypoint allowlist.
- **Fission token proof:** deploy an inert function that reads only the service-account token metadata and attempts a Kubernetes API `get` for a lab-owned secret/configmap. Stop at a redacted marker; do not enumerate unrelated namespace secrets.
- **NocoDB shared-link proof:** with a test base and shared-base UUID, request the member list or send an invite to a controlled email. Vulnerable result: shared-link context creates a persistent authenticated member that survives link revocation.
- **NocoDB OAuth/API-token proof:** issue a restricted OAuth token or delete a test API token, then call a route outside the expected scope or repeat authentication during the cache window. Keep actions read-only and use disposable tokens.
- **NocoDB webhook SSRF proof:** configure a controlled webhook URL pointing at a benign collaborator endpoint that represents the internal host class. Vulnerable result: the notification plugin performs the outbound POST despite configured SSRF filtering.
- **MCP Kubernetes proof:** configure read-only or explicit allowed-tool mode, hide a destructive test tool from `tools/list`, then send a direct `tools/call` for a harmless lab command such as listing a disposable namespace. Vulnerable result: execution ignores the presentation-layer restriction.
- **FlaskBB avatar proof:** as an ordinary authenticated test user, set an avatar URL to a benign collaborator endpoint or internal canary. Vulnerable result: the server-side `get_image_info()` request reaches the canary.
- **Snappy proof:** if the binary path or stylesheet option is attacker-influenced, pass only harmless marker values: a binary string that creates a lab marker file in a disposable container, or an `xsl-style-sheet` URL/file canary with no sensitive path.
- **phpMyFAQ proof:** with a normal user account, request a backend-only API endpoint that returns non-sensitive version or health metadata. For traversal, use only a disposable client folder and marker directory.

## Reporting heuristics

- Show the trust boundary that failed: Kubernetes CRD privilege to builder pod execution, function code to namespace secrets, shared-link viewer to persistent member, OAuth scope to full user ACL, presentation-only MCP filtering to actual tool execution, or URL/render input to server-side fetch/command behavior.
- Include exact product versions, role prerequisites, endpoint/tool names, request shape, and one redacted proof artifact.
- For SSRF, report both the attacker-controlled input and backend-observed callback; avoid real metadata, admin panels, or internal production services unless explicitly authorized.
- For token and shared-link issues, demonstrate persistence or scope mismatch with disposable users and tokens rather than live customer data.
- For renderer/command issues, keep payloads inert and prove command/file-fetch reachability in an isolated container.

## Notes on skipped items from this scan

- **Russh CryptoVec allocation** ([GHSA-g9f8-wqj9-fjw5](https://github.com/advisories/GHSA-g9f8-wqj9-fjw5)) was not promoted because current broad reachability is mostly local-agent/resource oriented; historical remote SSH reachability is version-specific and not yet a wiki-wide workflow.
- **Hulumi policy/drift/baseline advisories** ([GHSA-59f3-7227-wmh4](https://github.com/advisories/GHSA-59f3-7227-wmh4), [GHSA-q2f7-m237-v562](https://github.com/advisories/GHSA-q2f7-m237-v562), [GHSA-4xrh-5m3m-328w](https://github.com/advisories/GHSA-4xrh-5m3m-328w), [GHSA-g43v-9x7q-83pq](https://github.com/advisories/GHSA-g43v-9x7q-83pq), [GHSA-2ffm-hxrq-qqmm](https://github.com/advisories/GHSA-2ffm-hxrq-qqmm), [GHSA-gfp8-mp24-5vxg](https://github.com/advisories/GHSA-gfp8-mp24-5vxg)) were skipped as governance/policy-evaluation gaps without a broad authorized exploit-validation path for this wiki.
- **Umbraco and Cockpit stored/backoffice XSS** ([GHSA-vr9v-27gg-qgx4](https://github.com/advisories/GHSA-vr9v-27gg-qgx4), [GHSA-ch4j-vcf5-58x5](https://github.com/advisories/GHSA-ch4j-vcf5-58x5)) were skipped because the current details are role-specific UI injection rather than a new reusable render-boundary technique.
- **SpiceDB nested-list cache reuse** ([GHSA-mqcf-gqvg-rmhm](https://github.com/advisories/GHSA-mqcf-gqvg-rmhm)) and **Plonky3 transcript malleability** ([GHSA-vj64-rjf3-w3v7](https://github.com/advisories/GHSA-vj64-rjf3-w3v7)) were skipped as highly specialized authorization/crypto proof issues.
