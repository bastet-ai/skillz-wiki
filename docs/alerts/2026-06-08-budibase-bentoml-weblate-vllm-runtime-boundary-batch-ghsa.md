# Budibase, BentoML, Weblate, vLLM, and API/runtime boundary batch

Source: hourly offensive-security scan, 2026-06-08. Primary entries: GitHub advisories [GHSA-xh5j-727m-w6gg](https://github.com/advisories/GHSA-xh5j-727m-w6gg), [GHSA-5vpg-rj7q-qpw2](https://github.com/advisories/GHSA-5vpg-rj7q-qpw2), [GHSA-hggm-x7r9-mm7v](https://github.com/advisories/GHSA-hggm-x7r9-mm7v), [GHSA-wqpv-c3pp-3m58](https://github.com/advisories/GHSA-wqpv-c3pp-3m58), [GHSA-v959-cwq9-7hr6](https://github.com/advisories/GHSA-v959-cwq9-7hr6), [GHSA-fgv4-6jr3-jgfw](https://github.com/advisories/GHSA-fgv4-6jr3-jgfw), [GHSA-jfjg-vc52-wqvf](https://github.com/advisories/GHSA-jfjg-vc52-wqvf), [GHSA-f8hv-g549-hwg2](https://github.com/advisories/GHSA-f8hv-g549-hwg2), [GHSA-558g-h753-6m33](https://github.com/advisories/GHSA-558g-h753-6m33), [GHSA-mqph-7h49-hqfm](https://github.com/advisories/GHSA-mqph-7h49-hqfm), [GHSA-pj86-258h-qrvf](https://github.com/advisories/GHSA-pj86-258h-qrvf), [GHSA-cj47-qj6g-x7r4](https://github.com/advisories/GHSA-cj47-qj6g-x7r4), and [GHSA-vpwc-v33q-mq89](https://github.com/advisories/GHSA-vpwc-v33q-mq89).

This batch is durable because the advisories repeat high-value operator patterns: archive/plugin URL SSRF filters that trust filename substrings, framework view-parameter name collisions, media path validation bypasses, ML build/deploy command injection, translation-platform add-on trust boundaries, exposed model-serving RPC deserialization, and GraphQL WebSocket authentication drift.

## What changed

- **Budibase plugin URL SSRF** — self-hosted Budibase plugin upload accepts a URL if `.tar.gz` appears anywhere in the string, then fetches it from the server. The useful testing pattern is a low-privilege Global Builder role reaching internal URLs through an archive-name validation bypass.
- **Yii 2 view rendering LFI** — `View::renderPhpFile()` extracts caller-supplied params before requiring the view file. A parameter named `_file_` can collide with the internal include variable, creating local file inclusion when attacker-controlled params reach view rendering.
- **OpenClaw media path traversal** — media parsing path checks can be bypassed through `isLikelyLocalPath()` / `isValidMedia()` logic and bare-filename handling, allowing reads outside the intended application sandbox.
- **OpenStack Ironic console execution surface** — a non-default Ironic console-interface configuration allows `ipmitool` execution. Treat this as a configuration-gated control-plane boundary, not a default internet-facing bug.
- **BentoML build/deploy code execution** — BentoML advisories describe three bento-controlled inputs that execute during packaging or deployment: unsandboxed Jinja2 `dockerfile_template`, unquoted `docker.system_packages` in generated Dockerfiles, and unquoted `system_packages` in BentoCloud deployment setup scripts.
- **Weblate add-on and backup trust boundaries** — Weblate advisories cover SSRF in the webhook add-on, backup-restore remote code execution, JavaScript localization CDN add-on local file reads, and over-permissive webhook endpoints that can trigger mass repository updates and component enumeration.
- **vLLM RPC pickle deserialization** — vLLM's `AsyncEngineRPCServer()` RPC path can deserialize pickle payloads. The operator value is finding deployments where this internal RPC listener is reachable across tenant, host, or network boundaries.
- **Strawberry GraphQL WebSocket auth bypass** — legacy `graphql-ws` subprotocol handling can bypass expected authentication. This belongs in GraphQL recon when HTTP auth checks pass but WebSocket subscription auth is untested.

## Operator triage

1. **Find build and plug-in ingestion surfaces:** inventory Budibase `/api/plugin`, BentoML bento import/containerize/deploy flows, Weblate backup restore, Weblate add-ons, and any CI/CD job that consumes user-supplied archives, templates, model packages, or project configuration.
2. **Separate role-gated from unauthenticated impact:** Budibase requires a Global Builder-style role, Yii depends on a caller-controlled view params path, OpenStack Ironic depends on non-default console configuration, and vLLM RPC impact depends on whether the RPC listener crosses a trust boundary.
3. **Prioritize internal-fetch primitives:** Budibase and Weblate SSRF checks are strongest where the server can reach internal control planes, cloud metadata proxies, source repositories, or private package registries. Use tester-controlled canaries first.
4. **Map framework and control-plane versions to reachable code paths:** version banners alone are weak. Strong evidence shows the exact endpoint, route group, add-on, view rendering path, or build/deploy command path reachable in the target.
5. **Look for ML/AI deployment shortcuts:** BentoML and vLLM findings matter most in hosted notebook, model-evaluation, inference-as-a-service, MLOps, or agent-platform environments where users submit model artifacts or start runtime workers.
6. **Check alternate protocols:** for Strawberry, test WebSocket subscription flows separately from HTTP GraphQL queries and mutations. Legacy subprotocols often travel through different authentication middleware.

## Replayable validation boundaries

### Budibase plugin SSRF

- Use an account and role explicitly in scope; do not attempt to escalate beyond plugin upload permissions.
- Submit a plugin URL containing `.tar.gz` in a query string or path while pointing to a tester-controlled canary endpoint.
- Capture only the callback metadata needed to prove server-side fetch: timestamp, source IP, HTTP method, path, and user agent.
- Do not target cloud metadata, internal admin panels, or third-party hosts unless the program has explicitly authorized those destinations.

### Yii 2 `_file_` view-parameter collision

- Prove the application passes attacker-controlled params into Yii view rendering before testing file inclusion.
- Use benign local canary files in a lab or application-owned scratch path. Avoid reading `/etc/passwd`, secrets, config files, or customer data on production targets.
- Report the call chain: request parameter, controller/action, params array, `_file_` collision, and included file path.
- If the target also has a file-write primitive, keep LFI and write-to-RCE chaining clearly separated and only chain with written authorization.

### OpenClaw media path traversal

- Start with path-normalization controls: valid media file, rejected traversal, and the bypass form that is accepted.
- Read only synthetic canaries placed by the tester or target owner. The finding is the sandbox escape, not the contents of sensitive files.
- Capture the media parser entry point, accepted path form, normalized path, and response evidence.

### Ironic control-plane boundaries

- Treat bare-metal control planes as high-impact systems. Validate only in labs or explicitly scoped management networks.
- For Ironic, document the non-default console-interface configuration and demonstrate command reach with a benign marker in a disposable lab node.

### BentoML build and deployment execution

- Use a disposable bento project with a harmless marker command, such as writing `bentoml-canary` under `/tmp` during `containerize` or deployment setup.
- Exercise each path separately: `dockerfile_template` Jinja2 rendering, `docker.system_packages` in Dockerfile generation, and cloud deployment setup script generation.
- Do not exfiltrate environment variables, credentials, model files, or cloud metadata. If a hosted build runner is in scope, stop at a canary marker or outbound DNS callback.
- Report whether untrusted users can upload/import bentos, trigger container builds, or trigger BentoCloud deployments.

### Weblate add-ons, backup restore, and webhooks

- For webhook SSRF, configure a tester-controlled callback URL and record server-side fetch evidence only.
- For backup restore RCE, use an isolated Weblate lab or program-provided test tenant. Do not restore untrusted archives into shared production instances.
- For JavaScript localization CDN local file reads, target only planted canary files and show the add-on crossing the repository boundary.
- For over-permissive webhook behavior, use a test component or repository and demonstrate enumeration or mass-update capability without touching production translations.

### vLLM RPC and Strawberry WebSocket auth

- For vLLM, first prove the RPC listener is exposed beyond its intended local worker boundary. Do not send destructive pickle payloads to production; use a lab payload that writes a marker or a safe deserialization detector.
- Capture listener address, network path, deployment topology, and whether authentication or network policy protects the RPC channel.
- For Strawberry, replay an authenticated HTTP GraphQL control and a legacy `graphql-ws` WebSocket subscription control. The finding is auth drift between transports/subprotocols.
- Avoid subscription floods or long-lived high-volume WebSocket tests; a single unauthorized subscription to a benign field is enough.

## Reporting heuristics

- Lead with the **trust-boundary crossing**: low-privileged builder to server-side fetch, bento artifact to build host command, add-on configuration to internal fetch/file read, internal RPC to code execution, or WebSocket legacy protocol to auth bypass.
- Include negative controls: URL without `.tar.gz` versus bypass form, safe view param versus `_file_`, protected OAM route versus unprotected UPI route, trusted bento versus malicious bento, HTTP GraphQL versus WebSocket GraphQL.
- Keep proof artifacts inert and reversible: DNS/HTTP canaries, scratch files, marker commands in disposable environments, and scoped test repositories.
- Do not publish secrets, internal URLs, customer translation content, model weights, or raw pickle payloads in reports.

## Notes on skipped items from this scan

- Availability-only DoS entries for Bandit, Nimiq, Dalfox, free5GC BSF, Ironic checksum pre-validation, Twisted, xgrammar, Wasmtime crash cases, vLLM image/cache failures, Tornado, Strawberry subscription exhaustion, PyTorch local DoS, and Spark encryption strength were marked processed without standalone publication.
- free5GC SMF UPI management exposure ([GHSA-3258-qmv8-frp3](https://github.com/advisories/GHSA-3258-qmv8-frp3)) was already covered in [free5GC mobile-core auth and crash-boundary batch](2026-05-08-mobile-core-auth-and-crash-boundary-batch-ghsa.md), so this run marked the updated-feed item processed without duplicating that guidance.
- Sparse product-specific stored XSS, permission, cache-control, enumeration, brute-force, weak-secret, and data-exposure items for Filament, MantisBT, Kong diagnostics, Shopper, Wagtail, Overhang Tutor, Vantage6, Taguette, and WebSSH were not promoted because they did not add a new reusable operator workflow beyond existing XSS, IDOR, or information-disclosure checks.
- TeleJSON DOM XSS and pyLoad configuration/path entries were left to existing render-boundary and pyLoad boundary coverage rather than creating separate pages.
