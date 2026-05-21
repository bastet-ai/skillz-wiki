# Fission, MLflow, Langflow, SSRF, and Crabbox boundary batch

Source: GitHub Security Advisories REST fallback and CISA KEV, published/updated 2026-05-21.

This batch is durable because it gives operators reusable checks for serverless function invocation boundaries, unauthenticated control-plane routes, CORS-to-token theft chains, redirect/sitemap SSRF bypasses, and repo-local remote-execution secret exposure.

## What changed

- **Fission router internal function invocation bypass** — [GHSA-3g33-6vg6-27m8](https://github.com/advisories/GHSA-3g33-6vg6-27m8): vulnerable `github.com/fission/fission <=1.22.0` exposed `/fission-function/<name>` and `/fission-function/<namespace>/<name>` on the public router listener, allowing callers who can reach the router to invoke functions even when no `HTTPTrigger` publishes them.
- **Fission StorageSvc unauthenticated archive CRUD** — [GHSA-chf8-4hv6-8pg6](https://github.com/advisories/GHSA-chf8-4hv6-8pg6): vulnerable Fission StorageSvc instances exposed `/v1/archive` and `/v1/archives` without authentication, allowing any pod or actor with network reachability to enumerate, download, upload, or delete function deployment archives.
- **MLflow FastAPI auth bypass** — [GHSA-75cm-x2w3-8mgf](https://github.com/advisories/GHSA-75cm-x2w3-8mgf): vulnerable `mlflow <3.10.0` left non-`/gateway/` FastAPI routes unprotected when the server was started with `--app-name basic-auth` under uvicorn/ASGI, exposing Job APIs and trace ingestion without authentication.
- **Langflow CORS/session refresh to token theft and RCE** — [CVE-2025-34291](https://nvd.nist.gov/vuln/detail/CVE-2025-34291), added to CISA KEV on 2026-05-21: Langflow `<=1.6.9` combined permissive credentialed CORS with a cross-site refresh-token cookie, letting a malicious origin obtain fresh victim tokens and then reach authenticated code-execution functionality.
- **pyload-ng redirect SSRF bypass** — [GHSA-8rp3-xc6w-5qp5](https://github.com/advisories/GHSA-8rp3-xc6w-5qp5): vulnerable `pyload-ng <0.5.0b3.dev100` checked only the initial `parse_urls` hostname; an attacker-controlled 302 redirect could send the backend to an internal/private IP via `HTTPRequest`.
- **Crawlee sitemap-derived SSRF** — [GHSA-3r75-xc34-5f44](https://github.com/advisories/GHSA-3r75-xc34-5f44): vulnerable `crawlee >=1.0.0 <1.7.0` accepted cross-host URLs from sitemaps or `robots.txt` `Sitemap:` directives, and the `CurlImpersonateHttpClient` path could also pass non-HTTP schemes such as `file://`, `gopher://`, or `ftp://`.
- **Crabbox repo-local environment exposure** — [GHSA-fm77-94qm-4894](https://github.com/advisories/GHSA-fm77-94qm-4894): vulnerable `github.com/openclaw/crabbox <0.12.0` allowed malicious or compromised repositories to forward local sensitive environment variables into remote command environments via permissive repo-local configuration.
- **Crabbox shared-token identity header spoofing** — [GHSA-4g9m-rffv-h6wq](https://github.com/advisories/GHSA-4g9m-rffv-h6wq): vulnerable Crabbox instances allowed non-admin shared-token callers to spoof `X-Crabbox-Owner` and `X-Crabbox-Org`, crossing owner/org scoped lease boundaries.

## Operator triage

1. Search dependency and deployment inventories for Fission `<=1.22.0`, `mlflow <3.10.0`, Langflow `<=1.6.9`, `pyload-ng <0.5.0b3.dev100`, `crawlee <1.7.0`, and Crabbox `<0.12.0`.
2. For Fission, map router exposure, namespaces, function names, non-HTTP-trigger functions, StorageSvc network reachability, and whether tenant workloads can reach ClusterIP services.
3. For MLflow and Langflow, identify externally reachable servers where authentication is assumed to protect job execution, trace ingestion, flow execution, component execution, or similar code-capable endpoints.
4. For SSRF items, inventory any target-controlled URL parsing, downloader, crawler, sitemap, or robots ingestion flow that can fetch attacker-hosted content before making backend requests.
5. For Crabbox, review repo-local config trust, allowed environment patterns, shared-token deployments, and reverse proxies that may preserve or inject identity headers.

## Replayable validation boundaries

- **Fission router proof:** in an authorized cluster, pick an inert function that lacks an `HTTPTrigger` or has method/path restrictions. Attempt only a harmless marker invocation through `/fission-function/<namespace>/<name>`. Vulnerable result: the function executes despite trigger policy.
- **Fission archive proof:** from an in-scope pod with ordinary network reachability, request the StorageSvc archive list or download one lab-owned function archive. Do not download unrelated tenant code or secrets; prove reachability and authorization failure with a disposable artifact.
- **MLflow route proof:** start from an unauthenticated session against an auth-enabled MLflow instance and request a non-destructive Job API or trace-ingestion route. Vulnerable result: the request is accepted without a session. Keep traces inert and avoid modifying production experiments.
- **Langflow browser-chain proof:** host a lab page on a separate origin and show whether credentialed cross-origin refresh requests return fresh tokens for a consenting test account. If tokens are obtained, stop at redacted proof or trigger only a harmless lab execution marker.
- **Redirect SSRF proof:** for pyload-ng, point `parse_urls` at an attacker-controlled URL that redirects to a benign collaborator endpoint representing the private target class. Vulnerable result: the backend follows the second-hop URL after validating only the first host.
- **Sitemap SSRF proof:** for Crawlee, serve a sitemap or `robots.txt` `Sitemap:` directive that points to a benign internal/collaborator marker. With `CurlImpersonateHttpClient`, separately test whether a non-HTTP scheme is queued or dispatched in a lab-only harness.
- **Crabbox environment proof:** in a disposable repository, configure an allowlist pattern for a harmless marker variable and verify whether it appears in the remote command environment. Do not forward real cloud/API credentials.
- **Crabbox identity proof:** with an authorized low-privilege shared token, send spoofed owner/org headers against a lab-owned lease namespace. Vulnerable result: the caller crosses into a different owner/org scope.

## Reporting heuristics

- For Fission, include router or StorageSvc reachability, function/archive identifiers, namespace boundaries, trigger policy expected behavior, and proof that invocation or archive access bypassed the intended publication model.
- For MLflow and Langflow, frame the issue as a full chain from auth/session boundary failure to a code-capable or data-modifying endpoint; include server mode, version, route, and token/session evidence with secrets redacted.
- For SSRF, report both validation points: the attacker-controlled first-hop input and the backend-observed second-hop/internal/scheme request. Avoid hitting real cloud metadata or internal admin services without explicit approval.
- For Crabbox, show the trust boundary crossed by repo-controlled configuration or spoofed identity headers, the exact non-secret marker used, and the owner/org or environment scope reached.
- Keep all validation scoped to owned tenants, lab functions, disposable repositories, and redacted marker values.

## Notes on skipped items from this scan

- **Umbraco Surface Controller open redirect** ([GHSA-2qjj-h6wp-c7h7](https://github.com/advisories/GHSA-2qjj-h6wp-c7h7)) was not promoted because it is useful phishing context but does not add a durable exploit-path workflow for this wiki on its own.
- **Nimiq advisories** ([GHSA-mw3q-r9wh-h2ff](https://github.com/advisories/GHSA-mw3q-r9wh-h2ff), [GHSA-vghx-352f-93jm](https://github.com/advisories/GHSA-vghx-352f-93jm), [GHSA-h9cc-w26m-j342](https://github.com/advisories/GHSA-h9cc-w26m-j342), [GHSA-799f-29jm-gr6c](https://github.com/advisories/GHSA-799f-29jm-gr6c)) were skipped as ecosystem-specific consensus/client proof issues or resource crashes.
- **LMDeploy `trust_remote_code=True`** ([GHSA-9xq9-36w5-q796](https://github.com/advisories/GHSA-9xq9-36w5-q796)) was already covered in the earlier 2026-05-21 LM runtime-boundary batch.
- **Trend Micro Apex One directory traversal** ([CVE-2026-34926](https://nvd.nist.gov/vuln/detail/CVE-2026-34926)) was not promoted because the public record currently describes a local, already-admin server prerequisite rather than a replayable external operator path.
