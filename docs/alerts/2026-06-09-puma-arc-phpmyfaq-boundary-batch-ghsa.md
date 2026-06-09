# Puma PROXY, Arc DuckDB, and phpMyFAQ boundary batch

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-2vqw-3mp8-cgmx](https://github.com/advisories/GHSA-2vqw-3mp8-cgmx) / CVE-2026-47737, [GHSA-qpgp-93vx-g8v8](https://github.com/advisories/GHSA-qpgp-93vx-g8v8) / CVE-2026-47736, [GHSA-p2j4-c4g6-rpf5](https://github.com/advisories/GHSA-p2j4-c4g6-rpf5) / CVE-2026-47735, and the phpMyFAQ advisory wave including [GHSA-289f-fq7w-6q2w](https://github.com/advisories/GHSA-289f-fq7w-6q2w), [GHSA-9pq7-mfwh-xx2j](https://github.com/advisories/GHSA-9pq7-mfwh-xx2j), [GHSA-hpgw-ww76-c68r](https://github.com/advisories/GHSA-hpgw-ww76-c68r), [GHSA-jrc5-w569-h7h5](https://github.com/advisories/GHSA-jrc5-w569-h7h5), [GHSA-pm8c-3qq3-72w7](https://github.com/advisories/GHSA-pm8c-3qq3-72w7), and [GHSA-99qv-g4x9-mgc3](https://github.com/advisories/GHSA-99qv-g4x9-mgc3).

This batch is durable because it captures reusable operator patterns: PROXY-protocol trust replay across persistent HTTP connections, direct listener memory pressure before HTTP parsing, SQL-as-a-feature escaping into local file reads and SSRF through DuckDB table functions, and FAQ/admin-console authz failures where ordinary headers, TOTP user IDs, OAuth token fields, or non-terminating permission checks become exploit paths.

## What changed

- **Puma PROXY protocol v1 source spoofing** — when `set_remote_address proxy_protocol: :v1` is enabled and persistent connections reach Puma, a second `PROXY` line between keep-alive requests can overwrite `REMOTE_ADDR` for the next request. Puma defaults are not affected; the signal is a non-default PROXY-protocol deployment where application logic trusts `REMOTE_ADDR`.
- **Puma PROXY protocol v1 pre-parse memory exhaustion** — with the same non-default configuration, a TCP client can keep sending bytes without `\r\n` so Puma continues appending to its PROXY-line buffer before normal HTTP parsing.
- **Arc DuckDB local-file read and SSRF** — authenticated `/api/v1/query` access, even with empty permissions, can call DuckDB I/O table functions such as `read_csv_auto`, `read_json`, `read_blob`, `glob`, or metadata readers outside RBAC table extraction. The advisory confirms reads of local config/token databases and SSRF when `httpfs` is loaded.
- **phpMyFAQ unauthenticated SQLi and 2FA workflow gaps** — phpMyFAQ `<= 4.1.1` includes unauthenticated SQL injection through the `User-Agent` header on `GET /api/captcha`, plus unauthenticated `/admin/check` TOTP probing that accepts arbitrary `user-id` values without binding to a prior password phase or rate limiting.
- **phpMyFAQ authenticated authorization drift** — additional advisories describe non-terminating admin permission checks, frontend users reaching admin API information endpoints, OAuth token fields interpolated into SQL, and unauthenticated FAQ permission bypass through `solution_id` redirects.

## Operator triage

1. **Find PROXY-enabled Puma, not just Ruby apps:** search deploy configs, container env, and Puma DSL files for `set_remote_address proxy_protocol: :v1`. Prioritize apps behind HAProxy, nginx stream, Envoy, ALB/NLB-style relays, or platform routers that preserve keep-alive connections to Puma.
2. **Tie source spoofing to a decision:** useful findings show that rewritten `REMOTE_ADDR` changes rate limits, IP allowlists, fraud controls, audit attribution, admin route access, tenant routing, or request signing logic. Source-IP log mismatch alone is weaker.
3. **Inventory SQL console products with embedded engines:** Arc is the concrete case, but the reusable heuristic is user-controlled SQL routed into engines with filesystem and network table functions. Look for DuckDB, SQLite extension loading, Parquet/CSV importers, and analytics APIs that claim RBAC by parsing `FROM` and `JOIN` only.
4. **Map phpMyFAQ exposure by route:** confirm version and route reachability before sending payloads: `/api/captcha`, `/admin/check`, `/admin/api/index.php/...`, OAuth callback/token flows, and public `/solution_id_{id}.html` redirects.
5. **Separate anonymous from role-bound impact:** phpMyFAQ captcha SQLi and TOTP probing are pre-auth; admin permission leakage and OAuth token SQLi require authenticated or configured identity-provider paths; stored XSS requires content/comment contribution paths and should be reported separately from server-side SQLi.

## Replayable validation boundaries

### Puma PROXY protocol checks

- Only test systems where PROXY protocol v1 is explicitly enabled and in scope. Sending raw PROXY lines to ordinary HTTP listeners can break connection handling.
- For source spoofing, use one TCP connection through the trusted proxy path: send a normal request, keep the connection alive, then place a second benign `PROXY TCP4 203.0.113.10 ...` line before the next HTTP request. Use documentation/example IPs and prove only whether `REMOTE_ADDR` or IP-derived behavior changed.
- For resource pressure, use a lab clone or customer-approved test window. A short, bounded no-CRLF stream is enough to demonstrate unbounded pre-parse buffering; do not intentionally OOM production Puma workers.
- Capture config evidence, connection topology, transcript ordering, request IDs, and the affected downstream control. Redact real client IPs and session cookies.

### Arc DuckDB I/O boundary checks

- Validate with a test token and planted canary files under a disposable path first. Do not read `/etc/passwd`, environment variables, token databases, S3 keys, TLS keys, or tenant data from production.
- Compare a normal table query with a scalar/table-function query that references a planted file, for example a CSV or text canary. The report should show that RBAC allowed no table access but DuckDB I/O still returned file-controlled content.
- Test SSRF only with a tester-controlled HTTP endpoint unless internal metadata probing is explicitly authorized. Record the callback and stop there.
- Include whether `httpfs` or other extensions are loaded, the exact vulnerable function family, API route, token permission set, and whether patched deployments set `enable_external_access = false` and restrict allowed directories.

### phpMyFAQ route and identity-boundary checks

- For `GET /api/captcha` SQLi, use a time-differential or boolean canary in a lab or explicitly authorized instance. Do not extract database rows; a single controlled delay and a safe negative control are enough.
- For `/admin/check`, use disposable accounts with TOTP enabled. Prove the endpoint accepts an arbitrary `user-id` without a prior password-authenticated session; do not brute-force real codes.
- For admin permission bypasses, create low-privilege and high-privilege test accounts. Verify whether the low-privilege account receives protected page content or admin API data after an apparent forbidden response.
- For OAuth token SQLi, use a controlled identity-provider test account with synthetic token/display-name values. Avoid real refresh tokens, access tokens, or IdP production logs.
- For `solution_id` permission bypass, plant a private FAQ with a known title and confirm whether the public redirect leaks existence and metadata. Do not enumerate sequential IDs at scale.

## Reporting heuristics

- Lead with the **boundary crossed**: trusted edge IP to application identity, SQL-console user to host filesystem/network, anonymous header to database query, anonymous user ID to TOTP verification, or low-privilege admin to protected admin data.
- Include environmental preconditions: Puma PROXY v1 enabled, keep-alive path to Puma, Arc DuckDB function availability, phpMyFAQ version `<= 4.1.1`, enabled comments/OAuth/TOTP where relevant, and reachable public/admin routes.
- Use canaries over secrets. Strong reports prove impact with planted files, documentation IPs, disposable users, test FAQ entries, and request IDs rather than sensitive reads or destructive state changes.
- Keep repeated advisories grouped by product and sink. The phpMyFAQ wave is most useful as a route-by-route authorization and input-boundary checklist, not as separate generic CVE summaries.

## Notes on skipped items from this scan

- Dulwich crafted thin-pack memory allocation (GHSA-xrvj-v92f-53gj) and Puma memory exhaustion are availability/resource-boundary items; only Puma was included because the same configuration also produces a durable PROXY-protocol trust-boundary spoofing workflow.
- Sparse duplicate phpMyFAQ GHSA records and XSS-only variants were marked processed without standalone publication; the reusable phpMyFAQ operator guidance above covers the route, sanitizer, and authorization-boundary themes.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, Disclosed, and CISA KEV had no separate new promotable deltas beyond items already represented in the wiki.
