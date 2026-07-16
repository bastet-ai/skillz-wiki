# TensorZero, ToolHive, local app, vault, and MCP documentation boundary checks

Source: hourly offensive-security scan, 2026-07-15 GitHub advisory wave. Primary entries: [GHSA-824w-x939-6cmc](https://github.com/advisories/GHSA-824w-x939-6cmc), [GHSA-pr64-jmmf-jp54](https://github.com/advisories/GHSA-pr64-jmmf-jp54), [GHSA-q78p-hj9h-5466](https://github.com/advisories/GHSA-q78p-hj9h-5466), [GHSA-62gx-5q78-wrvx](https://github.com/advisories/GHSA-62gx-5q78-wrvx), [GHSA-pph6-vfjv-vpjw](https://github.com/advisories/GHSA-pph6-vfjv-vpjw), [GHSA-xgch-x3mx-cm3c](https://github.com/advisories/GHSA-xgch-x3mx-cm3c), [GHSA-f5pf-q7c7-m3vv](https://github.com/advisories/GHSA-f5pf-q7c7-m3vv), and [GHSA-6f5r-5672-72j7](https://github.com/advisories/GHSA-6f5r-5672-72j7).

This batch is durable because the advisories expose repeatable operator boundaries: user-controlled object-storage configuration crossing into gateway file reads and outbound fetches, remote MCP discovery responses steering host-side authentication metadata fetches outside ToolHive's container sandbox, browser-readable local developer apps through wildcard CORS, local vault APIs that decode path separators after framework routing, SSRF guards that omit IPv6 transition or special-purpose ranges, downloader crawler selection that treats host substrings as trusted service identity, and documentation-server web UIs that bind to all interfaces with unauthenticated corpus administration APIs.

!!! warning "Authorized validation only"
    Keep proofs to disposable TensorZero gateways, ToolHive and MCP documentation-server labs, local FiftyOne/Obsidian labs, owned browser origins, synthetic vaults, owned callback domains, fake object stores, canary files, fake API keys, and isolated IPv6/NAT64 test networks. Do not read real credentials, notebooks, datasets, Obsidian notes, cloud metadata, customer media, production object stores, browser profile data, live downloader API keys, real MCP documentation corpora, or host-side environment variables. Do not write or delete files outside disposable lab canary paths.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-824w-x939-6cmc](https://github.com/advisories/GHSA-824w-x939-6cmc) | TensorZero Gateway `/internal/object_storage` | Caller-supplied JSON `storage_path` can override object-storage configuration; `filesystem` reads gateway-local paths and `s3_compatible` can steer outbound object-storage requests | Treat internal object-storage helpers as sensitive control-plane APIs. Validate whether request bodies can swap storage backend, endpoint, bucket, or root path before proving only with marker files and owned endpoints. |
| [GHSA-pr64-jmmf-jp54](https://github.com/advisories/GHSA-pr64-jmmf-jp54) / CVE-2026-58196 | ToolHive remote MCP authentication discovery | A remote MCP server controls `WWW-Authenticate` / resource-metadata discovery URLs that ToolHive fetches host-side, before and outside the per-server container sandbox, without private-IP or redirect guards | Test agent/MCP discovery flows as host-side SSRF surfaces. The operator value is proving that untrusted server metadata crosses from a sandboxed tool relationship into the orchestrator host's network context. |
| [GHSA-q78p-hj9h-5466](https://github.com/advisories/GHSA-q78p-hj9h-5466) | FiftyOne local App/API server and `/media` route | Unauthenticated localhost app responses set `Access-Control-Allow-Origin: *`; browser pages on arbitrary origins can read local API/media responses, including path-selected files exposed by `/media` | Add drive-by browser-origin checks to local AI/data-science tools: bind-to-localhost is not enough when wildcard CORS lets malicious websites read loopback responses. |
| [GHSA-62gx-5q78-wrvx](https://github.com/advisories/GHSA-62gx-5q78-wrvx) | `obsidian-local-rest-api` `/vault/{path}` handlers | Express routes see `%2F` as data, then handlers call `decodeURIComponent` and pass reconstituted `../` segments to vault adapter read/write/delete paths without vault-root confinement | Test framework-router normalization and handler-level decoding as separate parser stages. Encoded separators that survive route matching can become traversal only after application decoding. |
| [GHSA-pph6-vfjv-vpjw](https://github.com/advisories/GHSA-pph6-vfjv-vpjw) | ToolHive SSRF guard used by OAuth CIMD fetcher and protected HTTP clients | Hand-rolled private/reserved IP checks miss NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`; affected IPv6-only/NAT64 deployments can allow internal/link-local reachability probes | Include IPv6 transition-address fixtures in SSRF allowlist testing, especially for OAuth metadata fetchers and agent/tool registries that resolve hosts before dialing. |
| [GHSA-xgch-x3mx-cm3c](https://github.com/advisories/GHSA-xgch-x3mx-cm3c) | Go `safeurl` library | Private-network blocklist misses newer IPv6 special-purpose ranges including NAT64 local-use, SRv6 SIDs, documentation, and dummy prefixes | Treat URL-safety libraries as policy snapshots. Regression-test guard libraries against current IANA/RFC special-purpose ranges, not only RFC1918 and loopback. |
| [GHSA-f5pf-q7c7-m3vv](https://github.com/advisories/GHSA-f5pf-q7c7-m3vv) | `cyberdrop-dl-patched` Pixeldrain crawler | Crawler selection matches supported service hostnames by substring, then sends the user's Pixeldrain `Authorization` header to the attacker-controlled host used in the URL | Add exact-host and redirect-authority checks to downloader, scraper, and crawler assessments where service-specific credentials are attached after URL classification. |
| [GHSA-6f5r-5672-72j7](https://github.com/advisories/GHSA-6f5r-5672-72j7) / CVE-2026-54504 | `@andrea9293/mcp-documentation-server` Web UI/API | The default Web UI listens on all interfaces (`0.0.0.0:3080`) and exposes document-management endpoints without authentication | Add default-bind and unauthenticated corpus-admin checks to MCP documentation/search helpers. Network-local exposure can turn a developer convenience UI into document read/write/delete/search access. |

## Replayable validation boundaries

### TensorZero object-storage override checks

1. Stand up a TensorZero Gateway version below `2026.6.0` in a lab with authentication configured both on and off if those deployment modes are in scope.
2. Create a disposable gateway-local canary file outside any intended object-storage root, and create an owned HTTP/S3-compatible mock endpoint that logs only request method, host, path, and a synthetic marker.
3. Exercise `/internal/object_storage` first with the legitimate configured object-storage path and record the expected behavior.
4. Replay with a request body that attempts to select a `filesystem` backend rooted at the canary directory. Stop once the response proves marker-file reachability; never target `/etc`, environment files, SSH keys, model weights, or application secrets.
5. Replay with an `s3_compatible` backend pointing only at the owned mock endpoint. Record whether the gateway makes an outbound request and which attacker-controlled fields reach the request.
6. Add controls for patched `2026.6.0`, authenticated versus unauthenticated gateway access, blocked `/internal/object_storage`, non-existent canary paths, and legitimate object-storage configuration.

Report this as **caller-controlled object-storage config -> internal helper swaps storage backend/root/endpoint -> gateway file-read or outbound-fetch boundary**. Evidence should be route, auth state, backend type, canary filename or mock-request marker, and patched negative control.

### ToolHive remote MCP authentication-discovery SSRF checks

1. Stand up ToolHive below `0.31.0` in an isolated lab host with no production cloud credentials, and configure a disposable remote MCP server under your control.
2. Serve a normal MCP endpoint first and record the expected remote-server connection and authentication-discovery behavior.
3. Modify the controlled MCP server to return a `WWW-Authenticate` challenge or discovery response whose `resource_metadata` / authorization metadata URL points only to an owned callback listener. Record whether the ToolHive host, not a per-server container, makes the request.
4. Repeat with a single redirect from the owned public URL to a synthetic private-address listener inside the lab network if the engagement explicitly permits redirect-boundary SSRF tests. Do not use cloud metadata, Kubernetes APIs, loopback admin panels, or third-party internal hosts.
5. Compare with ToolHive's normal remote URL validation and protected-client SSRF guard paths: the finding is strongest when the configured remote server URL is blocked for internal targets but the server-supplied discovery URL is fetched without the same guard.
6. Add controls for patched ToolHive, disabled remote-server authentication discovery, no `WWW-Authenticate` challenge, invalid metadata URLs, HTTPS/TLS failures, redirect refusal, DNS rebinding if explicitly in scope, and egress proxy behavior.

Report this as **untrusted remote MCP server metadata -> ToolHive host-side auth discovery fetch -> sandbox/egress isolation bypass via SSRF**. Evidence should include the discovery field class, callback source address or host process context, redirect decision, guard mismatch, and patched or disabled-discovery negative control. Keep all callbacks marker-only.

### FiftyOne local wildcard-CORS file-read checks

1. Run an affected FiftyOne release below `1.17.0` on a disposable workstation profile with a synthetic dataset and a canary file under a temporary directory.
2. Serve a test page from an owned non-localhost origin. From that page, issue browser `fetch()` requests to the local FiftyOne server and `/media` route.
3. Confirm whether responses include `Access-Control-Allow-Origin: *` and whether browser JavaScript can read the response body from the non-localhost origin.
4. For `/media`, request only the synthetic canary file path. Do not request home directories, notebooks, credentials, dataset media outside the canary, cloud config, browser profile data, or SSH material.
5. Add controls for FiftyOne `1.17.0`, same-origin access, disabled local server, browsers with Private Network Access restrictions where available, and non-existent file paths.

Report this as **browser visit -> wildcard CORS on unauthenticated local app -> cross-origin read of local API/media response**. Evidence should include origin, target localhost URL class, CORS header, browser-read marker, and patched/default-origin controls.

### Obsidian Local REST API encoded-separator traversal checks

1. Build a disposable Obsidian profile and vault with the Local REST API plugin enabled. Use a lab API key and redact it from all notes.
2. Place one marker file inside the vault and one marker file in a temporary sibling directory outside the vault root.
3. Confirm that literal `../` traversal is rejected or normalized by the route layer.
4. Replay GET against `/vault/..%2F..%2F.../canary` using a client mode that preserves encoded separators on the wire. Stop at reading the synthetic outside-vault marker.
5. If write/delete tests are authorized, write only to a pre-created disposable canary path outside the vault and immediately remove it through normal filesystem cleanup, not through destructive production paths.
6. Add controls for MOVE if it already has a confinement guard, patched plugin versions, URL-encoded `%2e%2e`, Windows path separators if in scope, invalid API keys, and non-vault routes.

Report this as **router-normalized path differs from handler-decoded path -> encoded separators reconstitute traversal -> vault adapter reaches outside root**. Evidence should be method, encoded path class, route-layer literal traversal control, marker result, and vault-root confinement control. Never read real notes or host secrets.

### IPv6 SSRF guard coverage checks

1. Build a local harness for ToolHive `<= 0.29.0` and `safeurl < 0.2.4`, or test the affected product/library inside an approved lab component that exposes a URL-fetch feature.
2. Prepare owned callback hosts and synthetic IPv6 addresses for: ordinary public IPv6, loopback/link-local, RFC1918-through-NAT64 using `64:ff9b::/96`, local-use NAT64 using `64:ff9b:1::/48`, and the special-purpose ranges named by `safeurl` (`5f00::/16`, `3fff::/20`, `100:0:0:1::/64`) where routing can be simulated safely.
3. For ToolHive, focus on the OAuth Client ID Metadata Document fetcher or another in-scope URL path that uses the same guarded dialer. Keep proof to blind callback or decision-table evidence.
4. For library-only targets, record whether the guard classifies each range as blocked before any network dial occurs.
5. Add controls for patched ToolHive `0.29.1`, safeurl `0.2.4`, IPv6 disabled, DNS A/AAAA rebinding, literal IPs versus hostname resolution, redirect hops, and TLS-verification failures.

Report this as **URL safety guard omits IPv6 transition/special-purpose range -> protected fetcher can reach a synthetic internal-address class**. Evidence should be range, textual URL, resolved IP, guard decision, network side effect, and patched/library negative control. Do not target metadata services or production internal addresses.

### Service-host substring credential relay checks

1. Configure `cyberdrop-dl-patched` below `9.14.0` with a fake Pixeldrain API key in an isolated profile.
2. Create an owned HTTPS host whose name contains the trusted service string but is not an official service domain, and log only whether an `Authorization` header with the fake marker key arrives.
3. Feed the downloader a URL on that host through the same ingestion path used for forum, page, or batch downloads.
4. Record whether crawler selection accepts the substring match and sends service-specific API requests to the attacker-controlled authority.
5. Add controls for exact official domains, unrelated domains, patched `9.14.0`, mixed-case hosts, IDN/punycode variants, redirects to untrusted authorities, and stripped credentials on cross-origin requests.

Report this as **host substring classification -> service crawler attaches API key -> credential header sent to attacker-controlled authority**. Use fake credentials only; never test with live Pixeldrain keys or third-party sites.

### MCP documentation-server default-bind and unauthenticated corpus-admin checks

1. Install `@andrea9293/mcp-documentation-server` `1.13.0` in a disposable lab with `MCP_BASE_DIR` pointing to a temporary directory containing only synthetic documents.
2. Start the server with default Web UI settings (`START_WEB_UI` not set to `false`, default or lab-selected `WEB_PORT`).
3. From the host, confirm whether the Web UI/API listens on all interfaces rather than only `127.0.0.1`. Record listener class only; avoid publishing real hostnames or interface inventories.
4. From a separate lab client on the same LAN, VM network, or container bridge, send unauthenticated requests to only marker-safe endpoints: configuration presence, document list, add a synthetic document, search for a marker string, read that synthetic document, then delete that same document.
5. Add controls for `START_WEB_UI=false`, explicit localhost binding if supported by a patched or hardened build, firewall-blocked access, authentication headers that should not be required for the vulnerable path, and non-lab network segments that should be out of scope.

Report this as **developer MCP helper starts web UI on all interfaces -> unauthenticated network client can administer documentation corpus**. Evidence should be package version, bind address class, network vantage point, endpoint family, marker document ID/content, and disabled or localhost-only negative control. Do not read or delete real documentation, embeddings, API keys, configuration secrets, or user files.

## Reporting notes

- Lead with preconditions: exposed TensorZero gateway access, ToolHive remote MCP trust state, MCP documentation-server Web UI settings, local FiftyOne/Obsidian server state, browser origin, API-key/auth state, IPv6/NAT64 network assumptions, and downloader credential configuration.
- Prefer decision tables over payload dumps: route, actor, supplied URL/path/host, parser stage or guard decision, target class, marker effect, and negative control.
- Redact API keys, callback tokens, local file paths beyond synthetic temp directories, browser origin secrets, object-storage credentials, vault names, interface names, document corpus contents beyond markers, and any request body field that would reveal production topology.
- The same scan included WebSocket resource-exhaustion/corruption advisories. They were marked processed without promotion because this run did not identify a safe, durable operator workflow beyond availability-limit testing.
