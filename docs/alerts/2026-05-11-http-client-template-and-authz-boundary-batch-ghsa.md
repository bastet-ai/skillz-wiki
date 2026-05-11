# HTTP client, template loader, and authorization-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because each advisory is a boundary-enforcement failure in a component that commonly runs with broader privileges than the untrusted input it processes: HTTP clients, template loaders, multi-tenant APIs, and user-memory endpoints.

## Advisories covered

- **Velociraptor cross-organization file read** — [GHSA-2v93-vp82-cjv8](https://github.com/advisories/GHSA-2v93-vp82-cjv8): `www.velocidex.com/golang/velociraptor <0.76.4` lets a root-organization reader issue an authenticated HTTP GET that reads files from other organizations without target-org permissions.
- **python-liquid absolute-path template include** — [GHSA-8p4x-wr7x-3788](https://github.com/advisories/GHSA-8p4x-wr7x-3788): `python-liquid <2.2.0` `FileSystemLoader` and `CachingFileSystemLoader` can resolve absolute paths outside configured search roots via `{% include %}` and `{% render %}`.
- **urllib3 streaming decompression bomb bypass** — [GHSA-mf9v-mfxr-j63j](https://github.com/advisories/GHSA-mf9v-mfxr-j63j): `urllib3 >=2.6.0,<2.7.0` can fully decompress highly compressed streaming responses during specific Brotli `read(amt=N)` or `drain_conn()` flows, consuming CPU and memory.
- **urllib3 proxied low-level redirect credential forwarding** — [GHSA-qccp-gfcp-xxvc](https://github.com/advisories/GHSA-qccp-gfcp-xxvc): `urllib3 >=1.23,<2.7.0` can forward `Authorization`, `Cookie`, or `Proxy-Authorization` across origins when callers follow redirects through low-level `ProxyManager.connection_from_url().urlopen(..., assert_same_host=False)` paths.
- **Open WebUI memories API authorization gaps** — [GHSA-hmjq-crxp-7rjw](https://github.com/advisories/GHSA-hmjq-crxp-7rjw): `open-webui <0.6.19` lets standard users query, leak, delete, and restore other users' memories through inconsistent memory endpoint checks.

## Operator triage

1. Patch HTTP-client libraries and framework apps where untrusted URLs, redirects, or response bodies are processed on behalf of users.
2. Search for direct urllib3 low-level proxy use with `assert_same_host=False`, manual redirect handling, `drain_conn()`, and streaming reads against attacker-controlled hosts.
3. For template engines, grep for user-controlled `{% include %}`, `{% render %}`, template names, and absolute-path-capable loaders; treat template-author permission as filesystem-read permission until fixed.
4. For Velociraptor and Open WebUI, audit access logs for low-privilege users enumerating cross-org resources, memory IDs, bulk memory queries, deletes, or restore-like updates.
5. If patching is delayed, restrict affected admin APIs to trusted networks and reduce service-account filesystem and data-store privileges.

## Durable controls

- Redirect handling must remove sensitive headers after the final parsed origin changes, regardless of whether the caller uses high-level or low-level APIs.
- Streaming decompression needs global output, CPU, and expansion-ratio budgets, not only chunk-size budgets.
- Filesystem loaders should reject absolute paths, parent traversal, symlinks escaping the root, and platform-specific separator tricks before any read.
- Multi-tenant APIs should authorize against the target tenant/object on every endpoint, not against only the caller's source organization or UI-visible list.
- Memory, note, and AI-context APIs should treat read, search, delete, restore, and update as separate privileges with object-owner checks.

