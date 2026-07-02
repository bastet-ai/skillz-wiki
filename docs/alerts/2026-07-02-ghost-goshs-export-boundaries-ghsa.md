# Ghost preview-cache, goshs share/WebDAV, and export file-boundary checks

Source: hourly offensive-security scan, 2026-07-02. Primary entries: GitHub Advisory Database [GHSA-62q6-4hv4-vjrw](https://github.com/advisories/GHSA-62q6-4hv4-vjrw) / CVE-2026-53943, [GHSA-3whc-qvhv-xqjp](https://github.com/advisories/GHSA-3whc-qvhv-xqjp) / CVE-2026-50138, [GHSA-j48m-h7xq-2xpj](https://github.com/advisories/GHSA-j48m-h7xq-2xpj) / CVE-2026-50139, [GHSA-v45h-mqf4-6939](https://github.com/advisories/GHSA-v45h-mqf4-6939) / CVE-2025-48977, and [GHSA-mpmf-3w4r-qfpf](https://github.com/advisories/GHSA-mpmf-3w4r-qfpf) / CVE-2026-9804.

These advisories are durable for operators because they expose reusable boundaries across publishing platforms, temporary file shares, data-grid REST APIs, and Kubernetes VM export workflows: request headers crossing into shared cache keys, one-use share tokens enforced after transfer instead of before transfer, alternate WebDAV listeners bypassing HTTP mode flags, log-path selectors escaping intended log roots, and export symlinks reaching pod-local files. Keep proofs to lab instances, harmless markers, tiny canary files, disposable namespaces, and fake share links only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-62q6-4hv4-vjrw](https://github.com/advisories/GHSA-62q6-4hv4-vjrw) / CVE-2026-53943 | Ghost frontend behind shared caches | unauthenticated `x-ghost-preview` requests could alter rendered frontend output that a cache then stores for later visitors | Test whether request-specific preview state is part of the cache key before claiming a Ghost/CDN deployment is isolated. |
| [GHSA-3whc-qvhv-xqjp](https://github.com/advisories/GHSA-3whc-qvhv-xqjp) / CVE-2026-50138 | `goshs <= v2.0.9` WebDAV listener | WebDAV routes ignored `--read-only`, `--upload-only`, and `--no-delete` flags enforced by the primary HTTP routes | File-share reviews need per-protocol mode matrices; do not assume HTTP route flags apply to WebDAV, SFTP, or alternate listeners. |
| [GHSA-j48m-h7xq-2xpj](https://github.com/advisories/GHSA-j48m-h7xq-2xpj) / CVE-2026-50139 | `goshs <= v2.0.9` share links | download counters were incremented after serving the file, allowing concurrent requests to redeem a single-use token more than once | Temporary-share assessments should include concurrency proofs for one-use and limited-use links using harmless canary files. |
| [GHSA-v45h-mqf4-6939](https://github.com/advisories/GHSA-v45h-mqf4-6939) / CVE-2025-48977 | Apache Ignite REST API `cmd=log` | authenticated log path input could traverse outside the expected log file boundary | Treat diagnostic log endpoints as file-read APIs; validate path canonicalization with synthetic log markers only. |
| [GHSA-mpmf-3w4r-qfpf](https://github.com/advisories/GHSA-mpmf-3w4r-qfpf) / CVE-2026-9804 | KubeVirt `virt-exportserver` VMExport directory endpoint | symlinks inside an exported PVC could point outside the mount root and disclose exporter pod-local files | VM/disk export flows need symlink and realpath controls; prove with disposable PVC content and pod-local marker files, never service-account tokens. |

## Operator triage

1. **Separate origin behavior from cache behavior.** For Ghost, first confirm the origin renders different output when `x-ghost-preview` is present, then test whether the shared cache varies on that header.
2. **Build a route/protocol capability matrix.** For `goshs`, compare primary HTTP and WebDAV ports for `GET`, `PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`, share-token redemption, and configured mode flags.
3. **Probe consumption limits under concurrency.** Any one-shot download link, invite, reset, or export token should be tested with parallel requests before accepting the limit as enforced.
4. **Treat diagnostics and exports as filesystem APIs.** Ignite log reads and KubeVirt VM exports are not just admin conveniences; they cross from user-controlled selectors into server or pod filesystems.
5. **Keep evidence synthetic and bounded.** Use canary pages, throwaway share files, fake logs, and lab PVCs. Do not read staff sessions, real documents, customer VM files, pod service-account tokens, or production logs.

## Replayable validation boundaries

### Ghost `x-ghost-preview` shared-cache poisoning check

- Preconditions: owned Ghost lab or explicitly authorized customer test, shared caching layer in front of Ghost, no staff users browsing the test path, and a harmless public page created for the case.
- Send baseline requests for the canary page without `x-ghost-preview` and record cache headers, `Age`, `Via`, and response hash.
- Send a request with `x-ghost-preview` containing only a harmless preview marker or use the minimal header form described by the advisory; do not inject script or staff-targeting payloads.
- Re-request the same URL without the header from a separate client or cache-busted control path.
- Positive evidence: the no-header client receives preview-altered output or a marker that should have varied on `x-ghost-preview`.
- Negative controls: patched Ghost, cache bypass for preview-header requests, cache key variation on preview headers, and separate frontend/admin domains where applicable.

### `goshs` WebDAV mode-flag matrix

- Preconditions: disposable `goshs` instance, temp directory with only synthetic files, Basic Auth test credentials, WebDAV enabled, and no real engagement artifacts.
- Start separate cases for `--read-only`, `--upload-only`, and `--no-delete`.
- For each case, test the primary HTTP port and WebDAV port with harmless verbs: `GET`, `PROPFIND`, `PUT` of `skillz-webdav-canary.txt`, `DELETE` of a disposable file, and `MKCOL` for a marker directory.
- Positive evidence: the primary HTTP route denies the action while WebDAV permits the same class of action.
- Negative controls: fixed version or wrapper guard that applies mode flags to every WebDAV state-changing verb.
- Do not point the share root at home directories, source trees, reports, credential stores, or customer data.

### `goshs` one-shot share race harness

- Preconditions: disposable file share, one tiny canary file, generated one-use token, and no sensitive link contents.
- Create a `limit=1` or equivalent share token for the canary file.
- Fire two or more parallel requests for the same token and record status codes, byte counts, and server-side download counter state.
- Positive evidence: multiple clients receive the canary despite a one-use limit.
- Negative controls: fixed version that reserves the download count before serving, serial request that fails after the first redemption, and retry behavior for failed transfers.
- Stop at marker files; do not race password resets, invite links, production exports, or real customer shares.

### Ignite REST `cmd=log` path-boundary check

- Preconditions: authenticated Ignite lab user, disposable Ignite node, synthetic log directory, and a harmless canary file outside the approved log root.
- Confirm the normal `cmd=log` request can read an approved synthetic log path.
- Try traversal/canonicalization variants only against the harmless outside-root canary file; record request path, normalized path if available, status, and returned marker decision.
- Positive evidence: the log command returns the outside-root canary content.
- Negative controls: patched Apache Ignite 2.18.0 or later, canonical realpath root checks, and denial for symlink or traversal segments.
- Never request `/etc/passwd`, private keys, cloud credentials, kubeconfigs, application secrets, or production logs.

### KubeVirt VMExport symlink escape check

- Preconditions: isolated cluster, disposable namespace, throwaway VM/PVC, namespace-level test identity matching the advisory preconditions, and no real VM disks or service-account token evidence.
- Place a symlink inside the exported PVC that points only to a pod-local synthetic marker file created for the test environment.
- Request the VMExport directory endpoint for the symlink path and record whether the marker is returned.
- Positive evidence: the export endpoint follows the symlink outside the mounted PVC/export root.
- Negative controls: fixed KubeVirt build, `O_NOFOLLOW`/realpath enforcement, and denial when the resolved target leaves the export root.
- Do not target `/var/run/secrets/kubernetes.io/serviceaccount`, real pod config, tenant VM data, host paths, or cluster credentials.

## Reporting notes

- Lead with the crossed boundary: **preview header to shared cache entry**, **WebDAV route to ignored mode flag**, **share token to post-transfer counter race**, **diagnostic log path to outside-root file**, or **PVC symlink to exporter pod-local read**.
- Include affected version, deployment topology, exact route/protocol, synthetic marker label, positive/negative decision table, and fixed-version or configuration control.
- Keep the exploit narrative scoped to authorized validation. Avoid publishing staff-account takeover payloads, production cache poisoning details, sensitive file paths, or destructive file-share actions.
