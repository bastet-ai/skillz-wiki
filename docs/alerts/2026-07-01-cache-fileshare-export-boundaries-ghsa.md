# Cache, fileshare, and export-boundary checks

Source: hourly offensive-security scan, 2026-07-01. Primary entries: GitHub Advisory Database [GHSA-62q6-4hv4-vjrw](https://github.com/advisories/GHSA-62q6-4hv4-vjrw), [GHSA-3whc-qvhv-xqjp](https://github.com/advisories/GHSA-3whc-qvhv-xqjp), [GHSA-j48m-h7xq-2xpj](https://github.com/advisories/GHSA-j48m-h7xq-2xpj), [GHSA-v45h-mqf4-6939](https://github.com/advisories/GHSA-v45h-mqf4-6939), and [GHSA-mpmf-3w4r-qfpf](https://github.com/advisories/GHSA-mpmf-3w4r-qfpf).

These advisories are durable for operators because they expose recurring validation boundaries: request-specific preview headers being stored by shared caches, alternate file-serving protocols bypassing HTTP-mode restrictions, one-shot share-token counters racing under concurrency, log-viewer path selectors escaping intended directories, and VM/exporter symlinks crossing from tenant-controlled data into pod-local files. Keep proofs to lab services, synthetic canary pages/files, disposable users, and owned cache/export infrastructure.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-62q6-4hv4-vjrw](https://github.com/advisories/GHSA-62q6-4hv4-vjrw) / CVE-2026-53943 | Ghost `4.0.0` through `6.36.0` | unauthenticated `x-ghost-preview` requests could alter rendered frontend responses that a shared cache then serves to later visitors | Cache-poisoning tests should include feature headers and staff/front-end domain co-tenancy, not only URL/query keys. |
| [GHSA-3whc-qvhv-xqjp](https://github.com/advisories/GHSA-3whc-qvhv-xqjp) / CVE-2026-50138 | `goshs <= 2.0.9` WebDAV listener | `--read-only`, `--upload-only`, and `--no-delete` were enforced on the primary HTTP port but not the WebDAV port | Test every exposed protocol for the same mode policy; WebDAV verbs often bypass route-level HTTP checks. |
| [GHSA-j48m-h7xq-2xpj](https://github.com/advisories/GHSA-j48m-h7xq-2xpj) / CVE-2026-50139 | `goshs <= 2.0.9` share links | one-shot `?token=` download limits were checked before serving and incremented after serving, allowing concurrent redemptions | Race single-use secret/share links with harmless files to validate reservation-before-use semantics. |
| [GHSA-v45h-mqf4-6939](https://github.com/advisories/GHSA-v45h-mqf4-6939) / CVE-2025-48977 | Apache Ignite REST API `cmd=log` | authenticated log-path selectors could read files outside the intended log boundary | Management/log viewer APIs should prove path confinement with synthetic canaries, not live logs or secrets. |
| [GHSA-mpmf-3w4r-qfpf](https://github.com/advisories/GHSA-mpmf-3w4r-qfpf) / CVE-2026-9804 | KubeVirt `virt-exportserver` VMExport directory endpoint | symlinks inside an exported PVC could point outside the designated mount root and expose exporter pod-local files | Export endpoints that package tenant-controlled filesystems need final-target checks; prove only with marker files in lab pods. |

## Operator triage

1. **Map cache keys before payloads.** Identify the CDN/proxy cache key, vary headers, preview/staff headers, admin/front-end domain split, and whether authenticated preview routes share cache with anonymous pages.
2. **Enumerate alternate protocols.** If a file server exposes HTTP plus WebDAV, SFTP, sync, or archive export paths, verify mode restrictions on each protocol and verb family.
3. **Race counters safely.** Single-use links, download caps, invite codes, and export tokens should reserve capacity before expensive work. Use tiny benign canary files and stop at a two-request proof.
4. **Treat log/export paths as file selectors.** Management endpoints that read logs or exported volumes should be tested with canaries under approved lab directories only.
5. **Record negative controls.** Include fixed-version behavior, cache-bypass decisions, verb decision tables, exactly-one-success race results, and realpath/symlink denial evidence.

## Replayable validation boundaries

### Shared-cache preview-header poisoning

- Preconditions: owned Ghost lab or customer-approved test instance, disposable page/post, shared cache under your control, no staff sessions or production audience, and clear permission to send preview headers.
- Create a canary page whose anonymous response is safe to cache. Send a request with `x-ghost-preview` and a harmless visible marker such as `SKILLZ_PREVIEW_CACHE_<case-id>`.
- Request the same URL without the header from a separate client/cache path and compare response body, cache status headers, and `Vary` behavior.
- Positive evidence is header-influenced content served to a later no-header visitor from the shared cache.
- Do not target live staff/admin sessions, steal cookies, inject executable payloads, or poison production content.

### WebDAV mode-policy bypass

- Preconditions: disposable `goshs` lab directory, affected version, WebDAV enabled, fake Basic credentials, and files containing only marker text.
- Start separate cases for `--read-only`, `--upload-only`, and `--no-delete`; record expected denial on the primary HTTP port first.
- Exercise WebDAV verbs `PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`, `GET`, and `PROPFIND` against the WebDAV port.
- Positive evidence is a WebDAV status code and filesystem marker showing a mode-prohibited operation succeeded.
- Do not run against production file shares, engagement evidence directories, or customer artifacts.

### Share-token concurrency race

- Preconditions: disposable server, tiny public canary file, one generated share token with `limit=1`, and a local concurrency harness.
- Fire two or more simultaneous `GET /?token=<canary>` requests and record status codes plus server-side downloaded/deleted state.
- Positive evidence is more than one successful response for a one-use token.
- Stop at minimal concurrency; do not race real secret links, mailbox links, paid downloads, or high-volume traffic.

### Log API and VM export symlink/file-boundary checks

- Preconditions: authenticated lab user, synthetic log/export marker files, disposable Kubernetes namespace or Ignite lab, and no mounted production secrets.
- For Ignite-style log viewers, create an allowed log canary and an outside-root canary, then test only path forms needed to prove whether `cmd=log` escapes the intended directory.
- For KubeVirt-style exports, place a symlink in an exported PVC that targets a pod-local marker file specifically created for the test; request only that marker path through the export endpoint.
- Positive evidence is the synthetic outside marker returned where the boundary should deny it.
- Never request `/etc/shadow`, service-account tokens, kubeconfigs, application logs with user data, VM disks, or customer files.

## Reporting notes

- Lead with the boundary crossed: **preview header to shared cached response**, **WebDAV verb to file mode bypass**, **share-token counter to concurrent over-redemption**, **log path to outside file**, or **export symlink to pod-local file**.
- Include versions, cache/proxy topology, exact route or protocol, decision table, canary labels, and patched negative controls.
- Keep impact claims bounded. Do not claim account takeover, secret theft, or cluster compromise unless the authorized lab demonstrates that specific downstream effect with disposable accounts and canaries.
