# Gogs proxy-auth, OpenCTI ingestion SSRF, motionEye file-read, and Paymenter upload boundary checks

Source: hourly offensive-security scan, 2026-06-22. Primary entries: GitHub advisories [GHSA-w6j9-vw59-27wv](https://github.com/advisories/GHSA-w6j9-vw59-27wv) / CVE-2026-25119, [GHSA-ffm6-vvph-g5f5](https://github.com/advisories/GHSA-ffm6-vvph-g5f5) / CVE-2026-21887, [GHSA-4mvw-j8r9-xcgc](https://github.com/advisories/GHSA-4mvw-j8r9-xcgc) / CVE-2024-37155, [GHSA-g9fx-5r4h-pcw3](https://github.com/advisories/GHSA-g9fx-5r4h-pcw3) / CVE-2026-31978, [GHSA-rhgp-6wq6-9j67](https://github.com/advisories/GHSA-rhgp-6wq6-9j67) / CVE-2026-32315, and [GHSA-5pm9-r2m8-rcmj](https://github.com/advisories/GHSA-5pm9-r2m8-rcmj) / CVE-2025-58048.

This batch is durable because the advisories share repeatable operator workflows: reverse-proxy identity headers crossing from the public client into application authentication, ingestion URLs becoming server-side requests, GraphQL introspection filters relying on brittle query formatting, media-preview paths reaching files outside a camera media root, local world-readable configuration exposing password hashes for chained validation, and authenticated attachments crossing into a public/executable storage path.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-w6j9-vw59-27wv](https://github.com/advisories/GHSA-w6j9-vw59-27wv) / CVE-2026-25119 | Gogs reverse-proxy authentication | client-controlled `X-WEBAUTH-USER`-style headers were trusted when reverse-proxy auth was enabled, without proving the request came from a trusted proxy | Test self-hosted Git forges by sending spoofed identity headers directly to the app listener and through each edge route; positive evidence is limited to a disposable canary user/session. |
| [GHSA-ffm6-vvph-g5f5](https://github.com/advisories/GHSA-ffm6-vvph-g5f5) / CVE-2026-21887 | OpenCTI data ingestion | user-supplied external URLs reached Axios with absolute URL handling enabled | Treat threat-intel ingestion, connector, enrichment, and import URLs as SSRF surfaces; prove only with owned callbacks and synthetic internal canary services. |
| [GHSA-4mvw-j8r9-xcgc](https://github.com/advisories/GHSA-4mvw-j8r9-xcgc) / CVE-2024-37155 | OpenCTI GraphQL introspection restriction | regex-based introspection blocking could be bypassed by query formatting changes | GraphQL hardening claims need compacted, aliased, multiline, and fragment-based negative controls; evidence is schema metadata for a lab tenant only. |
| [GHSA-g9fx-5r4h-pcw3](https://github.com/advisories/GHSA-g9fx-5r4h-pcw3) / CVE-2026-31978 | motionEye picture/movie preview endpoints | encoded traversal in preview filename paths reached filesystem reads as the motionEye process user | Media preview and thumbnail routes need the same path-containment tests as download routes; prove with synthetic files owned by the lab service account, not real secrets. |
| [GHSA-rhgp-6wq6-9j67](https://github.com/advisories/GHSA-rhgp-6wq6-9j67) / CVE-2026-32315 | motionEye configuration files | `/etc/motioneye/motion.conf` and camera configs could be world-readable and contain admin password hashes or camera settings | Local foothold reviews should include service config permissions and hash exposure, but stop at showing readability and hash presence unless cracking is explicitly authorized. |
| [GHSA-5pm9-r2m8-rcmj](https://github.com/advisories/GHSA-5pm9-r2m8-rcmj) / CVE-2025-58048 | Paymenter ticket attachments | authenticated low-privilege uploads could land in public storage with executable server handling | Ticket, support, invoice, and customer-portal attachments need upload-to-serving-path validation with inert files and server header/body evidence; do not publish shells or run commands. |

Adjacent [GHSA-3qq3-668m-v9mj](https://github.com/advisories/GHSA-3qq3-668m-v9mj) was processed but not promoted as a standalone workflow because the public details center on repository/wiki file-listing denial of service via Git pathspec parsing. Revisit it only if paired with an authorization, disclosure, or durable parser-differential path beyond availability impact.

## Operator triage

1. **Map deployment topology before testing.** For Gogs, identify whether the app is reachable directly behind the reverse proxy, whether reverse-proxy auth is enabled, and which header name is configured. Do not assume `X-WEBAUTH-USER` if the deployment changed the header.
2. **Separate direct-client, proxy, and server-side reachability.** SSRF and proxy-auth bypasses depend on route placement. Record whether a request was sent to the public edge, the internal app listener, or an application feature that performs the outbound request.
3. **Use owned canaries only.** Callback domains, fake users, synthetic GraphQL tenants, temporary media files, and harmless upload markers are enough. Do not read production config, customer camera media, `.env` files, cloud metadata, or internal service responses.
4. **Prove the boundary, not maximum impact.** A canary session created by a forged proxy header, a blind callback from OpenCTI, a schema field disclosed by bypassed introspection, or an inert uploaded marker served with executable handling is sufficient for a report.
5. **Chain only inside an approved lab.** motionEye config readability plus preview traversal may form useful chains, but cracking hashes, reusing camera credentials, or reading unrelated files requires explicit authorization and a disposable environment.

## Replayable validation boundaries

### Reverse-proxy authentication header harness

- Preconditions: written permission to test the Gogs deployment, a disposable low-privilege account, and confirmation that reverse-proxy authentication is expected in scope.
- Send a baseline unauthenticated request to a harmless authenticated route, then repeat with the configured proxy-auth header set to the disposable username.
- Test both paths separately: through the public reverse proxy and, if in scope, directly to the backend listener or service port.
- Positive evidence is an authenticated response, user auto-creation, or session state for the disposable account when the request did not traverse a trusted identity proxy.
- Negative controls: backend listener not externally reachable, edge strips identity headers from clients, app validates source proxy, and auto-registration is disabled or scoped.

### OpenCTI ingestion SSRF and GraphQL introspection harness

- Create a lab OpenCTI tenant and a canary HTTP endpoint under an owned domain.
- Submit ingestion/import/enrichment URLs that should be rejected by policy and one allowed canary URL. For redirect tests, keep the redirect target owned; do not point at cloud metadata or production internal services.
- For semi-blind SSRF, record only callback timing, source IP, method, path, and headers that do not include secrets.
- For introspection controls, compare a normal introspection query with compacted, no-whitespace, alias, fragment, and line-ending variants. Capture schema-field presence for lab objects only.
- Negative controls: URL parser canonicalization before fetch, scheme and host allowlists applied after redirects, egress isolation, and GraphQL validation rules rather than regex-only query matching.

### motionEye media and configuration harness

- Use a disposable camera/media root with a synthetic outside-root marker readable by the motionEye lab process.
- Compare download/content routes and preview/thumbnail routes with the same encoded traversal filename matrix, including `%2F`-encoded separators, without targeting real files.
- Check file permissions on lab `motion.conf` and `camera-*.conf`; report only whether non-privileged local users can read synthetic `@admin_password` or camera-setting markers.
- Negative controls: canonical path containment before every open/delete/preview path, traversal rejection before URL decoding ambiguity reaches `os.path.join()`, and `0600` config permissions owned by the service user.

### Paymenter attachment serving harness

- Use a disposable low-privilege customer/support account and upload benign files only: text markers, image polyglots without executable content, and extension/MIME mismatch canaries.
- Record where the attachment is stored, the public URL shape, response headers, and whether the server treats the file as a download or active content.
- Do not upload web shells, execute server-side code, read `.env`, or touch production customer tickets.
- Negative controls: random outside-webroot storage, forced download headers, extension allowlists, content sniffing disabled, and route authorization on attachment retrieval.

## Reporting notes

- State the crossed boundary precisely: **client header to trusted reverse-proxy identity**, **ingestion URL to server-side request**, **GraphQL query text to schema-introspection policy**, **media preview path to outside-root file read**, **local config mode to password-hash disclosure**, or **support attachment to executable public storage**.
- Evidence should be boring: route matrices, canary callbacks, synthetic users, harmless uploaded markers, path-resolution tables, and redacted headers.
- Avoid mitigation-first framing; lead with reachability, preconditions, exact trust boundary, and canary impact within the authorized environment.
