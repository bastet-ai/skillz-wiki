# NukeViet forwarded-host CMS and DIRAC eval-boundary checks

Source: hourly offensive-security scan, 2026-07-13 GitHub advisory wave. Primary entries: [GHSA-4chg-4752-w88r](https://github.com/advisories/GHSA-4chg-4752-w88r) / CVE-2026-55372, [GHSA-c9xg-64p9-f2jj](https://github.com/advisories/GHSA-c9xg-64p9-f2jj) / CVE-2026-54065, [GHSA-465g-4q99-5x86](https://github.com/advisories/GHSA-465g-4q99-5x86) / CVE-2026-54064, [GHSA-w2w5-w2pw-r929](https://github.com/advisories/GHSA-w2w5-w2pw-r929) / CVE-2026-49259, [GHSA-mxpf-qgg6-v3ff](https://github.com/advisories/GHSA-mxpf-qgg6-v3ff) / CVE-2026-48118, [GHSA-9jpv-c7p4-997x](https://github.com/advisories/GHSA-9jpv-c7p4-997x) / CVE-2026-45579, [GHSA-m4m7-4cw8-62j6](https://github.com/advisories/GHSA-m4m7-4cw8-62j6), [GHSA-7xw9-549r-8jrc](https://github.com/advisories/GHSA-7xw9-549r-8jrc), and [GHSA-vg99-gr89-qhw9](https://github.com/advisories/GHSA-vg99-gr89-qhw9).

This batch is durable because each item maps to a reusable operator boundary: forwarded proxy headers becoming a pre-auth outbound fetch target, CMS upload/comment metadata escaping its intended storage root during later cleanup, encoded or context-mismatched CMS content reaching trusted browser execution, authenticated grid/computing service parameters crossing into SQL or Python `eval()`, and pilot bootstrap code trusting an unverified transport channel before execution.

!!! warning "Authorized validation only"
    Keep proofs to disposable NukeViet and DIRAC labs. Use owned callback endpoints, synthetic comments/articles/users, harmless browser markers, inert RequestManager/FileCatalog/PilotManager canaries, fake pilot archives, and temp files created only for the test. Do not probe internal networks, delete production files, steal sessions, collect credentials, execute shell payloads, read `dirac.cfg`, dump tokens/proxies, tamper with production pilot distribution, or target real visitors.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-4chg-4752-w88r](https://github.com/advisories/GHSA-4chg-4752-w88r) | NukeViet `server_info_update()` | Pre-auth `__serverInfoUpdate` request trusts `X-Forwarded-Host` / `X-Forwarded-Proto` when building a cURL URL | Add forwarded-host SSRF checks to CMS install/base-URL helper paths, especially when proxy headers are consumed before authentication. |
| [GHSA-c9xg-64p9-f2jj](https://github.com/advisories/GHSA-c9xg-64p9-f2jj) | NukeViet comment attachment edit/delete | Admin-editable `attach` value is prefix-stripped, stored, then later joined under uploads while deletion only checks the broader app root | Test two-phase file operations where metadata is stored during edit but the filesystem effect occurs during cleanup/delete. |
| [GHSA-465g-4q99-5x86](https://github.com/advisories/GHSA-465g-4q99-5x86) | NukeViet news body filter | HTML5 whitespace/entity decoding differs from server-side anti-XSS filtering | Add browser-parser differential fixtures for CMS rich-text/news fields instead of trusting regex-only filters. |
| [GHSA-w2w5-w2pw-r929](https://github.com/advisories/GHSA-w2w5-w2pw-r929) | NukeViet comment reply template | Profile display-name data is HTML-entity encoded but inserted into an inline JavaScript string | Test every profile/comment variable in its final output context: HTML text, attribute, URL, and JavaScript string are different sinks. |
| [GHSA-mxpf-qgg6-v3ff](https://github.com/advisories/GHSA-mxpf-qgg6-v3ff) | NukeViet comment status loader | Base64-like status parameter is filtered before decode and paired with a site-wide reusable `checkss` token | Check encoded-message flows where validation happens before decoding and anti-forgery tokens are not bound to user/session state. |
| [GHSA-9jpv-c7p4-997x](https://github.com/advisories/GHSA-9jpv-c7p4-997x) | DIRAC RequestManager counters | Authenticated `groupingAttribute` reaches RequestDB dynamic evaluation when it misses an expected allowlist | Add API-parameter-to-dynamic-evaluation checks to scientific/grid/control-plane services that expose reporting or counter endpoints. |
| [GHSA-m4m7-4cw8-62j6](https://github.com/advisories/GHSA-m4m7-4cw8-62j6) | DIRAC FileCatalog DatasetManager | Authenticated dataset input reaches SQL construction, the query result is passed into `eval()`, and the attacker can shape the evaluated value | Chain source-to-sink checks across database result materialization and later dynamic evaluation instead of stopping at the SQLi primitive. |
| [GHSA-7xw9-549r-8jrc](https://github.com/advisories/GHSA-7xw9-549r-8jrc) | DIRAC PilotManager service | Pilot status/accounting parameters pass to the database layer without escaping and selected service methods also miss access-control checks | Add authenticated scientific-control-plane tests for both SQL grammar boundaries and method-level role gates. |
| [GHSA-vg99-gr89-qhw9](https://github.com/advisories/GHSA-vg99-gr89-qhw9) | DIRAC pilot bootstrap | The first-stage wrapper downloads `pilot.tar` and its checksum over an HTTPS path with certificate validation disabled, then executes the fetched pilot code | Treat job bootstrap/update channels as code-execution supply-chain boundaries; prove with lab-only fake pilot artifacts and TLS-decision evidence. |

## Replayable validation boundaries

### NukeViet forwarded-host SSRF canary

1. Stand up a NukeViet lab older than the patched line and place it behind the same proxy-header behavior used by the target environment.
2. Run an owned HTTPS callback listener that records only request method, path, Host header, and timestamp. Do not point probes at metadata endpoints, loopback services, RFC1918 hosts, or third-party systems.
3. Send a pre-auth request that exercises the server-info update path and supplies a controlled `X-Forwarded-Host` / `X-Forwarded-Proto` pair for the owned callback host.
4. Confirm whether the lab server issues an outbound request to the callback URL and whether the request path resembles the expected `index.php?response_headers_detect=1` helper.
5. Add negative controls: no forwarded headers, a configured allowed site domain, a disallowed host on the patched version, and a request without the update trigger.

Report this as **pre-auth helper trigger -> forwarded Host/Proto trust -> server-side cURL to attacker-owned endpoint**. Evidence should be callback metadata and route timing only.

### NukeViet stored metadata to file-delete boundary

1. In a disposable lab, create a canary file under the application root that is safe to remove and not part of NukeViet configuration, uploads, logs, or source code.
2. As an administrator, edit a synthetic comment and set the attachment metadata to a path that should remain confined to the comment upload directory.
3. Delete only that synthetic comment and observe whether the canary outside the upload directory is removed.
4. Include controls for normal uploaded attachments, sibling paths outside the application root, and patched builds that reject traversal or constrain deletion to the upload directory.

Report this as **comment edit metadata -> stored attachment path -> later delete cleanup escapes upload root**. Do not delete real configuration files or demonstrate site breakage in production.

### NukeViet CMS rendering context checks

1. Seed a lab with a low-privileged user, synthetic article, and synthetic comments; do not use real administrator accounts or public visitors.
2. For news body filters, use harmless DOM-only markers that exercise parser differentials such as unusual HTML5 whitespace and entity-decoding behavior. Avoid credential collection, persistent beacons, or payloads intended for real users.
3. For profile/comment templates, place a marker in display-name fields and verify how it appears after entity decoding inside the final inline JavaScript string when a lab user clicks the reply control.
4. For comment status rendering, pass an encoded harmless marker through the status flow and verify whether filtering occurs before or after decode. Record whether the anti-forgery value is reusable across sessions only as a decision table, not as a weaponized link.
5. Compare with patched NukeViet versions where output is escaped for the actual sink, decoded content is sanitized after decode, and tokens are session-bound.

Report these as **CMS user-controlled field -> context mismatch or decode-order gap -> trusted-origin browser execution**. Keep screenshots to visible canary markers and redact cookies, tokens, account emails, and browser storage.

### DIRAC RequestManager dynamic-evaluation check

1. Use a DIRAC lab with a disposable authenticated user and no production jobs, tokens, proxies, credentials, or science data.
2. Identify the RequestManager counter endpoint and send a normal request using documented grouping values to establish expected output.
3. Send an inert grouping canary that should be rejected as an unknown field; instrument the lab or logs to determine whether the server constructs a dynamic expression rather than using a strict allowlist.
4. If a positive proof is required, use only a benign expression marker in a patched/offline harness that cannot run shell commands or read files. Do not demonstrate OS command execution, token access, proxy export, or log tampering.
5. Compare with patched versions where unexpected grouping values are rejected before any dynamic evaluation call.

Report this as **authenticated reporting parameter -> missing allowlist -> Python dynamic evaluation in service context**. The strongest safe evidence is a source-to-sink trace plus patched negative control, not command output.

### DIRAC FileCatalog SQL-to-`eval()` chain

1. Use a DIRAC FileCatalog lab with disposable datasets and a non-production database containing only synthetic marker rows.
2. Trace the `checkDataset` / DatasetManager path from authenticated dataset parameters into the backend query builder, then into the value later consumed by Python `eval()`.
3. Send a harmless dataset-name canary that demonstrates whether the SQL grammar can alter only the returned marker value. Do not extract schema data, credentials, user proxies, job metadata, or science data.
4. If dynamic evaluation must be proven, run the proof in an offline harness or instrumented lab where the evaluated value can only set an inert variable or write a disposable marker under `/tmp`.
5. Include controls for a normal dataset, an escaped/quoted dataset value, a user lacking FileCatalog permissions, and a patched build that rejects or parameterizes the dataset value before evaluation.

Report this as **authenticated dataset parameter -> SQL result shaping -> Python `eval()` sink**. Keep evidence to source links, query-shape notes, inert marker values, and patched negative controls.

### DIRAC PilotManager SQL and method-authorization check

1. Stand up a DIRAC WorkloadManagement lab with fake pilots, fake sites, and no real worker nodes or grid credentials.
2. From a disposable authenticated role, call a documented PilotManager read/update method with normal parameters to establish expected access and database behavior.
3. Exercise the same method family with a grammar canary in fields such as pilot reference, status, or accounting selectors to determine whether parameters are concatenated into SQL rather than bound.
4. Record whether pilot-update permission is verified before any database write path is reached.
5. Record only status codes, role decisions, and synthetic row markers. Do not modify production pilot status, enumerate real pilots, or attempt stacked statements or destructive SQL.

Report this as **authenticated PilotManager parameter -> unescaped SQL layer and/or missing method gate -> synthetic pilot-state impact**. Separate the injection evidence from the access-control evidence.

### DIRAC pilot bootstrap transport-integrity check

1. Recreate the pilot bootstrap flow in an isolated lab runner that fetches a fake `pilot.tar` from an owned endpoint. Never intercept or alter production pilot distribution.
2. Present a test HTTPS endpoint with a deliberately untrusted certificate and a fake checksum file served over the same endpoint.
3. Observe whether the wrapper accepts the connection, fetches both the pilot archive and checksum, and reaches the execution decision for the fake archive.
4. Keep the archive inert: a marker file or log-only script is enough. Do not ship shells, credential readers, persistence, or code that contacts external infrastructure beyond the owned lab callback.
5. Compare with a patched wrapper where certificate validation is enforced and checksums are anchored to a trusted channel or signed metadata.

Report this as **pilot bootstrap URL -> TLS validation disabled -> checksum and code fetched from same untrusted channel -> execution decision**. The strongest evidence is a TLS decision table plus fake-artifact logs, not post-exploitation output.

## Reporting notes

- Lead with preconditions: NukeViet version, proxy-header trust path, update trigger reachability, comment/news/profile permissions, DIRAC authenticated role, enabled FileCatalog/PilotManager services, and pilot bootstrap source.
- Prefer decision tables: input field, storage/transformation step, sink, expected boundary, observed canary, patched control.
- Redact callback tokens, account IDs, `checkss` values, session cookies, filesystem paths tied to real deployments, and DIRAC job/user identifiers.
- Skip generic XSS/DoS phrasing. The durable lessons are forwarded-host trust, edit-to-cleanup filesystem effects, browser/server parser differentials, decode-before-sanitize order, token binding, dynamic-evaluation allowlists, SQL-result-to-code chains, service method authorization, and bootstrap transport integrity.
