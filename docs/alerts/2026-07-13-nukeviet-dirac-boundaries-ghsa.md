# NukeViet forwarded-host CMS and DIRAC eval-boundary checks

Source: hourly offensive-security scan, 2026-07-13 GitHub advisory wave. Primary entries: [GHSA-4chg-4752-w88r](https://github.com/advisories/GHSA-4chg-4752-w88r) / CVE-2026-55372, [GHSA-c9xg-64p9-f2jj](https://github.com/advisories/GHSA-c9xg-64p9-f2jj) / CVE-2026-54065, [GHSA-465g-4q99-5x86](https://github.com/advisories/GHSA-465g-4q99-5x86) / CVE-2026-54064, [GHSA-w2w5-w2pw-r929](https://github.com/advisories/GHSA-w2w5-w2pw-r929) / CVE-2026-49259, [GHSA-mxpf-qgg6-v3ff](https://github.com/advisories/GHSA-mxpf-qgg6-v3ff) / CVE-2026-48118, and [GHSA-9jpv-c7p4-997x](https://github.com/advisories/GHSA-9jpv-c7p4-997x) / CVE-2026-45579.

This batch is durable because each item maps to a reusable operator boundary: forwarded proxy headers becoming a pre-auth outbound fetch target, CMS upload/comment metadata escaping its intended storage root during later cleanup, encoded or context-mismatched CMS content reaching trusted browser execution, and an authenticated grid/computing service parameter crossing into Python `eval()`.

!!! warning "Authorized validation only"
    Keep proofs to disposable NukeViet and DIRAC labs. Use owned callback endpoints, synthetic comments/articles/users, harmless browser markers, inert RequestManager canaries, and temp files created only for the test. Do not probe internal networks, delete production files, steal sessions, collect credentials, execute shell payloads, read `dirac.cfg`, dump tokens/proxies, or target real visitors.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-4chg-4752-w88r](https://github.com/advisories/GHSA-4chg-4752-w88r) | NukeViet `server_info_update()` | Pre-auth `__serverInfoUpdate` request trusts `X-Forwarded-Host` / `X-Forwarded-Proto` when building a cURL URL | Add forwarded-host SSRF checks to CMS install/base-URL helper paths, especially when proxy headers are consumed before authentication. |
| [GHSA-c9xg-64p9-f2jj](https://github.com/advisories/GHSA-c9xg-64p9-f2jj) | NukeViet comment attachment edit/delete | Admin-editable `attach` value is prefix-stripped, stored, then later joined under uploads while deletion only checks the broader app root | Test two-phase file operations where metadata is stored during edit but the filesystem effect occurs during cleanup/delete. |
| [GHSA-465g-4q99-5x86](https://github.com/advisories/GHSA-465g-4q99-5x86) | NukeViet news body filter | HTML5 whitespace/entity decoding differs from server-side anti-XSS filtering | Add browser-parser differential fixtures for CMS rich-text/news fields instead of trusting regex-only filters. |
| [GHSA-w2w5-w2pw-r929](https://github.com/advisories/GHSA-w2w5-w2pw-r929) | NukeViet comment reply template | Profile display-name data is HTML-entity encoded but inserted into an inline JavaScript string | Test every profile/comment variable in its final output context: HTML text, attribute, URL, and JavaScript string are different sinks. |
| [GHSA-mxpf-qgg6-v3ff](https://github.com/advisories/GHSA-mxpf-qgg6-v3ff) | NukeViet comment status loader | Base64-like status parameter is filtered before decode and paired with a site-wide reusable `checkss` token | Check encoded-message flows where validation happens before decoding and anti-forgery tokens are not bound to user/session state. |
| [GHSA-9jpv-c7p4-997x](https://github.com/advisories/GHSA-9jpv-c7p4-997x) | DIRAC RequestManager counters | Authenticated `groupingAttribute` reaches RequestDB dynamic evaluation when it misses an expected allowlist | Add API-parameter-to-dynamic-evaluation checks to scientific/grid/control-plane services that expose reporting or counter endpoints. |

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

## Reporting notes

- Lead with preconditions: NukeViet version, proxy-header trust path, update trigger reachability, comment/news/profile permissions, and DIRAC authenticated role.
- Prefer decision tables: input field, storage/transformation step, sink, expected boundary, observed canary, patched control.
- Redact callback tokens, account IDs, `checkss` values, session cookies, filesystem paths tied to real deployments, and DIRAC job/user identifiers.
- Skip generic XSS/DoS phrasing. The durable lessons are forwarded-host trust, edit-to-cleanup filesystem effects, browser/server parser differentials, decode-before-sanitize order, token binding, and dynamic-evaluation allowlists.
