# Hosted app, CDN, and serializer-boundary batch

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because it crosses three common self-hosted and SaaS trust boundaries: reverse-proxy identity headers, browser-facing proxy routes, package-CDN build sandboxes, and serializer error paths. The shared lesson is that “internal” helper features still need explicit origin, path, session, output, and resource controls.

## Advisories covered

- **SillyTavern SSO header injection** — [GHSA-gxx6-h3g6-vwjh](https://github.com/advisories/GHSA-gxx6-h3g6-vwjh), CVE-2026-44649: when header-based SSO is enabled, direct clients could inject `Remote-User` or `X-Authentik-Username` unless the app restricts trusted proxy source IPs. Fixed in `sillytavern 1.18.0`.
- **SillyTavern extension delete path traversal / base-directory deletion** — [GHSA-886q-f44j-h6wh](https://github.com/advisories/GHSA-886q-f44j-h6wh), CVE-2026-44650: sanitizing `.` to an empty filename made the delete path resolve to the whole extensions directory. Fixed in `1.18.0`.
- **SillyTavern session reuse after password change** — [GHSA-wmm3-h9qj-p5v6](https://github.com/advisories/GHSA-wmm3-h9qj-p5v6), CVE-2026-44648: stateless cookie sessions stayed valid after password reset/change. Fixed in `1.18.0`.
- **SillyTavern CORS proxy SSRF and reflected XSS** — [GHSA-ccfq-2454-f5xw](https://github.com/advisories/GHSA-ccfq-2454-f5xw), CVE-2026-44652, and [GHSA-xc4x-2452-5gc9](https://github.com/advisories/GHSA-xc4x-2452-5gc9), CVE-2026-44651: the optional CORS proxy fetched attacker-controlled URLs and reflected failed URLs into HTML error responses. Fixed in `1.18.0`; private request filtering is available but must be enabled/configured for network-hosted deployments.
- **esm.sh legacy-route arbitrary file write / potential RCE** — [GHSA-3636-h3vx-6465](https://github.com/advisories/GHSA-3636-h3vx-6465), CVE-2026-44593: encoded traversal through the legacy route could produce a filesystem storage key outside the intended cache root. Fixed in `github.com/esm-dev/esm.sh` pseudo-version `0.0.0-20260508100112-1960055e1d53` and release `v137_3`.
- **esm.sh `package.json` browser-field local file inclusion** — [GHSA-rg65-45m7-hq57](https://github.com/advisories/GHSA-rg65-45m7-hq57), CVE-2026-44594: package-controlled browser remapping occurred after the package-directory sandbox check, letting build output or source maps include readable host files. Fixed in pseudo-version `0.0.0-20250616164159-0593516c4cfa` and release `v137`.
- **UltraJSON `ujson.dump()` memory leak on failed write** — [GHSA-c38f-wx89-p2xg](https://github.com/advisories/GHSA-c38f-wx89-p2xg), CVE-2026-44660: failed file-like writes leaked the serialized payload. Fixed in `ujson 5.12.1`.
- **Flowise bcrypt password-hash exposure** — [GHSA-8f47-4rh3-x44m](https://github.com/advisories/GHSA-8f47-4rh3-x44m), CVE-2026-8026: login/API response handling could disclose password hashes in `flowise <=3.0.12`; vendor metadata did not list a patched npm version at scan time.

## Operator triage

1. Upgrade SillyTavern to `1.18.0` before exposing any instance beyond localhost. If SSO is enabled, restrict SSO-header trust to loopback or explicit reverse-proxy IPs and block direct client access to the app port.
2. Treat SillyTavern CORS proxy exposure as SSRF-relevant until private request whitelisting is enabled and verified. Test loopback, RFC1918, link-local, IPv6, DNS rebinding, redirects, and encoded host forms.
3. For shared package-CDN/build services using esm.sh, patch immediately, clear untrusted cache/storage roots, and look for traversal strings, encoded `..%2f`, `#` fragment tricks in paths, and unexpected writes outside cache directories.
4. For `ujson`, upgrade to `5.12.1` wherever `ujson.dump()` writes to sockets, streaming responses, custom file-like objects, or attacker-influenced sinks. Repeated client disconnects can become memory pressure.
5. For Flowise, upgrade as vendor fixes become available and inspect API/login responses, logs, and telemetry for bcrypt hashes; rotate affected passwords if hashes may have left the trust boundary.

## Durable controls

- Do not trust identity headers unless the request arrived from a pinned reverse proxy and all direct paths to the backend are blocked.
- Bind session validity to server-side revocation state or a per-user session epoch so password changes, recovery flows, and admin disables invalidate old cookies.
- Validate path inputs after every transformation, not only before sanitization, mapping, decoding, proxying, or joining.
- Keep build/cache storage roots on isolated filesystems with no executable paths, no shared secrets, no home directories, and tight service-account permissions.
- Make SSRF filters central and default-on for network-hosted deployments; enforce destination allowlists after DNS resolution, redirects, protocol upgrades, and IP canonicalization.
- Return proxy and fetch errors as plain text or structured JSON, never raw concatenated HTML containing attacker-controlled URLs.
- Treat serializer error paths as resource-boundary code: test disconnects, partial writes, exceptions, and retries under memory limits.
