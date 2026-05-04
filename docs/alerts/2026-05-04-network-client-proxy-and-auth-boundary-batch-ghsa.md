# Network client, proxy, and auth-boundary batch (GHSA)

**Signal:** GitHub Security Advisories surfaced a **2026-05-04** batch where network clients and edge/auth middleware allowed lower-trust users or malformed protocol state to redirect traffic, strip TLS, inject commands, bypass policy, or weaken sessions.

## Advisories in this batch

- **pyload-ng proxy/TLS control by non-admin SETTINGS users** — `pyload-ng <= 0.5.0b3.dev99` let non-admin SETTINGS users redirect outbound traffic through attacker-controlled proxies and disable TLS peer verification. Fixed in 0.5.0b3.dev100. References: <https://github.com/advisories/GHSA-pg67-9wjv-mr85>, <https://github.com/advisories/GHSA-ccxc-x975-4hh9>, CVE-2026-42313, CVE-2026-42312.
- **net-imap command injection and STARTTLS/resource failures** — `net-imap` fixed raw-argument command injection, Symbol-input command injection, SCRAM high-iteration DoS, quadratic response-literal parsing, and STARTTLS stripping via invalid response timing across 0.6.4 / 0.5.14 / 0.4.24 / 0.3.10. References: <https://github.com/advisories/GHSA-hm49-wcqc-g2xg>, <https://github.com/advisories/GHSA-75xq-5h9v-w6px>, <https://github.com/advisories/GHSA-87pf-fpwv-p7m7>, <https://github.com/advisories/GHSA-q2mw-fvj9-vvcw>, <https://github.com/advisories/GHSA-vcgp-9326-pqcp>.
- **Heimdall policy bypasses** — `github.com/dadrus/heimdall < 0.17.14` had path normalization mismatch, case-sensitive host matching, and URL-encoded slash case handling that could produce inconsistent authorization decisions. References: <https://github.com/advisories/GHSA-3q34-rx83-r6mq>, <https://github.com/advisories/GHSA-72h4-mxfc-jx37>, <https://github.com/advisories/GHSA-43jv-5j4x-qv67>.
- **Saltcorn open redirect** — `@saltcorn/server` fixed backslash bypasses in login redirect validation in 1.4.6 / 1.5.6 / 1.6.0-beta.5. Reference: <https://github.com/advisories/GHSA-f3g8-9xv5-77gv>, CVE-2026-42259.
- **Budibase session cookie exposure** — `@budibase/backend-core < 3.35.10` set auth session cookies with `httpOnly:false`, turning any XSS into likely account takeover. Reference: <https://github.com/advisories/GHSA-4f9j-vr4p-642r>, CVE-2026-42239.
- **AzuraCast account/control-plane issues** — `azuracast/azuracast <= 0.23.5` had untrusted `X-Forwarded-Host` password-reset poisoning, missing permission checks on media download, and missing internal-connection enforcement on the Liquidsoap API. Fixed in 0.23.6. References: <https://github.com/advisories/GHSA-gv7r-3mr9-h5x8>, <https://github.com/advisories/GHSA-qff7-q5fm-8p76>, <https://github.com/advisories/GHSA-4fm3-ggg2-c6qx>.

## Why this is durable

Outbound proxy settings, TLS state, STARTTLS timing, host/path normalization, forwarded headers, and cookie flags are all security boundaries. If they are user-tunable or inconsistently parsed, authentication and authorization become advisory instead of enforceable.

## Immediate triage

1. Patch the named packages and services; prioritize internet-facing downloaders, IMAP clients, auth gateways, and admin panels.
2. Freeze pyload proxy/TLS settings to admin-only configuration and audit recent changes.
3. Regenerate Heimdall route-policy tests with mixed case hosts, encoded slashes, double slashes, dot segments, and reverse-proxy normalized paths.
4. For Budibase and AzuraCast, assume XSS or host-header poisoning could have yielded account takeover; rotate sessions and check password-reset events.

## Hunt ideas

- Look for `X-Forwarded-Host` values that do not match canonical application hosts.
- Search downloader logs for proxy endpoints, disabled TLS verification, or failed certificate validation immediately before successful downloads.
- Add IMAP fixtures for invalid STARTTLS response timing, large SCRAM iteration counts, and literal-size stress cases.
- Diff gateway decisions between raw URL, proxy-normalized URL, and application-normalized URL.

## Durable controls

- Make proxy, TLS-verification, and outbound-network controls privileged settings with change logs.
- Canonicalize host, path, percent-encoding, and slash semantics once, then authorize on that exact representation.
- Treat forwarded headers as trusted only from explicitly trusted proxies and only after canonical host allowlisting.
- Set auth cookies `HttpOnly`, `Secure`, and `SameSite` by default; do not let app-level convenience override session safety.

## Operator lesson

Most auth bypasses are parser disagreements wearing a login form. Test every gateway with the bytes the proxy receives, the path the app sees, and the policy key the authorizer uses.
