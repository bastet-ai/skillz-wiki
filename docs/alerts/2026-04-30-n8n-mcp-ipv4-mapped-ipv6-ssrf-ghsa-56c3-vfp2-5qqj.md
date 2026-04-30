# n8n-mcp IPv4-mapped IPv6 SSRF in SDK URL validation (GHSA-56c3-vfp2-5qqj / CVE-2026-42449)

**Signal:** GitHub Security Advisories published **2026-04-30**. `n8n-mcp` fixed a non-blind SSRF in SDK embedder paths where IPv4-mapped IPv6 literals bypassed synchronous URL validation.

## What it is
`SSRFProtection.validateUrlSync()` did not apply IPv6 range checks. SDK embedders that accepted user-controlled `n8nApiUrl` values could be made to request hosts such as `http://[::ffff:169.254.169.254]`, bypassing checks for localhost, RFC1918 networks, and cloud metadata endpoints. Response bodies are returned to the caller, and the `x-n8n-api-key` header can be forwarded to the attacker-selected endpoint.

Affected package: npm `n8n-mcp` versions `2.47.4` through `2.47.13` when using `N8NDocumentationMCPServer` / `N8NMCPEngine` with user-supplied instance context. Fixed version: `2.47.14`.

Reference: <https://github.com/advisories/GHSA-56c3-vfp2-5qqj>

## Triage
1. Find services embedding `n8n-mcp` as an SDK rather than only running the first-party HTTP server.
2. Check whether `n8nApiUrl` or instance context can come from tenants, users, uploaded configs, or untrusted automation.
3. Review egress logs for bracketed IPv6 literals, IPv4-mapped IPv6, metadata IPs, localhost, and private-network destinations from the n8n-mcp process.

## Mitigation
- Upgrade to `n8n-mcp >= 2.47.14`.
- Reject IP literals, bracketed IPv6, and private/link-local/metadata ranges before passing URLs into the SDK.
- Enforce process/network egress deny rules for metadata, localhost, RFC1918, and internal control-plane ranges.
- Do not forward privileged API keys to user-selected base URLs.

## Detection ideas
- Search logs and traces for `::ffff:`, bracketed IPv6 hosts, `169.254.169.254`, `localhost`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` as `n8nApiUrl` targets.
- Hunt for unexpected `x-n8n-api-key` traffic to non-n8n hosts.

## Durable lesson
URL validation is not complete until all equivalent address forms collapse to the same policy decision. IPv4-mapped IPv6, DNS rebinding, redirects, and normalized hostnames need the same egress policy as plain IPv4 literals.
