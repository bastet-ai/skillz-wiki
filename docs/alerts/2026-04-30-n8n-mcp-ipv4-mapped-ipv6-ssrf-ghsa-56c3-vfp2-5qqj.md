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

## October 9 follow-up: Pydantic AI metadata-blocklist bypass via IPv6 zone identifiers — `%25`-encoded scope IDs survive into the connect target (CVE-2026-107289 / GHSA-vmxc-h2x2-jmf3)

Third-generation fix-drift on this exact invariant. Pydantic AI's cloud-metadata blocklist (itself already two generations of fixes deep: CVE-2026-25580 → CVE-2026-46678 → CVE-2026-48782) is bypassed by appending an **IPv6 zone identifier to a metadata address**: `fd00:ec2::254%251` (AWS IPv6 metadata endpoint with `%251` = URL-encoded zone `%1`). The **validator parses the zone and treats the string as a different/unmatchable host, while the host stack ignores the zone on a non-link-local destination and delivers to the metadata endpoint anyway** — exposing cloud IAM short-term credentials through `FileUrl(force_download='allow-local')` / `web_fetch_tool(allow_local_urls=True)`.

Operator battery additions for every URL-allowlist/metadata-blocklist engagement (add to the canonicalization sweep this page already prescribes):

- **Zone-identifier shapes on every blocklisted IPv6 literal:** `fe80::1%251`, `%25eth0`, `%25lo`, double-encoded `%25251` — validators that call `netip.ParseAddr`-family parsers often reject or normalize-away the zone while the socket layer silently drops it and connects.
- **The general rule stays the same and now has a fourth proof point:** *any token the parser understands but the connect path discards creates a validator-vs-destination split.* Zone IDs are the newest member of the family next to IPv4-mapped IPv6, leading-zero octets, and DNS rebinding. Grep for URL/network validators that call a parse-and-stringify routine (`Addr.String()`-style) — the stringify is where the discarded token disappears from the *comparison* but not the *connection*.
- **Fix-generation counting is recon:** three prior CVEs on the same guard means the guard is a denylist over address spellings, not a resolve-then-connect design — expect more spellings (this is now confirmed a fourth time) and test new spellings against it first.

## October 10 follow-up: Kortix Suna connector URLs — private-IP guard bypassed with 6to4/Teredo spellings that embed the private IPv4 destination (CVE-2026-108115 / [GHSA-f37m-qrrx-ww7w](https://github.com/advisories/GHSA-f37m-qrrx-ww7w), low as scored, fixed 0.13.52)

Fourth-something spelling on this page's invariant, now on the AI-agent-platform side: Kortix Suna project holders with `project.connector.write` set connector `base_url` / OpenAPI / Postman / MCP URLs to **IPv6 6to4 (`2002:`) or Teredo addresses embedding a private IPv4 destination** — the `isPrivateIp` guard checks the IPv6 literal's own prefix (global 6to4/Teredo space, not RFC1918), passes it, and the dual-stack/NAT64 stack routes the embedded IPv4 to internal services and cloud metadata, with responses readable through the connector. Same family as the May 29 Gotenberg deny-list leg (6to4/NAT64/`fec0::/10` spellings) and the Oct 9 Pydantic AI zone-ID leg on this page.

Operator additions: (1) the **connector-config angle** — on AI/automation platforms, every stored outbound-fetch config (connectors, webhooks, MCP servers, OpenAPI imports, Postman collections) is a URL validator you must sweep, and these often ship a *different, weaker* guard than the platform's main fetch path; test the battery against each config field separately. (2) The spellings to append to this page's canonicalization battery: `2002:7f00:1::`-style 6to4 (embed `127.0.0.1` as hex groups), `2001:db8::`-wrapped Teredo with XOR-obfuscated client/server IPv4, `64:ff9b::<ipv4>` and `64:ff9b:1::<ipv4>` NAT64 — and check whether the guard's IP class check runs on the literal string, the parsed `IPv6Address`, or the post-resolution route; only the last is correct. (3) CVSS 5.3/low hides that cloud-metadata reach + response read from a mid-privilege role is a standard lateral step; report on reachability and response-read proof, not on the vendor's score.
