# SSRF address canonicalization boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced two durable SSRF-filter bypasses updated on **2026-05-06**: `dssrf` IPv6 category bypasses and QuantumNous/new-api `0.0.0.0` SSRF.

## Advisories covered

- **dssrf IPv6 category bypasses** — [GHSA-8p33-q827-ghj5](https://github.com/advisories/GHSA-8p33-q827-ghj5): npm `dssrf < 1.3.0` allowed IPv6 loopback, ULA, link-local, IPv4-mapped IPv6, NAT64, deprecated site-local, documentation, and IPv4-compatible forms despite documentation claiming IPv6 was disabled.
- **QuantumNous/new-api `0.0.0.0` SSRF filter bypass** — [GHSA-v5c3-6wvc-pc2q](https://github.com/advisories/GHSA-v5c3-6wvc-pc2q): Go `github.com/QuantumNous/new-api <= 0.11.9-alpha.1` did not classify `0.0.0.0/8`; authenticated API-token users could send multimodal fetch URLs that resolve to localhost. No patched version was listed when checked.

## Why this is durable

Both issues are the same defensive failure: a URL filter treated a small set of textual host forms as the security boundary. Attackers used equivalent address families and special-use ranges that route to loopback, metadata, link-local, or internal services after parsing and connection setup.

## Immediate triage

1. Upgrade `dssrf` to `1.3.0+`; for new-api, track upstream patch status and restrict remote fetch features until a fixed build is available.
2. Inventory services that fetch user-supplied images, files, webhooks, model inputs, or remote documents, especially agent/LLM and multimodal endpoints.
3. Test filters against IPv6 loopback (`[::1]`), ULA (`[fc00::1]`), link-local (`[fe80::1]`), IPv4-mapped metadata (`[::ffff:169.254.169.254]`), NAT64 forms, `0.0.0.0`, redirects, and DNS rebinding.
4. Review egress logs for bracketed IPv6 hosts, `::ffff:`, `64:ff9b::`, `0.0.0.0`, localhost, metadata IPs, and internal address ranges.

## Durable controls

- Canonicalize hostnames through the same parser and resolver path used by the outbound client, then classify the final IP for every redirect and DNS response.
- Use positive egress allowlists for fetch features; deny metadata, loopback, link-local, multicast, documentation, CGNAT, ULA, RFC1918, IPv4-mapped IPv6, NAT64, and unspecified ranges by default.
- Keep SSRF policy outside application helper libraries when possible: enforce network namespaces, proxy allowlists, firewall rules, and metadata-service blocks.
- Treat model/file/image URL fetchers as credential-adjacent. Do not let privileged API keys, cloud IAM, or internal service credentials live in the fetch process.
