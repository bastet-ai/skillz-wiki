# URL allowlists: canonicalize, parse, and ban userinfo

**Problem:** URL allowlists are frequently implemented with **string checks** (e.g., `url.startsWith("https://good.example/")`). Attackers can exploit differences between **raw string representation** and the **actual network destination** after URL parsing.

This shows up in SSRF defenses, “trusted domain” checks, webhook allowlists, build-time fetchers, and agent tooling.

## Durable guidance

### 1) Never enforce allowlists on raw strings
- Don’t use `startsWith`, `includes`, regexes, or naive splitting.
- Use a URL parser and enforce policy on **structured fields**:
  - scheme/protocol
  - hostname (after normalization)
  - port (explicit and implicit)
  - path (if relevant)

### 2) Reject URL **userinfo** outright
- The `username:password@host` form is rarely needed.
- It is a common source of **allowlist bypasses** because the `@` changes what the parser treats as the real host.

### 3) Normalize before compare
- Normalize punycode/IDNA, lowercase hostnames, and apply consistent port rules.
- Avoid comparing raw input to stored allowlist strings.

### 4) Defend in depth with egress controls
- For high-risk contexts (CI/build hosts, automation/agents): prefer **network egress allowlisting** at the firewall/proxy layer.
- If SSRF would be catastrophic, block access to:
  - cloud metadata IPs/hostnames
  - RFC1918 ranges (as appropriate)
  - link-local ranges

## Related examples
- webpack build-time fetch allowlist bypass via userinfo: https://github.com/advisories/GHSA-8fgc-7cc6-rx7x
