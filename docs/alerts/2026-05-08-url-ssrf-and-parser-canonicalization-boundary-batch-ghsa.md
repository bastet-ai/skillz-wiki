# URL, SSRF, and parser canonicalization boundary batch

**Signal:** The **2026-05-08 19:15 UTC** advisory scan surfaced URL parser and webhook SSRF bypasses where policy checked a string form that was not the authority the network stack ultimately used.

## Advisory cluster

- **fast-uri host confusion via percent-encoded authority delimiters** — [GHSA-v39h-62p7-jpjc](https://github.com/advisories/GHSA-v39h-62p7-jpjc): `fast-uri <= 3.1.1` could confuse host parsing around percent-encoded authority delimiters. Patch to `3.1.2+`.
- **Bugsink webhook URL validation SSRF bypass** — [GHSA-fp53-qcf8-2xx2](https://github.com/advisories/GHSA-fp53-qcf8-2xx2): `bugsink <= 2.1.2` `validate_webhook_url` could be bypassed. Patch to `2.1.3+`.
- **Apache Polaris improper input validation** — [GHSA-w76p-3cgp-qfcm](https://github.com/advisories/GHSA-w76p-3cgp-qfcm): `org.apache.polaris:polaris-runtime-service < 1.4.1` adds another Polaris validation boundary to the May 8 batch. Patch to `1.4.1+`.

## Why this matters

SSRF controls fail when the allowlist, logger, proxy, and client disagree about the canonical URL. Percent-encoded delimiters, userinfo, backslashes, IPv6 forms, redirects, and framework parser differences must be normalized once and passed as structured components, not repeatedly re-parsed from strings.

## Triage

1. Search SBOMs for `fast-uri <= 3.1.1`, `bugsink <= 2.1.2`, and Polaris runtime services `< 1.4.1`.
2. Inventory webhook, callback, import, preview, and integration endpoints that accept user-controlled URLs.
3. Review egress logs for webhook requests to loopback, link-local, RFC1918, metadata, cluster service, or unexpected internal DNS names.
4. Test URL policy with percent-encoded `@`, `/`, `\\`, `#`, `?`, IPv6 literals, mixed-case schemes, userinfo, redirects, and DNS rebinding.

## Durable controls

- Parse with the same library used by the outbound client, then enforce policy on structured scheme/host/port/path fields.
- Resolve DNS and IP allow/deny rules at connect time, including every redirect hop.
- Block loopback, link-local, private, multicast, and cloud metadata ranges by default for user-supplied destinations.
- Record both the original URL and canonical connect tuple in audit logs.
- Keep URL parser regression tests for every bypass class that has affected your stack.
