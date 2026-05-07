# SSRF, policy-reference, and URL boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where URL ingestion and policy-reference helpers fetched attacker-influenced locations without enough destination validation.

## Advisories covered

- **docling-graph URLInputHandler SSRF** — [GHSA-fqph-j6v6-jvgx](https://github.com/advisories/GHSA-fqph-j6v6-jvgx): document ingestion accepted remote URLs without blocking internal IP ranges and metadata services.
- **Apache Neethi remote policy reference SSRF** — [GHSA-287c-fxr7-3w6c](https://github.com/advisories/GHSA-287c-fxr7-3w6c): manually fetched policy references could retrieve arbitrary URIs through the PolicyReference API.

## Why this is durable

"Fetch this URL for me" helpers are often treated as parsing or convenience features, but they are network clients running from a trusted server position. The durable control is not a one-off denylist; it is a reusable egress policy around every URL-to-fetch boundary.

## Immediate triage

1. Patch affected docling-graph and Apache Neethi consumers where present.
2. Inventory document-ingestion, policy-reference, schema-import, OpenAPI-import, webhook-test, and preview endpoints that fetch user-supplied URLs.
3. Block link-local, loopback, RFC1918, RFC4193, metadata-service, and cluster-service destinations after DNS resolution and after redirects.
4. Hunt proxy, resolver, and application logs for fetches to `169.254.169.254`, localhost aliases, internal service names, and unexpected private ranges.

## Durable controls

- Canonicalize hostnames, resolve DNS, and enforce destination policy on the final socket address, not just on the original string.
- Re-check policy after each redirect and cap redirect depth, response size, content type, and total fetch time.
- Route untrusted fetchers through a constrained egress proxy with explicit allowlists and no cloud metadata reachability.
- Treat policy/schema/document imports as untrusted network activity; separate them from privileged control-plane credentials.
