# pygeoapi OGC subscriber SSRF and STAC path traversal (GHSA-jgvc-94c8-3chc / GHSA-f6pr-83pg-ghh6)

**Signal:** GitHub Security Advisories published **2026-04-29**. pygeoapi fixed two 0.23.x issues: unauthenticated SSRF through process subscribers and path traversal in the STAC FileSystemProvider.

## What it is
The first issue (`GHSA-jgvc-94c8-3chc` / `CVE-2026-42352`) lets OGC API Process execution requests use a `subscriber` object to make requests to internal HTTP services. The second (`GHSA-f6pr-83pg-ghh6` / `CVE-2026-42351`) uses raw string path concatenation in the STAC FileSystemProvider, exposing directories when `..` segments reach pygeoapi without proxy normalization.

Affected package: pip `pygeoapi` `>= 0.23.0, < 0.23.3`. Fixed version: `0.23.3`.

References: <https://github.com/advisories/GHSA-jgvc-94c8-3chc>, <https://github.com/advisories/GHSA-f6pr-83pg-ghh6>

## Triage
1. Inventory public pygeoapi 0.23.x deployments.
2. Check whether OGC API Processes are enabled and whether process execution is reachable without strong authentication.
3. Identify `stac-collection` resources using the FileSystemProvider, especially deployments without a front proxy that normalizes or rejects dot segments.

## Mitigation
- Upgrade to pygeoapi `0.23.3` or later.
- Disable process resources if unused.
- Keep internal-request blocking off by default unless a tightly scoped allowlist is configured.
- Reject dot segments and canonicalize STAC filesystem paths before serving collection content.

## Detection ideas
- Search access logs for process execution payloads containing `subscriber` URLs to localhost, RFC1918, link-local, or metadata addresses.
- Search STAC routes for `..`, encoded dot segments, repeated slashes, and unusual directory listings or file reads.

## Durable lesson
Geospatial APIs frequently bridge public request data to internal services and file-backed collections. Subscriber callbacks and dataset paths need the same SSRF and traversal controls as generic webhooks and download endpoints.
