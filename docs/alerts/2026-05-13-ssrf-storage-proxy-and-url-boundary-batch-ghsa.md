# SSRF, storage, proxy, and URL-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because URL parsing, object storage paths, preview fetchers, game/profile media, SAML metadata sync, and incident bots all crossed from “user-provided location” into trusted network or filesystem authority.

## Advisories covered

- **link-preview-js internal-target bypass** — [GHSA-4gp8-rjrq-ch6q](https://github.com/advisories/GHSA-4gp8-rjrq-ch6q): IPv6 and internal-loopback forms bypassed preview restrictions. Fixed in `4.0.1`.
- **FireFighter unauthenticated Jira bot SSRF** — [GHSA-fqvv-jvhr-g5jc](https://github.com/advisories/GHSA-fqvv-jvhr-g5jc): unauthenticated SSRF could reach IAM metadata. Fixed in `firefighter-incident 0.0.54`.
- **edx-enterprise SAML metadata SSRF** — [GHSA-64cv-vxpr-j6vc](https://github.com/advisories/GHSA-64cv-vxpr-j6vc): `sync_provider_data` accepted attacker-controlled SAML metadata URLs. Fixed in `7.0.5`.
- **Geyser player-head texture SSRF** — [GHSA-xcfg-fcr5-gw9r](https://github.com/advisories/GHSA-xcfg-fcr5-gw9r): media URL fetching crossed into server-side network authority. Fixed in `2.9.3`.
- **MinIO Storage REST path traversal** — [GHSA-xh8f-g2qw-gcm7](https://github.com/advisories/GHSA-xh8f-g2qw-gcm7): msgpack bodies in `ReadMultiple` could traverse object paths. Fixed in `RELEASE.2026-04-14T21-32-45Z` lineage.
- **S3-Proxy path matching flaws** — [GHSA-rfgq-wgg8-662p](https://github.com/advisories/GHSA-rfgq-wgg8-662p): resource path matching allowed authorization confusion. Fixed in `1320e4abd46a` and later.
- **@workos/authkit-session open redirect** — [GHSA-vvvv-983w-r7pv](https://github.com/advisories/GHSA-vvvv-983w-r7pv): redirect targets derived from `state` were not constrained. Fixed in `0.5.1`.

## Operator triage

1. Patch externally reachable previewers, SAML sync endpoints, incident bots, game/proxy media fetchers, and object-storage gateways first.
2. Review access logs for URL payloads containing IPv6 literals, decimal/octal IP forms, DNS-rebinding hostnames, `localhost`, cloud metadata paths, and excessive redirect chains.
3. Inspect object-storage audit logs for suspicious `../`, encoded slash, dot-segment, or bucket/key confusion around gateway and REST APIs.
4. For open redirect issues, search auth logs for unexpected post-login destinations and rotate tokens exposed to untrusted redirect origins.

## Durable controls

- URL allowlists must canonicalize scheme, host, port, and resolved addresses at request time and after every redirect.
- Fetchers should run through egress-controlled workers with deny-by-default access to metadata, cluster, loopback, private, and admin networks.
- Storage proxies must authorize the canonical bucket/key tuple after normalization, not the raw path string before rewriting.
- OAuth/session `state` can bind CSRF and nonce data, but redirect destinations need a separate signed allowlisted return URL.
