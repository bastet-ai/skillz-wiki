# i18next-http-middleware language and namespace traversal / SSRF (GHSA-jfgf-83c5-2c4m / CVE-2026-42353)

**Signal:** GitHub Security Advisories published **2026-04-29**. `i18next-http-middleware` fixed unsanitized `lng` and `ns` handling in resource loading.

## What it is
`getResourcesHandler` passed user-controlled language (`lng`) and namespace (`ns`) values into backend loading without sanitization. Depending on the configured backend, this becomes filesystem path traversal with `i18next-fs-backend` or SSRF with `i18next-http-backend`.

Affected package: npm `i18next-http-middleware` `< 3.9.3`. Fixed version: `3.9.3`.

Reference: <https://github.com/advisories/GHSA-jfgf-83c5-2c4m>

## Triage
1. Find Express/Node services exposing i18next resource endpoints.
2. Identify backend type and interpolation patterns for `lng` and `ns`.
3. Check whether translation endpoints are public or reachable before authentication.

## Mitigation
- Upgrade to `i18next-http-middleware` `3.9.3` or later.
- Allowlist supported languages and namespaces before resource loading.
- For filesystem backends, resolve and enforce that resource paths stay under the locale root.
- For HTTP backends, block private IP ranges, metadata services, and unapproved hosts.

## Detection ideas
- Search logs for `../`, encoded dot segments, absolute URLs, IP literals, localhost, cloud metadata hostnames, or unexpected namespaces in translation requests.
- Monitor backend fetch logs for translation loads to non-locale directories or unapproved hosts.

## Durable lesson
Localization parameters often reach filesystem and network backends. Treat language and namespace as untrusted path/URL components, not harmless display preferences.
