# i18next localization path, URL, and prototype-pollution batch (GHSA-5fgg-jcpf-8jjw / GHSA-8847-338w-5hcj / GHSA-q89c-q3h5-w34g / GHSA-mgcp-mfp8-3q45 / GHSA-6457-mxpq-4fqq)

**Signal:** GitHub Security Advisories updated **2026-04-30**. Multiple i18next ecosystem packages fixed unsafe interpolation of language, namespace, project, and translation values into filesystem paths, backend URLs, object paths, and DOM attributes.

## What it is
The common failure pattern is treating localization inputs as harmless strings. In these advisories, attacker-controlled `lng`, `ns`, project/version values, or translation strings could cross trust boundaries:

- `i18next-http-middleware` `< 3.9.3` (GHSA-5fgg-jcpf-8jjw / CVE-2026-41690): public resource handlers accepted `lng`/`ns` values that could trigger prototype pollution via `__proto__`, `constructor`, or `prototype`, and could feed backend traversal or SSRF paths.
- `i18next-fs-backend` `< 2.6.4` (GHSA-8847-338w-5hcj / CVE-2026-41693): raw `lng`/`ns` interpolation into `loadPath` and `addPath` allowed locale-root escape and arbitrary file reads or missing-key writes.
- `i18next-http-backend` `< 3.0.5` (GHSA-q89c-q3h5-w34g / CVE-2026-41691): raw `lng`/`ns` interpolation into `loadPath` and `addPath` enabled path traversal and URL-structure injection in outbound translation fetches.
- `i18next-locize-backend` `< 9.0.2` (GHSA-mgcp-mfp8-3q45 / CVE-2026-41885): unsanitized `lng`, `ns`, `projectId`, and `version` values could alter Locize backend request paths.
- `i18nextify` `< 4.0.8` (GHSA-6457-mxpq-4fqq / CVE-2026-41692): translated values substituted into `href` and `src` attributes could preserve `javascript:` or `data:` schemes and become DOM XSS when translation content is attacker-influenced.

References: <https://github.com/advisories/GHSA-5fgg-jcpf-8jjw>, <https://github.com/advisories/GHSA-8847-338w-5hcj>, <https://github.com/advisories/GHSA-q89c-q3h5-w34g>, <https://github.com/advisories/GHSA-mgcp-mfp8-3q45>, <https://github.com/advisories/GHSA-6457-mxpq-4fqq>

## Triage
1. Inventory Node services using i18next resource endpoints, server-side locale loading, Locize-backed translation sync, or `i18nextify` DOM localization.
2. Check whether language and namespace selection can be controlled through query parameters, path params, cookies, headers, localStorage, or user-contributed locale files.
3. For filesystem backends, review configured `loadPath` / `addPath` templates and inspect logs for dot segments, absolute paths, URL-encoded separators, or suspicious namespace values.
4. For HTTP/Locize backends, review outbound fetch logs for unexpected hosts, schemes, path prefixes, metadata IPs, localhost, or tenant/project swaps.
5. For browser localization, treat writable translation stores/CDNs as script-capable until URL schemes in translated attributes are constrained.

## Mitigation
- Upgrade affected packages: `i18next-http-middleware` `3.9.3+`, `i18next-fs-backend` `2.6.4+`, `i18next-http-backend` `3.0.5+`, `i18next-locize-backend` `9.0.2+`, and `i18nextify` `4.0.8+`.
- Allowlist language codes, namespaces, project IDs, and version strings before they reach path or URL templates.
- Resolve filesystem paths and enforce they remain under the locale root before reads or writes.
- Pin translation HTTP backends to approved hosts and block private, loopback, link-local, and metadata address ranges.
- Sanitize translated `href`/`src` values to approved schemes; never treat translation files as trusted code.

## Detection ideas
- Alert on `lng` or `ns` values containing `..`, `%2e`, `%2f`, backslashes, `://`, `@`, IPv4/IPv6 literals, `localhost`, `169.254.169.254`, `__proto__`, `constructor`, or `prototype`.
- Watch for locale-load errors that mention paths outside the expected translation tree or outbound translation fetches to non-approved domains.
- Review translation changes for URL-scheme shifts, especially `javascript:`, `data:`, and protocol-relative URLs in attributes.

## Durable lesson
Localization is a supply-chain and routing surface. Language, namespace, and translation values must be validated as path components, URL components, object keys, and DOM sinks before they touch filesystems, networks, prototypes, or live attributes.
