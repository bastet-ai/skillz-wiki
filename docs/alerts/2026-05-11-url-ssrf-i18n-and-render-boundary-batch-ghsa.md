# URL, SSRF, i18n, and render-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because it shows URL canonicalization and secondary fetch/render paths failing after the initial application validation: redirects, IPv4-mapped IPv6, translated attributes, and language/namespace template variables must be normalized before trust decisions.

## Advisories covered

- **Gotenberg Chromium URL-to-PDF SSRF and redirect deny-list bypass** — [GHSA-chwh-f6gm-r836 / CVE-2026-42595](https://github.com/advisories/GHSA-chwh-f6gm-r836): `github.com/gotenberg/gotenberg/v8 <8.32.0`, fixed `8.32.0`, exposes SSRF through `/forms/chromium/convert/url` and redirect bypasses that also affect URL-fetching flows.
- **n8n-mcp IPv4-mapped IPv6 SSRF bypass** — [GHSA-56c3-vfp2-5qqj / CVE-2026-42449](https://github.com/advisories/GHSA-56c3-vfp2-5qqj): `n8n-mcp >=2.47.4,<2.47.14`, fixed `2.47.14`, lets SDK embedders bypass localhost/private/cloud-metadata checks with URLs like `http://[::ffff:169.254.169.254]`.
- **i18nextify DOM XSS through translated URL attributes** — [GHSA-6457-mxpq-4fqq / CVE-2026-41692](https://github.com/advisories/GHSA-6457-mxpq-4fqq): `i18nextify <4.0.8`, fixed `4.0.8`, writes translated `javascript:` or `data:` values into live `href` / `src` attributes.
- **i18next-http-backend path traversal and URL injection** — [GHSA-q89c-q3h5-w34g / CVE-2026-41691](https://github.com/advisories/GHSA-q89c-q3h5-w34g): `i18next-http-backend <3.0.5`, fixed `3.0.5`, interpolates `lng` and `ns` into `loadPath` / `addPath` without validation.
- **Grafana Explore Traces XSS** — [GHSA-cqp7-wf4c-3xgc / CVE-2025-41117](https://github.com/advisories/GHSA-cqp7-wf4c-3xgc): `github.com/grafana/grafana >=12.2.0,<12.2.5` and `>=12.3.0,<12.3.3`, fixed `12.2.5` / `12.3.3`, renders stack traces from affected Jaeger HTTP API data as raw HTML.

## Operator triage

1. Prioritize services that fetch user-supplied URLs or render attacker-controlled pages/PDFs inside infrastructure with metadata, loopback, admin panels, or service mesh access.
2. Test SSRF defenses with redirects, DNS rebinding where relevant, IPv6 literals, IPv4-mapped IPv6, mixed-encoding hostnames, scheme changes, and private-network canonical forms.
3. Review localization pipelines: language and namespace values should be enumerated or encoded, and translation content must not be trusted to supply executable URL schemes.
4. For Grafana, identify Jaeger HTTP data sources and trace fields influenced by tenants or untrusted workloads; assume stored trace content can attack analysts' browsers until patched.
5. Put URL-to-PDF/render workers in egress-restricted sandboxes that cannot reach metadata endpoints, internal admin services, or developer laptops.

## Durable controls

- Validate the final fetch target after every redirect and after DNS/IP canonicalization; blocking only the first submitted URL is not enough.
- Treat IPv6, IPv4-mapped IPv6, octal/decimal IPv4, userinfo, redirects, and default ports as first-class SSRF bypass inputs in tests.
- Localization variables should be identifiers, not path/URL fragments; translate text, not trust boundaries.
- Rendered observability data needs the same HTML escaping as app data because logs, traces, and stack frames are often attacker-controlled.
- URL allowlists should bind scheme, host, port, path semantics, and resolved IP class at use time, not only at parse time.
