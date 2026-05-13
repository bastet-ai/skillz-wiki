# URL, i18n, render, and data-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because URL, localization, render, and data-plane features repeatedly turned attacker-controlled strings into filesystem paths, internal fetches, headers, script contexts, or downstream credentials. These bugs are often “medium” individually, but they compose into SSRF, XSS, data theft, and tenant boundary bypasses.

## Advisories covered

- **i18next/locize localization boundaries** — [GHSA-jfgf-83c5-2c4m](https://github.com/advisories/GHSA-jfgf-83c5-2c4m), [GHSA-5fgg-jcpf-8jjw](https://github.com/advisories/GHSA-5fgg-jcpf-8jjw), [GHSA-c3h8-g69v-pjrg](https://github.com/advisories/GHSA-c3h8-g69v-pjrg), [GHSA-8847-338w-5hcj](https://github.com/advisories/GHSA-8847-338w-5hcj), [GHSA-mgcp-mfp8-3q45](https://github.com/advisories/GHSA-mgcp-mfp8-3q45), [GHSA-w937-fg2h-xhq2](https://github.com/advisories/GHSA-w937-fg2h-xhq2): language/namespace traversal, SSRF, prototype pollution, Content-Language response splitting, filesystem read/write, URL injection, and missing `event.origin` validation. Upgrade to the fixed package versions listed in each advisory.
- **pygeoapi process/STAC boundary** — [GHSA-jgvc-94c8-3chc](https://github.com/advisories/GHSA-jgvc-94c8-3chc), [GHSA-f6pr-83pg-ghh6](https://github.com/advisories/GHSA-f6pr-83pg-ghh6): unauthenticated SSRF via OGC API Processes Subscriber and STAC FileSystemProvider path traversal. Fixed in `0.23.3`.
- **Lemmy metadata/Webmention SSRF** — [GHSA-3jvj-v6w2-h948](https://github.com/advisories/GHSA-3jvj-v6w2-h948), [GHSA-h6hf-9846-xwrq](https://github.com/advisories/GHSA-h6hf-9846-xwrq): Webmention dispatch and `og:image` metadata fetching could reach internal resources or disclose internal images. Fixed in `0.19.18`.
- **QuantumNous/new-api SSRF and webhook signature defaults** — [GHSA-v5c3-6wvc-pc2q](https://github.com/advisories/GHSA-v5c3-6wvc-pc2q), [GHSA-xff3-5c9p-2mr4](https://github.com/advisories/GHSA-xff3-5c9p-2mr4): SSRF filter bypass via `0.0.0.0` and Stripe webhook signature bypass when the secret is empty. Webhook fixed in `0.12.10`; SSRF advisory has no fixed version listed.
- **Flarum/OmniFaces/Marko render-path boundaries** — [GHSA-xjvc-pw2r-6878](https://github.com/advisories/GHSA-xjvc-pw2r-6878), [GHSA-vp6r-9m58-5xv8](https://github.com/advisories/GHSA-vp6r-9m58-5xv8), [GHSA-x9fj-57fh-c8wq](https://github.com/advisories/GHSA-x9fj-57fh-c8wq): LESS path traversal/SSRF incomplete fix, OmniFaces wildcard CDN EL injection, and Marko script/style closing-tag escaping bypass.
- **Kirby/Avo/Arcane/Prometheus/Cilium data exposure** — [GHSA-2h7v-4372-f6x2](https://github.com/advisories/GHSA-2h7v-4372-f6x2), [GHSA-x68m-c7jf-2572](https://github.com/advisories/GHSA-x68m-c7jf-2572), [GHSA-39cp-6679-8xv2](https://github.com/advisories/GHSA-39cp-6679-8xv2), [GHSA-qc5p-3mg5-9fh8](https://github.com/advisories/GHSA-qc5p-3mg5-9fh8), [GHSA-cxx3-hr75-4q96](https://github.com/advisories/GHSA-cxx3-hr75-4q96), [GHSA-fw8g-cg8f-9j28](https://github.com/advisories/GHSA-fw8g-cg8f-9j28), [GHSA-gj49-89wh-h4gj](https://github.com/advisories/GHSA-gj49-89wh-h4gj): permissionless system/user reads, arbitrary action execution, compose-template secret disclosure, stored XSS in old UI heatmaps, and debug archive secret exposure.
- **TorrentPier SQL/deserialization and Signal K brute-force** — [GHSA-fg86-4c2r-7wxw](https://github.com/advisories/GHSA-fg86-4c2r-7wxw), [GHSA-4rwr-8c3m-55f6](https://github.com/advisories/GHSA-4rwr-8c3m-55f6), [GHSA-vmfm-ch9h-5c7g](https://github.com/advisories/GHSA-vmfm-ch9h-5c7g): untrusted deserialization, authenticated SQL injection, and missing WebSocket login rate limiting.

## Operator triage

1. Patch public-facing localization, metadata-fetching, map/process, forum/CMS, dashboard, and API gateway components first.
2. Search outbound proxy/DNS logs for `0.0.0.0`, loopback, link-local, RFC1918, cloud metadata, and internal hostnames triggered by user content.
3. Review localization filesystem roots and caches for unexpected files written through language/namespace values.
4. Rotate secrets present in compose templates, debug archives, dashboard datasource configs, or old logs.

## Durable controls

- Normalize and classify URLs after DNS resolution and before every redirect; block loopback, link-local, private, Unix socket, and metadata ranges at the egress layer.
- Treat localization keys, namespaces, and language tags as identifiers, not paths or URLs. Validate against a finite allowlist.
- Response headers must be generated from structured values; reject CR/LF and invalid language tags before serialization.
- Renderers need context-specific escaping tests, including case variations in closing tags, unquoted attributes, and postMessage origin checks.
- Debug archives and public dashboards require a deny-by-default secret scrubber and explicit publication review.
