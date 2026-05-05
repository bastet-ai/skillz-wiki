# Network, parser, render, and resource-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because small parser and rendering mistakes turn into SSRF, denial of service, data exfiltration, and stored script execution. URL validators, DNS parsers, protocol sniffers, spreadsheet exports, and forum/admin pages need bounded, canonical interpretation.

## Advisories covered

- **MagicMirror `/cors`** — [GHSA-ph6f-2cvq-79hq](https://github.com/advisories/GHSA-ph6f-2cvq-79hq): unauthenticated SSRF.
- **ssrfcheck** — [GHSA-j4rj-2jr5-m439](https://github.com/advisories/GHSA-j4rj-2jr5-m439), [GHSA-p4hc-9pjh-55c8](https://github.com/advisories/GHSA-p4hc-9pjh-55c8), and duplicate [GHSA-c2fv-2fmj-9xrx](https://github.com/advisories/GHSA-c2fv-2fmj-9xrx): incomplete SSRF/reserved-address classification.
- **Hysteria QUIC sniffing** — [GHSA-9fw6-xgg2-mq9q](https://github.com/advisories/GHSA-9fw6-xgg2-mq9q): crafted QUIC packet can crash the server with OOM when sniffing is enabled.
- **GoBGP** — [GHSA-p3w2-64xm-833j](https://github.com/advisories/GHSA-p3w2-64xm-833j): malformed BGP Update can trigger nil-pointer panic.
- **Twisted DNS** — [GHSA-grgv-6hw6-v9g4](https://github.com/advisories/GHSA-grgv-6hw6-v9g4): crafted DNS compression pointer chains cause DoS.
- **phpseclib ASN.1 OID decode** — [GHSA-3qpq-r242-jqj7](https://github.com/advisories/GHSA-3qpq-r242-jqj7): CVE-2024-27355 mitigation bypass enables OID amplification DoS.
- **Kimai XLSX export** — [GHSA-3xc2-h5r3-wv3r](https://github.com/advisories/GHSA-3xc2-h5r3-wv3r): formula injection via tag names.
- **YAFNET forum/admin pages** — [GHSA-8rq5-wwpp-fmj2](https://github.com/advisories/GHSA-8rq5-wwpp-fmj2), [GHSA-xhw7-j96h-c3g5](https://github.com/advisories/GHSA-xhw7-j96h-c3g5), and [GHSA-33gv-fc78-qgf5](https://github.com/advisories/GHSA-33gv-fc78-qgf5): stored XSS, pre-handler admin authorization bypass to blind SQL execution, and second-order event-log XSS through `User-Agent`.

## Operator triage

1. Inventory unauthenticated fetch/CORS/proxy endpoints and libraries advertised as SSRF filters; retest with IPv6, IPv4-mapped IPv6, octal/decimal IPs, redirects, DNS rebinding, link-local, loopback, multicast, and documentation ranges.
2. Disable protocol sniffing and recursive parser features where not required; otherwise place them behind packet, recursion-depth, object-count, and memory limits.
3. For BGP, DNS, QUIC, ASN.1, and OID parsers, fuzz malformed length, pointer, recursion, and compression cases before accepting internet-facing input.
4. Search for exported spreadsheets containing user-controlled values that begin with `=`, `+`, `-`, `@`, tab, CR, or LF.
5. Hunt forum/admin logs for suspicious `User-Agent` payloads, stored script tags, blind SQL execution attempts, and admin pages reached before authorization middleware.

## Durable controls

- SSRF defenses must use a positive egress policy, not only a deny list. Resolve and classify the final destination for every request and redirect.
- Parser loops need explicit depth, allocation, decompression, pointer-hop, and time budgets with fail-closed behavior.
- Spreadsheet exports should prefix dangerous cell values or emit them as typed strings, never raw formulas.
- Authorization middleware must run before route handlers, logging sinks, or admin pre-handlers that can mutate or query data.
- Stored-render surfaces need context-specific output encoding, including admin/event logs that display request headers.
