# DNS, QUIC, and protocol auth/resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-08 16:15 UTC** protocol batch centered on alternate DNS transports, QUIC stacks, and pre-validation resource budgets.

## Advisories covered

- **CoreDNS TSIG authentication bypass across encrypted/modern transports** — [GHSA-qhmp-q7xh-99rh](https://github.com/advisories/GHSA-qhmp-q7xh-99rh) and prior [GHSA-vp29-5652-4fw9](https://github.com/advisories/GHSA-vp29-5652-4fw9): DoT, DoH, DoH3, DoQ, gRPC, and QUIC paths could accept TSIG-bearing requests without equivalent HMAC enforcement. Patch `github.com/coredns/coredns` to `1.14.3+`.
- **CoreDNS transfer stanza subzone ACL bypass** — [GHSA-h8mm-c463-wjq3](https://github.com/advisories/GHSA-h8mm-c463-wjq3): lexicographic selection can choose the wrong transfer stanza and weaken zone-transfer authorization.
- **CoreDNS DoH GET pre-validation amplification** — [GHSA-63cw-r7xf-jmwr](https://github.com/advisories/GHSA-63cw-r7xf-jmwr): oversized `dns=` query parameters can consume CPU and memory before normal DNS validation.
- **CoreDNS DoQ stream backlog exhaustion** — [GHSA-2wpx-qpw2-g5h5](https://github.com/advisories/GHSA-2wpx-qpw2-g5h5): unbounded stream backlog can exhaust worker capacity.
- **MsQuic remote elevation of privilege** — [GHSA-gvvw-8j96-8g5r](https://github.com/advisories/GHSA-gvvw-8j96-8g5r): affected `Microsoft.Native.Quic.MsQuic.*` packages should move to fixed `2.4.18+` or `2.5.7+` lines.

## Why this is durable

Protocol implementations often add new transports faster than they port every old invariant. TSIG, ACL selection, payload limits, backlog bounds, and crypto-stack privilege boundaries must be enforced identically on UDP/TCP, HTTPS, HTTP/3, QUIC, gRPC, and any future transport wrapper. A control that exists only on the original path is not a control.

## Immediate triage

1. Inventory CoreDNS deployments exposing DoH, DoH3, DoQ, gRPC, QUIC, zone-transfer, dynamic-update, or TSIG-protected plugin paths.
2. Patch CoreDNS to `1.14.3+`; until then, disable affected modern transports or restrict them to trusted network segments where TSIG-protected operations exist.
3. Review CoreDNS logs for AXFR/IXFR, dynamic update, and TSIG-bearing requests from unexpected clients or over unexpected transports.
4. Search NuGet/SBOM inventories for `Microsoft.Native.Quic.MsQuic.OpenSSL` and `Microsoft.Native.Quic.MsQuic.Schannel`; patch to the fixed line and prioritize internet-facing QUIC endpoints.
5. Check edge logs and metrics for large DoH GET `dns=` parameters, unusual HTTP/3/QUIC stream counts, transfer spikes, and unexplained worker saturation.

## Durable controls

- Maintain a protocol-invariant test matrix: every auth, ACL, parser, size, rate, and timeout rule must be tested across every enabled transport.
- Put hard byte, stream, and request-count budgets before expensive decode, decompression, crypto, or DNS-message parsing work.
- Keep zone-transfer and dynamic-update paths behind network allowlists and service identities; TSIG should be one layer, not the only gate.
- Separate public recursive/query endpoints from authoritative management or transfer paths where possible.
- Alert on transport drift: any sensitive DNS operation over a newly enabled transport should be treated as suspicious until explicitly approved.
