# CoreDNS TSIG authentication bypass on gRPC, QUIC, DoH, and DoH3 (GHSA-vp29-5652-4fw9)

**Signal:** GitHub Security Advisory updated **2026-04-28**. CoreDNS before the fixed release can treat forged TSIG-bearing requests as authenticated on newer transports.

## What it is
CoreDNS mishandled TSIG verification on several transports:

- gRPC and QUIC checked whether the TSIG key name existed, but did not verify the HMAC.
- DoH and DoH3 did not verify TSIG at all because the response writer reported a nil TSIG status.

If a deployment gates sensitive DNS behavior with TSIG, an attacker may be able to bypass authentication and reach functionality such as AXFR/IXFR zone transfers, dynamic updates, or TSIG-protected plugin paths.

References:
- GitHub advisory: <https://github.com/coredns/coredns/security/advisories/GHSA-vp29-5652-4fw9>
- Release: <https://github.com/coredns/coredns/releases/tag/v1.14.3>

## Triage
1. Inventory CoreDNS instances that expose gRPC, QUIC, DoH, or DoH3 transports.
2. Identify zones or plugins where TSIG is the primary authorization control.
3. Check whether zone transfer, dynamic update, or admin-like DNS flows are reachable over those transports.
4. Review logs for unusual TSIG-signed requests, especially invalid MACs, unknown clients, or unexpected transfer/update attempts.

## Mitigation
- Upgrade CoreDNS to the fixed release or later.
- Until upgraded, disable affected transports where TSIG-protected operations are exposed.
- Restrict CoreDNS management/transfer paths by network allowlist, not TSIG alone.
- Rotate TSIG keys if abuse cannot be ruled out.

## Detection ideas
Look for:

- AXFR/IXFR requests over gRPC, QUIC, DoH, or DoH3 from non-transfer hosts
- dynamic update requests outside expected automation windows
- request patterns containing TSIG records with bad MACs or unexpected key names
- newly disclosed internal hostnames after suspicious zone-transfer activity

## Operator note
Treat TSIG bypasses as **authorization failures**, not just protocol bugs. DNS zone data often provides high-value recon for lateral movement, and dynamic DNS updates can become an infrastructure manipulation primitive.
