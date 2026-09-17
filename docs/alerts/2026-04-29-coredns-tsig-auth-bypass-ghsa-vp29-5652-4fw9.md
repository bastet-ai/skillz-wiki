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

## September 17 follow-up: opcode policy is per-transport too — unsigned UPDATEs relayed over DoH/DoH3/DoQ/gRPC (GHSA-9gm5-9rfh-m6vx / CVE-2026-86003)

[GHSA-9gm5-9rfh-m6vx](https://github.com/advisories/GHSA-9gm5-9rfh-m6vx) / CVE-2026-86003 (published 2026-09-17T20:33Z, CVSS 7.5) is the transport-parity sibling of the TSIG item above: the UDP/TCP servers reject RFC 2136 **UPDATE** opcodes via `dns.DefaultMsgAcceptFunc` (allows only QUERY/NOTIFY), but the DoH, DoH3, DoQ, and gRPC listeners call `dns.Msg.Unpack` with **no opcode check**, and `forward`/`proxy` relays the UPDATE unchanged to the upstream. If the update-capable upstream trusts CoreDNS's source address or authenticated connection instead of end-to-end TSIG, an **unauthenticated** client can add, replace, or delete DNS records through the resolver — dynamic-DNS takeover without any credential.

- Operator pattern: **when a security policy exists on one transport of a multi-transport server, test every transport for the same policy — request-policy checks (opcode allowlists, header validation, TSIG verification per the April item) are per-listener code paths and drift individually.** For any CoreDNS-style resolver in scope, build a transport × policy decision table: for each of UDP/TCP/DoT/DoH/DoH3/DoQ/gRPC, record whether UPDATE, AXFR/IXFR, and bad-TSIG are rejected *before plugin dispatch*.
- Validation boundary: reproduce only against a lab CoreDNS forwarding to a loopback synthetic upstream (the advisory PoC does exactly this with a stdlib DNS listener on `127.0.0.1`); never relay UPDATEs at a real authoritative server or a customer resolver. Positive = the synthetic upstream receives the UPDATE record over each transport where UDP/TCP rejects it.
- Same family as this run's Grav front-controller item: fast/alternate listeners added later skip the security checks the original path performs — enumerate the transports, then diff their pre-dispatch gates.
