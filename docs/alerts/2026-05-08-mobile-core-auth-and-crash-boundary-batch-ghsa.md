# free5GC mobile-core auth and crash-boundary batch

**Signal:** The **2026-05-08 23:15 UTC** advisory scan added a large free5GC SBI batch where internal mobile-core APIs treat network reachability as trust, and several error paths turn malformed or unauthenticated requests into process crashes.

## Advisory cluster

- **NEF route groups missing inbound authorization** — [GHSA-5f62-53r8-qrqf](https://github.com/advisories/GHSA-5f62-53r8-qrqf), [GHSA-rwww-x45w-p52w](https://github.com/advisories/GHSA-rwww-x45w-p52w), [GHSA-3p28-73q7-45xp](https://github.com/advisories/GHSA-3p28-73q7-45xp), [GHSA-cmpj-2x3g-m7g3](https://github.com/advisories/GHSA-cmpj-2x3g-m7g3), and [GHSA-wqfh-gq79-j8mf](https://github.com/advisories/GHSA-wqfh-gq79-j8mf): NEF PFD-management, traffic-influence, OAM, and callback route groups accepted missing or forged bearer tokens.
- **SMF UPI management-plane exposure** — [GHSA-3258-qmv8-frp3](https://github.com/advisories/GHSA-3258-qmv8-frp3), [GHSA-p9mg-74mg-cwwr](https://github.com/advisories/GHSA-p9mg-74mg-cwwr), and [GHSA-44qj-cghf-9p97](https://github.com/advisories/GHSA-44qj-cghf-9p97): unauthenticated UPI topology read/write/delete paths could reach business handlers, nil dereferences, or `Fatalf` process exits. Patch SMF to **1.4.3+** where available.
- **Token/parser and policy-control crash paths** — [GHSA-f8qv-7x5w-qr48](https://github.com/advisories/GHSA-f8qv-7x5w-qr48), [GHSA-wr8j-6chw-gm6p](https://github.com/advisories/GHSA-wr8j-6chw-gm6p), and [GHSA-wwqh-7jm5-gj7w](https://github.com/advisories/GHSA-wwqh-7jm5-gj7w): NRF/PCF structured inputs and downstream error returns could trigger type-confusion or nil-pointer panics. Patch NRF/PCF to the fixed 1.4.x releases where available.
- **UDR/BSF/NEF state and notification panics** — [GHSA-jqfc-gwj5-3w63](https://github.com/advisories/GHSA-jqfc-gwj5-3w63), [GHSA-4rqf-grm6-vf75](https://github.com/advisories/GHSA-4rqf-grm6-vf75), [GHSA-j59f-x285-69jx](https://github.com/advisories/GHSA-j59f-x285-69jx), [GHSA-rxrq-fv76-26pr](https://github.com/advisories/GHSA-rxrq-fv76-26pr), and [GHSA-27ph-8q4f-h7m7](https://github.com/advisories/GHSA-27ph-8q4f-h7m7): missing state, nil `ProblemDetails`, attacker-controlled notify URIs, and unsynchronized maps could crash core services.

## Why this matters

5G core service-based interfaces are often deployed on “trusted” internal networks, but this batch shows why that assumption fails. A flat SBI network turns route-registration mistakes into unauthenticated control-plane mutation, and panic-style error handling turns routine validation failures into availability loss.

## Triage

1. Inventory exposed free5GC SBI listeners, especially NEF, SMF, NRF, PCF, UDR, and BSF ports reachable from lab, tenant, or management networks.
2. Patch components with available fixed versions: SMF/NRF/PCF/UDR **1.4.x** fixes, BSF **1.0.2+**, and NEF **1.2.3+** where the advisory lists a fix; isolate or front components with no patched version.
3. Block all unauthenticated cross-NF HTTP at the network layer. Require mTLS, issuer/audience validation, and explicit route-level authorization before requests hit Gin/OpenAPI handlers.
4. Hunt for unexpected NEF PFD/traffic-influence subscription changes, forged `Authorization: Bearer not-a-real-token` style probes, and repeated 500/recovery logs around UPI, PCF, NRF token, UDR delete, and BSF subscription routes.
5. Treat any process restart from `logger.Fatal`, panic recovery, or concurrent map access as a security event when the triggering request came from outside the exact expected NF peer set.

## Durable controls

- Do not rely on SBI network location as authentication; every route group needs middleware that fails closed.
- Make service enablement config authoritative: disabled APIs should not mount routes.
- Ban `Fatal`/`os.Exit` in request and callback paths; return errors without killing the NF process.
- Add fuzz and negative-state tests for OpenAPI consumers, nil `ProblemDetails`, missing UE/subscription state, and concurrent map mutation.
