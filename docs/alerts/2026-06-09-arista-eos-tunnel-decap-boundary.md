# Arista EOS tunnel decapsulation boundary validation

Source: hourly offensive-security scan, 2026-06-09. Primary entries: CISA KEV [CVE-2026-7473](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), NVD [CVE-2026-7473](https://nvd.nist.gov/vuln/detail/CVE-2026-7473), and Arista Security Advisory 0137 at <https://www.arista.com/en/support/advisories-notices/security-advisory/24005-security-advisory-0137>.

This is durable operator guidance because the vulnerability is not just a product alert: it is a reusable **tunnel decapsulation trust-boundary** test. Affected Arista EOS platforms with VXLAN, decap-groups, or GRE tunnel-interface decapsulation can incorrectly decapsulate and forward unexpected tunneled packets when the outer destination IP matches a configured decapsulation IP, because the switch does not sufficiently verify the tunnel protocol type.

## What changed

- CISA added CVE-2026-7473 to KEV on 2026-06-09, with exploitation reported in the wild.
- NVD describes the precondition as an affected Arista EOS platform with tunnel decapsulation configuration present, including VXLAN, decap-groups, or GRE tunnel interfaces.
- The operator-relevant issue is **protocol confusion at a decapsulation endpoint**: traffic addressed to the switch's configured decap IP may be processed as a tunnel even when it is not the expected configured tunnel protocol.
- The useful finding is not generic Arista exposure. It is evidence that an in-scope decap endpoint accepts an unexpected tunnel type and forwards inner traffic into a network segment, VRF, tenant, or route path that should only be reachable through the configured tunnel mode.

## Operator triage

1. **Find decapsulation endpoints first:** in customer-approved config exports or live CLI output, identify VXLAN VTEPs, GRE tunnel interfaces, and decap-group configurations. Record loopback/VTEP addresses, allowed underlay peers, VRFs, VLAN/VNI mappings, and ACLs around the underlay.
2. **Map where the decap IP is reachable:** determine whether the configured decapsulation IP can receive packets from the internet, partner WANs, lab underlays, management networks, or only tightly scoped fabric peers.
3. **Compare expected and unexpected tunnel protocols:** for each decap IP, list the configured tunnel type. A VXLAN-only endpoint accepting GRE-like or other tunneled packets is a stronger boundary break than a simple reachability finding.
4. **Prioritize blast radius:** focus on decap paths that could land inner packets near management planes, tenant networks, storage networks, routing adjacencies, or otherwise segmented workloads.
5. **Tie validation to forwarding evidence:** durable reports show a planted inner probe, controlled destination, packet capture, route hit, or canary callback after unexpected decapsulation. Do not rely only on version strings.

## Replayable validation boundaries

- Test only with explicit authorization for the network device and the underlay path. Tunnel decapsulation probes can cross segmentation boundaries if the device is vulnerable.
- Use a lab switch, maintenance window, or tightly scoped customer-approved test path. Start with one packet at a time; do not scan broad underlay ranges.
- Use documentation/example addresses or planted lab canaries for inner payloads. Avoid probing real internal hosts, management services, routing peers, metadata endpoints, or tenant assets unless they are explicitly in scope.
- Capture both sides where possible: the crafted outer packet to the decap IP and the expected/observed inner packet on a controlled interface or sink.
- Keep protocol tests minimal: one expected configured tunnel sample as a positive control, one unexpected tunnel-protocol sample as the boundary test, and one malformed/negative control.

## Safe validation pattern

1. Build a test matrix from authorized config evidence:
   - decap IP
   - configured tunnel protocol
   - expected peer/source restrictions
   - destination VRF/VLAN/VNI/route path
   - controlled canary destination
2. Establish a positive control using the configured tunnel protocol in a lab or approved fabric path.
3. Send one unexpected tunnel-protocol packet to the same decap IP with a harmless inner probe toward a controlled canary.
4. Confirm whether the inner probe is forwarded by packet capture, flow log, route counter, or canary callback.
5. Repeat only for explicitly scoped decap endpoints. Stop after demonstrating the boundary; do not enumerate internal networks.

## Reporting heuristics

- Lead with the crossed boundary: **unexpected tunnel protocol to configured decapsulation IP to forwarded inner traffic**.
- Include exact preconditions: EOS platform/version if available, decap configuration family, decap IP reachability, expected tunnel protocol, observed unexpected protocol, and the controlled destination used for proof.
- Show why it matters in the assessment context: tenant isolation bypass, underlay-to-overlay reachability, management-plane adjacency, segmentation bypass, or route-policy bypass.
- Keep evidence sanitized. Redact real infrastructure IPs, customer topology names, interface descriptions, and tenant identifiers before publishing or sharing externally.

## Notes on skipped items from this scan

- CISA also added Google Chromium V8 CVE-2026-11645. It is actively exploited and important for client patching, but the public data available in this scan did not add a replayable, durable operator workflow beyond existing browser memory-safety and client-side testing guidance.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub advisory feeds, GitHub Security Blog, and Disclosed did not surface additional new durable offensive-operator deltas beyond items already represented in the wiki.
