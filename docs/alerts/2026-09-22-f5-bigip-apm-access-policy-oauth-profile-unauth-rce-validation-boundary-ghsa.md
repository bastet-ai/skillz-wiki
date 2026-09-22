# F5 BIG-IP APM + OAuth profile: unauthenticated data-plane RCE — perimeter validation boundary

**Date reviewed:** 2026-09-22
**Advisory:** [GHSA-qppv-6jrg-hxq4 / CVE-2026-94127](https://github.com/advisories/GHSA-qppv-6jrg-hxq4) (critical, CVSS 9.8)

F5 publishes an unauthenticated remote-code-execution advisory whose precondition is a **configuration intersection**, not a default install: a virtual server that has **both an APM access policy and an OAuth profile attached**. Specific malicious traffic on the data plane yields RCE; Appliance mode is also vulnerable; F5 states there is no control-plane exposure. This is the same shape as the perimeter VPN/auth-boundary pages already on this wiki (IKEv1 auth bypass, SD-WAN file handling): the finding class is **composite-config perimeter surfaces**, where the exploitable surface exists only where two licensed modules meet on one virtual server.

## Why this is durable operator guidance

1. **Config-intersection surfaces are invisible to version-only scans.** A BIG-IP at a vulnerable version is *not* exploitable unless a vserver binds both an APM policy and an OAuth profile. Version fingerprinting alone gives false positives; the real question is which virtual servers carry the intersection. For an authorized assessment, enumerate the vserver→profile binding table (`/tm/cm/device/config` exports, `bigip.conf` `[profile]`/`[virtual]` blocks, or iControl REST `/mgmt/tm/ltm/virtual` + `/mgmt/tm/apm/policy/access/policy` + `/mgmt/tm/security/oauth/profile` — read-only GETs, auth required) and report the intersection count, not just the build string.
2. **The OAuth-IdP-facing leg is the interesting boundary.** APM acting as an OAuth client puts an unauthenticated, externally reachable HTTP endpoint in front of the access-policy engine. The recurring perimeter pattern (SAML SPs, OAuth relaying parties, OIDC bridges): the federation endpoint is reachable *before* any authentication by design, so its parser/traffic-handling code runs on attacker-chosen bytes pre-auth. When auditing any federation appliance, map the pre-auth request surface each module adds to a shared listener — one module's profile can silently widen another module's attack surface.
3. **Data-plane vs control-plane scoping changes the engagement plan.** F5 scopes this to the data plane: the exposed traffic-handling path, not the management interface. On assessments, that means the relevant question is "which business traffic transits the vulnerable vserver" (everything behind it becomes post-compromise reachable), not "is the management UI exposed." Document the traffic inventory behind each intersecting vserver as the blast-radius section of the report.
4. **Appliance mode is not a mitigation.** Appliance mode restricts admin shell/TMSH capabilities; the advisory explicitly says it remains vulnerable. Don't let a client mark composite-config appliances as mitigated — record appliance-mode state as a fact, not a defense.

## Bounded validation (authorized perimeter assessments)

- **Do not attempt exploitation against production or in-scope-but-unauthorized infrastructure.** No exploit traffic, no crafted payloads against live VSes. This page is a scoping/validation-boundary workflow, not an exploit path; the advisory description is generic ("specific malicious traffic") and no PoC is published.
- Approved-lab workflow only: a BIG-IP lab instance with an APM access policy + OAuth profile on a test virtual server, a synthetic IdP callback, and a lab client. Prove only (a) which build trains are affected per the F5 advisory table, (b) that your config carries the profile intersection, and (c) route-level pre-auth reachability of the OAuth endpoints on that vserver (GET-level, harmless).
- Version/build fingerprinting for authorized targets: the Management UI footer, `/tmui/` redirects, iControl REST version endpoint (authenticated), or banner/JS hash baselining — record build string and hotfix list; do not brute anything.
- Evidence to capture per client: build string, vserver list with profile bindings, intersection verdict, traffic inventory behind each intersecting vserver, appliance-mode state.

## Reporting heuristic

For composite-config appliance findings, structure the report as: version-in-range? → config-intersection present? → which vserver/tenant depends on it → blast radius behind that vserver. Severity is driven by the second and third rows, not the first. A vulnerable build with zero intersecting vservers is an inventory note; one intersecting vserver fronting production SSO traffic is a critical.

## Safety

- Read-only enumeration on authorized targets only; no write iControl calls, no config changes, no payload traffic.
- Lab instances must have no route to production identity providers or internal users.
- Keep hostnames, IdP endpoints, and vserver inventories out of public evidence; they belong in the client report.

## Sources

- [GitHub Advisory GHSA-qppv-6jrg-hxq4 / CVE-2026-94127](https://github.com/advisories/GHSA-qppv-6jrg-hxq4)
- Related perimeter-boundary precedent on this wiki: [Check Point IKEv1 auth bypass](2026-06-08-check-point-ikev1-vpn-auth-bypass.md), [F5 BIG-IP KEV precedent](2026-03-27-f5-big-ip-unspecified-vulnerability-cve-2025-53521.md)
