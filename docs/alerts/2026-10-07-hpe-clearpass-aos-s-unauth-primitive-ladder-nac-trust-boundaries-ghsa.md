# HPE ClearPass Policy Manager + AOS-S coordinated wave: unauthenticated primitive ladder on the NAC brain

Source: GitHub Security Advisories wave published 2026-10-06T21:32Z — ~28 GHSAs for **HPE Networking ClearPass Policy Manager** and **ArubaOS-Switch (AOS-S)** in one vendor bulletin window (HPE bulletins [hpesbnw05158](https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05158en_us&docLocale=en_US) for ClearPass, [hpesbnw05156](https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05156en_us&docLocale=en_US) for AOS-S). Related pages: [Oct 1 wireless management-plane pre-auth wave](2026-10-01-wireless-management-plane-preauth-wave-hpe-instant-on-watchguard-ap-ghsa.md) (same Aruba ecosystem, AP/controller plane), [Oct 2 UTMStack transport page](2026-10-02-utmstack-internal-key-header-and-agent-command-transport-ghsa.md) (agent-fleet reasoning), [Sept 15 KEV wave page](2026-09-15-kev-wave-netscaler-cisco-routeros-jfrog-gitlab-screenconnect.md) (perimeter appliance validation posture).

Why this is durable: ClearPass is the **network access control brain** — it decides VLAN assignment, posture admission, and identity for every wired/wireless endpoint in the estate, stores RADIUS/EAP/IdP credentials, and pushes policy to an OnGuard agent fleet running elevated on every managed endpoint. It is the same credential-dense, agent-riddled appliance class as UTMStack and Zammad, and this wave puts a **full unauthenticated primitive ladder** on the management interface plus a second, network-facing attack surface on the endpoint agents themselves.

## 1. The management interface ladder (ClearPass)

| Advisory | CVE | Sev. | Primitive |
| --- | --- | --- | --- |
| [GHSA-757q-87fg-c2p6](https://github.com/advisories/GHSA-757q-87fg-c2p6) | CVE-2026-76750 | critical | **Unauthenticated deserialization of untrusted data in the web interface → RCE** on the appliance |
| [GHSA-m7g4-2j92-rmph](https://github.com/advisories/GHSA-m7g4-2j92-rmph) | CVE-2026-76752 | critical | **Unauthenticated auth bypass (web + API interfaces) → administrative access** |
| [GHSA-62qp-w4gp-5m8w](https://github.com/advisories/GHSA-62qp-w4gp-5m8w) | CVE-2026-76753 | critical | **Unauthenticated format string in a service interface** → memory corruption → code execution |
| [GHSA-qvwm-rf7f-hmh9](https://github.com/advisories/GHSA-qvwm-rf7f-hmh9) | CVE-2026-76754 | critical | **Unauthenticated SQL injection** against the ClearPass instance → arbitrary database commands |
| [GHSA-7wf7-w5jj-hhjq](https://github.com/advisories/GHSA-7wf7-w5jj-hhjq) | CVE-2026-79796 | critical | Vulnerabilities in the affected interface, unauthenticated remote (boilerplate detail) |
| [GHSA-x6vr-x995-pjqg](https://github.com/advisories/GHSA-x6vr-x995-pjqg) | CVE-2026-79809 | high | **Unauthenticated path traversal in an API endpoint that influences authorization decisions → unintended role assignment** |
| [GHSA-cr9w-rx83-m757](https://github.com/advisories/GHSA-cr9w-rx83-m757) | CVE-2026-79818 | medium | Unauthenticated API auth circumvention → sensitive information |
| [GHSA-3f5c-px44-h7w5](https://github.com/advisories/GHSA-3f5c-px44-h7w5) | CVE-2026-79794 | critical | Authenticated SQL injection (web UI) → arbitrary database commands |
| [GHSA-gmmr-x93w-hv99](https://github.com/advisories/GHSA-gmmr-x93w-hv99) | CVE-2026-79798 | critical | **Low-privileged** authenticated SQL injection (web UI) |
| [GHSA-695p-j8g6-xv66](https://github.com/advisories/GHSA-695p-j8g6-xv66) | CVE-2026-79811 | high | SQL injection in the API (remote) |
| [GHSA-m27g-wj58-2ppf](https://github.com/advisories/GHSA-m27g-wj58-2ppf) | CVE-2026-79799 | high | **Stored XSS → admin browser** via the web management interface |
| [GHSA-5c69-x6gv-pf4x](https://github.com/advisories/GHSA-5c69-x6gv-pf4x) | CVE-2026-79810 | high | Authenticated high-priv RCE → arbitrary OS commands on the underlying host |
| [GHSA-2h4r-fr3h-ff6g](https://github.com/advisories/GHSA-2h4r-fr3h-ff6g) | CVE-2026-79803 | high | Command injection in the API |
| [GHSA-6f23-w4wq-f8hw](https://github.com/advisories/GHSA-6f23-w4wq-f8hw) / [GHSA-9c7m-r2h4-cc62](https://github.com/advisories/GHSA-9c7m-r2h4-cc62) | CVE-2026-79805 / CVE-2026-79800 | critical / high | Authenticated path traversal (product + CLI interface) |

Operator axes:

1. **Pre-auth parse is the auth layer.** Four distinct unauthenticated classes (deserialization, format string, SQLi, auth bypass) landed on the *same* management/API surface in one bulletin. Whenever unauthenticated input reaches a deserializer, a format sink, or a query builder, authentication never had a chance to be the boundary — memory-safety and injection bugs in the pre-auth parse path are equivalent to auth bypass on that route. Sweep posture for any appliance admin plane: treat every reachable route's *parse* layer as an untrusted-code surface, and prioritize products whose bulletin lists unauthenticated deserialization/format-string items — that combination says the interface layer processes attacker bytes before identity.
2. **Path traversal as an authorization oracle, not a file reader** (79809). The traversal "influences authorization decisions and role assignment" — the path value is steering the *authorization input plane*, and the outcome is an unintended role, not a disclosed file. Generalization: when a path/route/identifier is used for both dispatch and policy lookup, normalization differentials (encoding, separators, case, suffix drift) between the authorization lookup and the handler dispatch are role-confusion candidates. Decision table per API family: request path spelling → authorization-decision path → handler actually run → role assigned. (Same check-vs-use family as the Elasticsearch leg folded on the Sept 18 ignored-scope page this same wave.)
3. **Low-privilege SQLi is the engagement-relevant SQLi.** The wave carries unauth, admin-authenticated, *and* low-priv web-UI SQLi legs. On NAC appliances the "low-privileged" account is often handed to helpdesk/auditors/monitoring integrations; a low-priv DB-command primitive on the system that stores every user's network identity and every integration credential is a full-estate compromise. Enumerate every role tier's SQLi surface separately; do not merge the legs into one finding.
4. **Stored XSS on a NAC admin UI is a token-steering pivot**, not a browser nuisance: the admin context can change policy, and the Oct 1 wireless page's rule applies — policy-plane XSS ⇒ wire/VLAN authority. Proof stays as a harmless marker in a lab admin session.

## 2. The OnGuard agent fleet is a second network-facing attack surface

| Advisory | CVE | Sev. | Primitive |
| --- | --- | --- | --- |
| [GHSA-rpmp-r6c2-r27x](https://github.com/advisories/GHSA-rpmp-r6c2-r27x) | CVE-2026-76751 | critical | **Missing integrity verification in the OnGuard agent → unauthenticated remote attacker executes arbitrary code on the endpoint with the agent's elevated privileges** |
| [GHSA-rc64-m9vj-82j9](https://github.com/advisories/GHSA-rc64-m9vj-82j9) | CVE-2026-79801 | critical | Missing integrity verification in the client agent software |
| [GHSA-rvh5-8jr8-6mgm](https://github.com/advisories/GHSA-rvh5-8jr8-6mgm) | CVE-2026-79807 | high | Missing integrity verification in the Windows client |
| [GHSA-vrf6-8f5q-64r6](https://github.com/advisories/GHSA-vrf6-8f5q-64r6) | CVE-2026-79808 | high | Buffer overflow in the OnGuard agent |
| [GHSA-5mfp-rqmh-c9ff](https://github.com/advisories/GHSA-5mfp-rqmh-c9ff) | CVE-2026-79815 | medium | Command injection in the OnGuard agent |
| [GHSA-hj73-xc58-6r33](https://github.com/advisories/GHSA-hj73-xc58-6r33) | CVE-2026-79814 | medium | Arbitrary file write in the OnGuard agent |
| [GHSA-pp5m-v773-p3rf](https://github.com/advisories/GHSA-pp5m-v773-p3rf) | CVE-2026-79806 | high | Privilege escalation, OnGuard **Linux** agent |
| [GHSA-49cr-m39h-fpjw](https://github.com/advisories/GHSA-49cr-m39h-fpjw) | CVE-2026-79802 | high | Command injection in client software |

- **Attack the agents, not the server.** OnGuard runs elevated on every managed endpoint and takes work from the ClearPass plane. "Unauthenticated remote attacker" against an agent whose update/command channel lacks integrity verification means network-position attackers can target **every domain-joined endpoint in the estate** without ever touching the appliance. Red-team inference (state as inference in reports): once you hold the management/infrastructure VLAN that agents trust, agent-channel payloads are a fleet-wide delivery mechanism; the recon step is identifying agent listener ports/services on endpoints (local service enumeration on a foothold, agent binaries' update URL grammar) — validation only in labs or against expressly-scoped endpoints.
- **Missing-integrity-verification recurs as its own class** across this wiki (update channels, plugin signatures, this wave's three separate legs): any channel where the endpoint *accepts* code/config from a lower-trust network position and no signature/proof-of-origin check gates it. Audit rule for agent fleets: diff who can *send* to the agent vs what the agent will *execute*, and test the gap against your own lab agent.
- [GHSA-4325-q6rc-wccx](https://github.com/advisories/GHSA-4325-q6rc-wccx) / CVE-2026-79797 rounds it out: Android client functionality invocable by untrusted sources (exported-component exposure, user-interaction info disclosure) — the mobile-client sibling of the same fleet surface.

## 3. AOS-S (ArubaOS-Switch) — the wired sibling of the Oct 1 wireless page

| Advisory | CVE | Sev. | Primitive |
| --- | --- | --- | --- |
| [GHSA-824j-mqpc-h7v9](https://github.com/advisories/GHSA-824j-mqpc-h7v9) | CVE-2026-76742 | critical | **Unauthenticated auth bypass, web management interface** → unauthorized access |
| [GHSA-jgvj-7684-4x9v](https://github.com/advisories/GHSA-jgvj-7684-4x9v) / [GHSA-5mpc-p2jf-4mh3](https://github.com/advisories/GHSA-5mpc-p2jf-4mh3) / [GHSA-cm3h-pm88-5rxx](https://github.com/advisories/GHSA-cm3h-pm88-5rxx) | CVE-2026-76747 / 76744 / 76745 | critical | Buffer-overflow / memory-corruption clusters reachable by **unauthenticated (and adjacent) attackers** |
| [GHSA-xjm4-53qx-cfrp](https://github.com/advisories/GHSA-xjm4-53qx-cfrp) | CVE-2026-76746 | critical | Unauthenticated **adjacent** buffer overflow → memory disclosure + DoS |
| [GHSA-8cx3-28f8-cvcq](https://github.com/advisories/GHSA-8cx3-28f8-cvcq) | CVE-2026-76748 | high | **API privilege escalation** |
| [GHSA-535g-9395-6mq8](https://github.com/advisories/GHSA-535g-9395-6mq8) | CVE-2026-76743 | critical | Management-interface vulnerability, potential RCE |
| [GHSA-rjjv-xg7f-54c4](https://github.com/advisories/GHSA-rjjv-xg7f-54c4) | CVE-2026-76749 | medium | Sensitive information disclosure |

- Same lesson as the Oct 1 Instant ON page, one layer down: **the access switch is the post-foothold prize**. Own the access switch and you control port VLANs, see the wired segment every AP hangs off, and can redirect traffic for anything on the port. Recon: AOS-S banners/`sysDescr` via SNMP are the version fingerprint; batch-report vulnerable firmware like the AP fleet rule.
- HPE shipped Aruba-family bulletins (Instant ON late Sept, ClearPass + AOS-S now) in a single audit cycle — when one vendor product family gets a coordinated wave, **re-sweep the vendor's sibling product families within the hour**; the advisories share a bulletin pipeline and land in adjacent windows.

## Version fingerprint and validation boundaries

- Fingerprint targets by product + firmware/release against the two HPE bulletins above (ClearPass release notes / AOS-S version strings; SNMP `sysDescr`, web console banner). GHSA CVSS fields were sparse at publication; severity here is from the advisory listings — re-check scores after GitHub enrichment.
- Authorized engagements only. The unauthenticated memory-safety legs (deserialization, format string, overflows) are **crash-inducing and potentially appliance-bricking — a crashed ClearPass is a network-wide admission outage**: bench/lab appliances only, never production NAC. Pre-auth proofs on production stop at version evidence, route/auth gating checks, and read-only disclosure markers. OnGuard agent execution work: lab agents in disposable VMs only. Stored-XSS and traversal-role proofs: lab instances, synthetic users, marker-only mutations. No public exploit reproduction; keep any captured agent-channel traffic to lab captures.
