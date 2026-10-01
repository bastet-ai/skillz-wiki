# Wireless management-plane pre-auth wave: HPE Instant ON APs and WatchGuard Access Points

Source: GitHub Security Advisory wave published 2026-09-28/29. Related pages: [Sept 22 serial-console appliance primitive cluster](2026-09-22-lantronix-slc8000-emg-appliance-primitive-cluster-ghsa.md), [June 23 appliance boundaries page](2026-06-23-unifi-lantronix-appliance-boundaries-kev.md), [Sept 21 management-plane page](2026-09-21-management-plane-config-writes-toctou-onboarding-race-and-flat-authz-drift-ghsa.md).

Why this is durable: WLAN controllers and AP fleets sit **between the network edge and every authenticated client session**, ship firmware that rarely auto-updates, and expose a *second* management plane (controller↔AP protocol, on-AP internal API) almost nobody audits. This single-vendor-per-product wave gives a full primitive ladder on each.

## HPE Networking Instant ON (Aruba OS-C) — 8-GHSA ladder on one product

| Advisory | CVE | CVSS | Boundary |
| --- | --- | --- | --- |
| [GHSA-6rfv-6396-m883](https://github.com/advisories/GHSA-6rfv-6396-m883) | CVE-2026-76722 | 9.8 | **Uncontrolled format string** in the affected management interface → unauthenticated *remote* attacker runs arbitrary commands (DoS→RCE) |
| [GHSA-pw85-jqmm-v352](https://github.com/advisories/GHSA-pw85-jqmm-v352) | CVE-2026-76721 | 9.8 | Buffer overflow in the same interface → unauth remote RCE as privileged user |
| [GHSA-377j-9995-vqp9](https://github.com/advisories/GHSA-377j-9995-vqp9) | CVE-2026-76725 | 9.6 | **Management protocol** (controller↔AP) auth bypass for an **unauthenticated adjacent** attacker → complete circumvention → elevated RCE |
| [GHSA-q975-3x5w-9w7r](https://github.com/advisories/GHSA-q975-3x5w-9w7r) | CVE-2026-76724 | 9.6 | Command injection in the CLI over the management protocol, unauth adjacent, crafted packets → privileged commands |
| [GHSA-ghw5-8j5x-rfpq](https://github.com/advisories/GHSA-ghw5-8j5x-rfpq) | CVE-2026-76723 | 9.6 | Buffer overflows, unauth adjacent → RCE |
| [GHSA-7fmh-992m-7rrh](https://github.com/advisories/GHSA-7fmh-992m-7rrh) | CVE-2026-76726 | 8.1 | API endpoint auth bypass → unauthorized access to restricted networks (precondition-dependent) |
| [GHSA-r22v-qj37-qcgq](https://github.com/advisories/GHSA-r22v-qj37-qcgq) | CVE-2026-76727 | 7.2 | Authenticated (high-priv) command injection → privileged OS commands |
| [GHSA-7xpj-rpxw-2rcx](https://github.com/advisories/GHSA-7xpj-rpxw-2rcx) | CVE-2026-76728 | 7.2 | Authenticated **SSRF in the API endpoint → privileged command execution** — the SSRF isn't a read primitive here, it lands on the host |

## WatchGuard Access Points — internal API pair

- [GHSA-238m-p2r4-wp6q](https://github.com/advisories/GHSA-238m-p2r4-wp6q) / CVE-2026-101891: **unauthenticated attacker with network access to the AP obtains a valid API session** from the internal API service.
- [GHSA-vv6p-f93j-23h8](https://github.com/advisories/GHSA-vv6p-f93j-23h8) / CVE-2026-86102: **OS command injection in the same internal API service** — chain the two: session mint → shell on the AP.

Two more AP-firmware entries the same week, same product class: Anjvision YSSD-RTMP-H5 (unauth ONVIF endpoint pack, hidden debug interface toggle, hardcoded cloud-API creds, empty-body `POST /setUserConfig` cred change, legacy hash exposure — [GHSA-x4gx-cgh5-8gqx](https://github.com/advisories/GHSA-x4gx-cgh5-8gqx) et al.) and Dbit T-CPE301K minirouter stack overflow — the recurring "consumer/prosumer radio gear ships unpatched forever" tracking class.

## Durable axes

1. **"Adjacent" means Wi-Fi range or one switched VLAN.** The Instant ON management-protocol advisories rate 9.6 with an *adjacent* attacker: whoever associates to the SSID (or lands any internal foothold) is in scope. For red-team internal recon, treat every AP management IP found in scanning as an unauthenticated target, not scenery — same posture rule as the Sept 22 serial-console page (own the console = own the gear; own the AP = see the air).
2. **The controller↔AP protocol is a separate attack surface from the web UI.** APs accept management-protocol packets authenticated by provisioning/crypto material that has its own bugs (auth bypass, format string, cmdi). Fingerprint the protocol (non-HTTP ports on the AP, e.g. the Instant ON CAPWAP-adjacent management channel) and test it directly rather than only the vendor web console.
3. **Format string in a management interface remains a live RCE class in 2026 firmware** (76722). Any field that flows into a logging/status `printf`-family sink with attacker-controlled format specifiers is read/write/execute. For fuzz triage on APs: `%n`-shaped payloads in every string parameter of the management interface, watch for crashes + partial writes.
4. **Unauthenticated session-mint on an internal API service is the whole chain** (WatchGuard pair). Enumerate the AP's listening services on management/VLAN interfaces; an "internal" API that answers at all is an external auth surface if the port is reachable from any attacker-reachable VLAN. APi tools/vendor CLIs speaking to that service document the endpoints — harvest request shapes from them.
5. **SSRF-to-RCE on the appliance itself** (76728) — on management appliances, SSRF should always be scored as *host execution risk*, because the fetcher runs as a privileged local user with local control services; the classic "read metadata" ceiling doesn't apply.
6. **Fleet-scale implication**: one owned AP inside the RF footprint ⇒ rogue AP/EAP-TLS interception position against every corporate client, plus pivot into the wired management VLAN. Prioritize AP firmware version collection in recon (SNMP sysDescr, web console banner, mDNS) and report Instant ON/older-ArubaOS-C builds as a batched finding.

## Validation boundaries

Authorized engagements only, on owned or expressly-scoped wireless infrastructure. Pre-auth proofs stop at: version/banner fingerprint, service enumeration, one crash or one read-only marker proving reachability — **no public exploit reproduction, no client-session interception, no production APs** (format-string/overflow work is crash-inducing: lab bench units only). Config-comparison evidence (firmware version vs vendor fixed build) is usually enough for the report. Keep packet captures of management-protocol probes on owned channels; never fuzz shared/live RF environments.
