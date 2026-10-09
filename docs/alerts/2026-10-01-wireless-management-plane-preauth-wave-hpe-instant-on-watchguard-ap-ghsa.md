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

## October 1 follow-up: TP-Link Tapo C120 v1 / C200 v5 — the onboarding interface lives past setup (4 GHSAs)

Same product-class lesson from a camera fleet: the **HTTPS onboarding interfaces remain reachable and unauthenticated after initial setup**.

| Advisory | CVE | Sev | Primitive |
| --- | --- | --- | --- |
| [GHSA-7ch5-88j9-f3v7](https://github.com/advisories/GHSA-7ch5-88j9-f3v7) | CVE-2026-78577 | Med | Unauthenticated onboarding **scan** action returns nearby AP metadata (SSIDs, BSSIDs, auth/encryption modes, RSSI) — the camera does wardriving for any LAN-adjacent attacker |
| [GHSA-5hx8-fmw3-r64v](https://github.com/advisories/GHSA-5hx8-fmw3-r64v) | CVE-2026-78578 | High | Unauthenticated `do`-method **connect** action accepts attacker-supplied wireless config → camera joins an attacker network / leaves its own, losing its management address |
| [GHSA-gq3v-7fcg-vgjc](https://github.com/advisories/GHSA-gq3v-7fcg-vgjc) | CVE-2026-9032 | — | NULL-deref in the connect-request parser (password field not validated for certain auth/encryption combos) → HTTPS service crash, sustained on repetition, sometimes reboot-only recovery |
| [GHSA-xrj7-3q7x-59fm](https://github.com/advisories/GHSA-xrj7-3q7x-59fm) | CVE-2026-102369 | High | **Full chain:** replay of login challenge data → administrative session → enable a privileged service that only becomes reachable **after a reboot** → crafted MacTool-handler input → arbitrary command execution in the device management process |

- **Setup-mode surfaces that outlive setup.** Same rule as the Instant ON controller plane: enumerate the provisioning/onboarding endpoint family on the *production* service (scan/connect actions, `do` method variants) and test auth gating. A device that has completed onboarding should not still honor onboarding RPCs; when it does, the "post-initial-setup" note in the advisory means every deployed unit is exposed, not just unconfigured ones.
- **Challenge replay = the challenge is a token.** A login challenge must bind to single-use server state; if previously-observed challenge data yields an admin session, the handshake degenerates to replay. Sweep rule for any device challenge-response login: capture one exchange on your own device, replay the server-side artifact, record whether a session mints without the secret.
- **Two-stage activation gates hide services.** The Tapo privileged service becomes network-reachable only after enabling + reboot — static service enumeration on a live device misses it. In the lab, enable advertised/hidden features and re-scan post-reboot; report any service family that appears only in that state.
- **Unauthenticated scan actions are LAN foothold tools.** Post-foothold wireless recon no longer needs radio tools: a vulnerable camera on the VLAN enumerates the surrounding RF environment for you, and the connect action is a stealthy one-packet relocation of an IoT device onto your network.

## October 9 00:3xZ follow-up: TP-Link Tapo C325WB V2 — predictable PSK + onboarding-object auth bypass on the same camera line (3 GHSAs)

The same October 1 Tapo lesson repeated on a newer model (published 2026-10-09T00:31Z by the NVD import, vendor advisories for C325WB V2):

| Advisory | CVE | Sev | Primitive |
| --- | --- | --- | --- |
| [GHSA-9544-m82g-43mh](https://github.com/advisories/GHSA-9544-m82g-43mh) | CVE-2026-105672 | High | **JSON API dispatcher auth bypass on TCP/443:** appending an *onboarding-scoped object* to an authenticated-shape JSON request bypasses session verification entirely → privileged actions unauthenticated (live video/audio, settings changes, device secrets) |
| [GHSA-h78v-m5hq-73p4](https://github.com/advisories/GHSA-h78v-m5hq-73p4) | CVE-2026-105674 | High | **Time-seeded PRNG generates the local media-streaming pre-shared key** → key recoverable/predictable → authenticate to the media service with no user credentials |
| [GHSA-mjqg-3r8q-j4cx](https://github.com/advisories/GHSA-mjqg-3r8q-j4cx) | CVE-2026-105673 | High | Crafted pair of RTSP-over-HTTP tunneling requests crashes the streaming daemon (memory corruption) when Camera Account is enabled — tracked as availability-only unless chained |

Reusable axes this adds to the page:

- **"Feature-scope objects are auth bypasses waiting for a friendly parser."** The bypass is not a route or a parameter — it is a *request-shape token* (an onboarding-scoped object) that the dispatcher's session gate treats as "provisioning mode, skip verification." On any device JSON API: replay captured production requests with provisioning/onboarding/first-run fields or wrapper objects appended, and compare the gate decision table. Same family as this page's onboarding-interfaces-outlive-setup rule, inverted: here an onboarding *object* outlives setup inside normal requests.
- **PRNG-seeded PSKs = offline key recovery from boot time.** Where a device derives keys/seeds from time at first boot, the attack is clock-skew-tolerant brute force offline, not online guessing — adjacent-network attackers recover the key, then authenticate cleanly. Fingerprint: fresh/rebooted devices emitting a new PSK-like credential; correlate observed keys across reboots to spot a narrow entropy window.
- **Same-model-line re-sweep confirmed again:** the Oct 1 C120/C200 quad and this C325WB V2 triple are the same product family shipping the same two classes (onboarding-interface trust + credential derivation). When one Tapo model gets an advisory wave, audit the sibling models for the same dispatcher and key-derivation code paths.

Validation boundary unchanged: owned/lab cameras only; PSK-recovery proofs stop at key recovery against your own device, onboarding-object proofs at one read-only privileged action on a bench unit.

## Durable axes

1. **"Adjacent" means Wi-Fi range or one switched VLAN.** The Instant ON management-protocol advisories rate 9.6 with an *adjacent* attacker: whoever associates to the SSID (or lands any internal foothold) is in scope. For red-team internal recon, treat every AP management IP found in scanning as an unauthenticated target, not scenery — same posture rule as the Sept 22 serial-console page (own the console = own the gear; own the AP = see the air).
2. **The controller↔AP protocol is a separate attack surface from the web UI.** APs accept management-protocol packets authenticated by provisioning/crypto material that has its own bugs (auth bypass, format string, cmdi). Fingerprint the protocol (non-HTTP ports on the AP, e.g. the Instant ON CAPWAP-adjacent management channel) and test it directly rather than only the vendor web console.
3. **Format string in a management interface remains a live RCE class in 2026 firmware** (76722). Any field that flows into a logging/status `printf`-family sink with attacker-controlled format specifiers is read/write/execute. For fuzz triage on APs: `%n`-shaped payloads in every string parameter of the management interface, watch for crashes + partial writes.
4. **Unauthenticated session-mint on an internal API service is the whole chain** (WatchGuard pair). Enumerate the AP's listening services on management/VLAN interfaces; an "internal" API that answers at all is an external auth surface if the port is reachable from any attacker-reachable VLAN. APi tools/vendor CLIs speaking to that service document the endpoints — harvest request shapes from them.
5. **SSRF-to-RCE on the appliance itself** (76728) — on management appliances, SSRF should always be scored as *host execution risk*, because the fetcher runs as a privileged local user with local control services; the classic "read metadata" ceiling doesn't apply.
6. **Fleet-scale implication**: one owned AP inside the RF footprint ⇒ rogue AP/EAP-TLS interception position against every corporate client, plus pivot into the wired management VLAN. Prioritize AP firmware version collection in recon (SNMP sysDescr, web console banner, mDNS) and report Instant ON/older-ArubaOS-C builds as a batched finding.

## Validation boundaries

Authorized engagements only, on owned or expressly-scoped wireless infrastructure. Pre-auth proofs stop at: version/banner fingerprint, service enumeration, one crash or one read-only marker proving reachability — **no public exploit reproduction, no client-session interception, no production APs** (format-string/overflow work is crash-inducing: lab bench units only). Config-comparison evidence (firmware version vs vendor fixed build) is usually enough for the report. Keep packet captures of management-protocol probes on owned channels; never fuzz shared/live RF environments.
