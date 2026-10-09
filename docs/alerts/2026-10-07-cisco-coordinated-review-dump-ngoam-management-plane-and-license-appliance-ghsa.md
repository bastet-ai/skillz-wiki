# Cisco coordinated dump wave (35 GHSAs): NGOAM pre-auth root RCE cluster

**Wave in one line:** Coordinated “internal review” dump: NGOAM pre-auth root RCE cluster, NX-API root RCE, and the License On-Prem forgotten appliance (Oct 7 18:32Z wave)

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-10-07. **Thirty-five Cisco GHSAs published 18:32Z** in one coordinated batch across NX-OS, APIC, Cisco License On-Prem (formerly Smart Software Manager On-Prem), Finesse, and Jabber for Android. Most descriptions are the boilerplate "comprehensive internal security review … hardening releases" text with **no affected-version or fixed-version data in the GHSA record at all** — the version truth lives only in Cisco's advisories lookup. The durable value of this wave is not any single CVE; it is the boundary map the batch exposes.

!!! warning "Authorized validation only"
    NX-OS/OAM proofs belong on lab images (nxosv-style virtual Nexus) or customer-owned gear with written approval. OAM-class bugs are triggered by crafted IP traffic against interfaces with the feature enabled — never send crafted OAM/PFCSD/TLV frames on production or third-party networks. Management-plane API proofs stay on owned devices with benign read-only bodies.

## 1. NGOAM: OAM features put an unauthenticated packet parser on every IP interface (four 9.8s)

Four of the batch are the same shape with different OAM dialects:

- **VXLAN OAM (NGOAM)** — [GHSA-cpwq-8jv6-8vg5](https://github.com/advisories/GHSA-cpwq-8jv6-8vg5) / CVE-2026-76485 and [GHSA-x3pw-q73p-vw8x](https://github.com/advisories/GHSA-x3pw-q73p-vw8x) / CVE-2026-76486: unauthenticated remote attacker sends **crafted IP traffic** to an IP interface **when the NGOAM feature is enabled** → arbitrary code execution **as root** or device-reload DoS.
- **SRv6 OAM (NGOAM)** — [GHSA-vxhc-whj8-6j78](https://github.com/advisories/GHSA-vxhc-whj8-6j78) / CVE-2026-76501: same, gated on NGOAM + SRv6 enabled.
- **MPLS OAM** — [GHSA-74h7-6gf3-j457](https://github.com/advisories/GHSA-74h7-6gf3-j457) / CVE-2026-76465 (Nexus 3000/9000): improper validation → unauthenticated root RCE or reload.

Operator axes:

1. **Feature toggles are attack-surface toggles, and the fingerprint is device-local.** An OAM feature adds a *parser for attacker-chosen bytes on ordinary IP traffic* — no management-plane reachability, no credentials, no protocol session handshake required beyond delivering a packet to an enabled interface. On authorized network pentests, `show running-config | include oam|ngoam|srv6|mpls` (and the config-diff against a hardened baseline) tells you *which devices in the estate even have the surface*; a fleet where OAM is enabled on core/fabric interfaces but not edge is a targeting map. Same rule as the Sept 15 KEV page's per-CVE `show-config` gates: the vulnerable condition is configuration state, not just software version.
2. **Root-RCE-or-reload DoS ambiguity is itself useful.** The vendor text pairs code execution with process-crash/reload for the same input class: an out-of-bounds bug that "only" reloads the device still yields full traffic interception during reconvergence. Scope the impact claim to what you can prove in a lab (crash vs controlled execution marker), and never prove the crash leg outside a lab.
3. **Fabric-protocol parsers are the least-audited pre-auth surface.** VXLAN/MPLS/SRv6 OAM traffic never crosses a firewall ACL review because it's "internal fabric." On red-team network engagements, ask which overlay/fabric features the estate runs, then check whether fabric-adjacent segments (server farm, in-band management VLANs) can reach interfaces with them enabled.

## 2. NX-API: the management HTTP API is a root RCE surface (CVE-2026-76471 / GHSA-cw8g-p542-fwjp, 9.8)

Unauthenticated crafted HTTP request to the **NX-API** → arbitrary code execution as root, or process crashes → reload. NX-API (`feature nx-api`, `GET/POST /ins` JSON/XML interface) is the canonical example of the wiki's standing rule that **a device's HTTP management API is a separate product from its CLI**:

1. **Fingerprint NX-API before anything else on a Nexus recon pass**: `GET /ins` (unauthenticated), `GET /` banner, port 80/443/8080 behavior. If NX-API is enabled and reachable, the device exposes a programmatic root-privileged config surface — the advisory makes the parser itself the escalation path.
2. **The batch also hits the broader NX-OS HTTP/API management family** (8.6–9.8 legs at [GHSA-q7hw-286v-vv3w](https://github.com/advisories/GHSA-q7hw-286v-vv3w) CVE-2026-76455 9.8, [GHSA-gmqq-qr7p-pfwh](https://github.com/advisories/GHSA-gmqq-qr7p-pfwh) CVE-2026-76464 9.6, [GHSA-mghj-vwpp-8x3f](https://github.com/advisories/GHSA-mghj-vwpp-8x3f) CVE-2026-76480 9.8, and the 8.6/8.8 remainder 76453–76472 — descriptions sparse), plus **APIC** web management (CVE-2026-20321 admin-to-root command execution and the 9.8 review-group CVE-2026-76498/76499/76500) and **Finesse** web UI (CVE-2026-20362, 7.2). Treat every Cisco product's *web/HTTP management interface* as one target family per engagement, not per-CVE.
3. **CVE-2026-20032 / GHSA-w5w6-f4p9-3h6f** (4.4, authenticated-local): low-privilege user escapes the **NX-OS Python interpreter sandbox** to the underlying OS. Notifiable because it documents the sandbox as a supported operator surface (the `python` shell in NX-OS): if an engagement lands any low-priv shell on a modern NX-OS box, the interpreter sandbox is the LPE candidate — lab-image only, per the standing appliance-shell-escape precedent.

## 3. Cisco License On-Prem: the licensing appliance joins the forgotten-perimeter class

The single highest score in the batch belongs to a licensing box:

- [GHSA-hg4w-vv9x-vfc5](https://github.com/advisories/GHSA-hg4w-vv9x-vfc5) / CVE-2026-76482 — **CVSS 10.0**, "improper input verification" group (CWE-347 pillar) on Cisco License On-Prem.
- [GHSA-p5v8-p64j-pj8c](https://github.com/advisories/GHSA-p5v8-p64j-pj8c) / CVE-2026-76454 (9.1): unauthenticated **arbitrary file write** via the Smart Licensing Utility API.
- [GHSA-v5w6-73vj-7qh9](https://github.com/advisories/GHSA-v5w6-73vj-7qh9) / CVE-2026-20328 (9.1): unauthenticated **password-reset process flaw** → unauthorized access to the application.
- [GHSA-c9jj-q8hj-9gv8](https://github.com/advisories/GHSA-c9jj-q8hj-9gv8) / CVE-2026-76452 and [GHSA-v4f9-w3g4-pjqg](https://github.com/advisories/GHSA-v4f9-w3g4-pjqg) / CVE-2026-76437 (4.9): web management interface lows.

This is the FlexNet `lmadmin` lesson (folded Oct 7 on the Sept 21 mgmt-plane page) landing at enterprise scale: **license/entitlement management servers are ubiquitous, network-reachable, off every scan target list, and staffed by nobody** — until today the CVSS ceiling for that class was high-8s. Operator rules:

1. **Add licensing infrastructure to the standing recon list** next to TACACS/RADIUS/DNS: Cisco License/Smart Software Manager On-Prem, FlexNet, Revenera, FlexLM 2700x/2701x, and vendor license portals. Fingerprint: default HTTPS management UI, `/portal`, Smart Agent/Utility API paths. The unauthenticated file-write + password-reset-reset pair on this product is the same config-write and recovery-flow families already canonical on the Sept 21 pages — reachable *because* nobody segments them.
2. **Unauthenticated arbitrary file write on an appliance VM = the RCE question is "when," not "if."** Per the Sept 21 ZLMediaKit rule, a remote config-set/file-write API is RCE until the value grammar is proven inert; on a licensing server the config paths feed the signing/registration machinery.
3. **A 10.0 on a grouped CWE-347 description means go read the vendor advisory, not the GHSA.** See axis 1 in the next section.

## 4. The "comprehensive internal security review" dump as an intelligence pattern

Most of this wave (License On-Prem 76480–76484, NX-OS 76453–76472, APIC 76498–76501 review group) carries: vendor boilerplate summary, **empty package/version fields**, CVEs grouped under CWE pillars, published in one minute-long window. Durable handling:

1. **GHSA review-dumps are pointers, not sources.** No version ranges in the GH record = the advisory is useless for fingerprinting. Pivot immediately to Cisco's advisories lookup (or the vendor's equivalent) for affected-platform tables and fixed releases; use the *first fixed release per platform train* as the external version fingerprint, exactly as the NetScaler CTX697096 mapping (Sept 15 KEV page) did.
2. **A review dump predicts the next vendor's dump.** These self-reported batches cluster around audit/certification cycles; when one major network vendor ships a 35-advisory "internal review" hardening release, adjacent products in the same BU (here: NX-OS ↔ APIC ↔ License On-Prem ↔ Finesse) get assessed as one perimeter, and patch-skew across them is the engagement opening — the licensing server and Finesse will lag the NX-OS fix by months in most estates.
3. **CVSS 10.0 without exploit detail is a triage signal, not a stop signal.** The public score alone changes prioritization for any authorized assessment of these products; the proof plan still comes from the actual advisory text once published.

## Tracked without publication (same 18:32Z wave)

- Cisco Jabber for Android CVE-2026-101886 path traversal (4.0, mobile local class), CVE-2026-20173 UDP rate-limit DoS, CVE-2026-20038 EPG contract issue, APIC export-policies CVE-2026-76488 (6.5) — noted in the family tables above; no standalone axis.
- GIMP Hot-color/raw-export/PCX plug-in heap overflows (CVE-2026-106065–106067) — memory-safety class per precedent.
- WP Data Access blind SQLi (CVE-2026-95605, 9.3), The Events Calendar / Unlimited Elements deserialization pairs (CVE-2026-95606 / 95534, 9.8/8.8), Forminator missing-authz (CVE-2026-96335) and the sparse WP XSS singles — VulDB-shape WP waves, classes covered on the Sept 19 pages.
- Apache Jackrabbit session fixation/reuse (CVE-2026-92414) + class-selection issue (CVE-2026-92415) — session class canonical (Oct 2 Zammad page); class-selection leg detail-free, revisit when detail lands.
- MISP OTP double-use race CVE-2026-107276 (non-atomic read-validate-delete) and sync description-validation silent drop CVE-2026-107278 — TOCTOU class canonical (Sept 21 page); sync-drop is data-loss, not offensive. Devolutions Server global-vault view-permit accepted for modify/delete (CVE-2026-105488, 7.1) — read-permission-accepted-on-write-verb axis already on the Oct 6 Payload page.

---

*Source: hourly offensive-security scan, 2026-10-07 (18:32Z GitHub advisory wave). Tracked in the [source index](../notes/source-index.md).*
