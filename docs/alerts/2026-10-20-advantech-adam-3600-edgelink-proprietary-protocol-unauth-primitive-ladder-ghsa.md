# Advantech ADAM-3600 EdgeLink — proprietary-protocol unauthenticated primitive ladder on an OT RTU (30-CVE CSA-coordinated wave, < 2.8.5.0)

Source: hourly offensive-security scan, 2026-10-20. The GitHub published feed landed a 30-advisory Advantech batch at 09:31Z on 2026-10-20 (CVE-2026-43829 through CVE-2026-43858 plus the July-31-published CVE-2026-43829..43833 enrichment re-listings). Every GHSA carries **empty package/version fields and no description beyond one sentence** — the vendor-advisory review-dump fingerprint (same shape as the Oct 14 NGINX wave and the Oct 7 Cisco dump). The real source is the CSA alert [al-2026-149](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-149) and Advantech's [security advisory page](https://www.advantech.com/en/security-advisory). Affected: ADAM-3600 EdgeLink **prior to 2.8.5.0**. Timeline: vendor disclosure 2026-04-29, patched 2026-10-15, public release 2026-10-20.

ADAM-3600 EdgeLink is a remote terminal unit for industrial data acquisition/remote monitoring — OT-adjacent infrastructure that is frequently internet-reachable through RTU cellular links and rarely in the patch loop.

## The primitive ladder (from the CSA severity table)

Unauthenticated / pre-auth:

- **Forged packet → arbitrary commands with maximum privileges** — CVE-2026-43836 (9.3). One crafted packet on the proprietary protocol = root-equivalent execution. No credential, no session.
- **Proprietary protocol authentication bypass** — CVE-2026-43844 (9.3).
- **Password-reset mechanism authentication bypass** — CVE-2026-43845 (9.2).
- **Stack overflows, unauthenticated**: password functionality (CVE-2026-43829, 9.2), log message functionality (CVE-2026-43831, 9.2), Cookie parsing (CVE-2026-43832, 9.2), login functionality (CVE-2026-43838, 9.2). Note the qualifier on two of them: code execution **when the SafeEnhancement feature is enabled**.
- **Brute force of the admin password without restrictions "even when the SafeEnhancement feature is enabled"** — CVE-2026-43847 (8.2).
- **License manager service unauthenticated crash surface with named internal handlers**: NULL deref via `on_disconnected` callback (CVE-2026-43840), via `rpc_rx_fsm` (CVE-2026-43841), via `rpc_rx_fsm` **when msglen is set to 0** (CVE-2026-43842), integer overflow (CVE-2026-43843). Bulk port configuration unauth crash (CVE-2026-43848).
- **Heap memory read → sensitive data exfiltration** — CVE-2026-43849.
- **Assertion fault via crafted message → service crash** — CVE-2026-43853.

Authenticated (guest/low tier included — CVE-2026-43837 is code execution from **guest** authentication):

- **Forged firmware upgrade file → permanent device compromise** — CVE-2026-43835 (8.6).
- **Command injection → root code execution** — CVE-2026-43850 (8.6); additional authenticated stack overflows incl. `FileProcess::CheckDir` with a path longer than 1024 bytes (CVE-2026-43856).
- **Arbitrary file read (path traversal)** — CVE-2026-43851; **arbitrary file write** — CVE-2026-43852.
- **Encrypted project file → administrator credentials for EdgeLink-enabled devices** — CVE-2026-43854 (6.3): possession of the project file is the whole attack.
- Authenticated stack overflows in upload and logs-settings functionality (CVE-2026-43833/43834), overflow in a **non-functional feature** reachable post-auth (CVE-2026-43846).

## Durable operator axes

1. **The proprietary protocol IS the product; the HTTP UI is a side show.** This ladder lives almost entirely in a custom RPC/packet protocol (`rpc_rx_fsm` in the advisory text confirms an RPC state machine). For OT/RTU engagements, fingerprint non-HTTP listeners first; banner-grab and replay anything that speaks a framed binary RPC. The Tektronix SCPI rule (second management plane with weaker controls than the web UI) generalizes: enumerate parsers by protocol, not by product page.
2. **A security feature can be the attack-surface selector.** Two unauth overflows list *SafeEnhancement enabled* as the precondition, and a third bug (unthrottled brute force) demonstrates the feature **not** being enforced on the protocol path. Two rules: (a) feature-gate battery — map which config state opens which surface; enabling a hardening toggle can add parsed fields (the overflow ingress); (b) feature-name vs enforcement — never credit a named security feature without differential testing on/off (`SafeEnhancement on` vs `off` decision table on every control the vendor markets). Same genealogy as the NetScaler per-CVE show-config gates (Oct 4) and Cisco feature-enabled surface rule (Oct 7): **configuration state, not just version, is the fingerprint**.
3. **Advisory wording is a fuzzing map.** `rpc_rx_fsm` with `msglen == 0`, `on_disconnected` callback ordering, a `CheckDir` path >1024 bytes, "crafted message → assertion fault": these sentences name the handler, the boundary value, and the failure mode. Harvest every named function/parameter/size from thin advisories into a protocol-fuzzer harness spec before touching the device.
4. **Bulk verbs and lifecycle callbacks are the classic unauth gaps** (bulk port config, disconnect-callback path) — same per-item-vs-bulk and lifecycle-handler authz drift this wiki carries for API surfaces; it shows up verbatim in appliance firmware.
5. **The project/engineering file is a credential carrier** (CVE-2026-43854). For OT gear, collect the vendor engineering/client project format, check what it stores and how it encrypts; possession-only credential recovery is a standing finding class (parallels the CHARX EV install-material-crypto-is-obfuscation rule).
6. **Forged-firmware permanence + guest-tier RCE + heap-read exfil = full OT appliance kill chain** across three tiers. Firmware signature/update-channel questions route to the [September 16 update-key page](2026-09-16-secret-server-identity-crypto-boundaries-and-ot-hardcoded-update-keys-ghsa.md); test the *forged update acceptance* decision in a lab, never against a field RTU.
7. **Dark-window note**: disclosure 2026-04-29, patch 2026-10-15, publication 2026-10-20 — five months of private knowledge ends today; expect scanning signatures for ADAM/EdgeLink banners within days. None of these CVEs are in KEV (catalog 2026.10.16) as of this scan — KEV-watch this set.

## Validation boundaries (authorized lab/scope only)

- Lab-owned ADAM-3600 unit or customer-approved scope only; never probe production RTUs — these are safety-adjacent industrial devices, and half the ladder is crash-class.
- Fingerprint from passive/low-impact steps first: listener enumeration, banner, firmware revision readout.
- Prove overflow reachability with length-boundary markers against your own device and capture crash-oracle evidence (service restart timing) without shipping exploit bytes; prove auth bypass on your own lab credential set; prove the brute-force gap with rate measurements against your own device only.
- Firmware proofs stop at acceptance/rejection decision recording with an inert forged package on a lab unit — never flash field devices.
- Report evidence: exact firmware band (< 2.8.5.0 vs 2.8.5.0), SafeEnhancement on/off state per test, listener/port inventory, named-handler behavior table, redacted crash dumps.

## Reporting heuristics

- Lead with the unauthenticated forged-packet → max-privilege leg; the ladder's other legs establish breadth, not the headline.
- State SafeEnhancement state explicitly per finding — the vendor's own table conditions exploitability on it.
- For the guest-tier overflow, spell out the tier: guest auth on an OT device is usually trivially obtainable (default/shared guest credentials).
- Keep the heap-read finding grounded in what bytes were observed — call it disclosure, not RCE.
- Reference the CSA alert as the canonical severity source; GHSA descriptions are stubs.
