# CGM CLININET coordinated wave: dynamic module-import RCE, root HL7 listeners, and the appliance adjacent-network trust map (GHSA, 2026-10-23)

Sources: GitHub Security Advisories published 2026-10-23T09:31Z (twelve-advisory coordinated wave against CGM CLININET, a widely deployed European medical-records/practice platform; confirmed band through 2026.MS3, several fixed only in MS3).

- [GHSA-cwv2-4c7h-2v4g / CVE-2025-30050 (critical): RunCGI.pm dynamically imports the module named in a query parameter → attacker-controlled module → root RCE (adjacent network)](https://github.com/advisories/GHSA-cwv2-4c7h-2v4g)
- [GHSA-q872-9p8m-4vww / CVE-2025-30046 (critical): HL7 communication processes run as root while processing untrusted external-system data → adjacent-network root RCE](https://github.com/advisories/GHSA-q872-9p8m-4vww)
- [GHSA-hjw9-7f25-8h43 / CVE-2025-30047 (critical): HTTP API for the admin module exchanges Java serialized objects; crafted serialized object → root RCE (same local network)](https://github.com/advisories/GHSA-hjw9-7f25-8h43)
- [GHSA-xr4f-2f7f-gcx6 / CVE-2025-30054 (critical): root HL7 service's scripts/config writable by the `uhcapache` web user → local priv-esc root](https://github.com/advisories/GHSA-xr4f-2f7f-gcx6)
- [GHSA-rg7r-823r-cw49 / CVE-2025-30043 (high): `/DocManagment` path unauthenticated — patient document list + download](https://github.com/advisories/GHSA-rg7r-823r-cw49)
- [GHSA-r2h5-x9v6-c986 / CVE-2025-30052 (high): rsyncd authenticates solely by client source IP → spoof an allowed address, edit files on the system](https://github.com/advisories/GHSA-r2h5-x9v6-c986)
- [GHSA-rrrj-xjqg-m92h / CVE-2025-30045 (high): ConvExpr function evaluates Perl expressions inside RTF document content → root code execution (authenticated, high-privileged)](https://github.com/advisories/GHSA-rrrj-xjqg-m92h)
- [GHSA-r5px-2ffh-84g7 / CVE-2025-30053 (medium): `cgm-updater` listens on an open network port with no authentication](https://github.com/advisories/GHSA-r5px-2ffh-84g7)
- [GHSA-6j7m-7j95-73q6 / CVE-2025-30051 (medium): production DB credentials + RabbitMQ broker credentials in `SysIO.pl`, world-readable](https://github.com/advisories/GHSA-6j7m-7j95-73q6)
- [GHSA-rjm5-jvqc-mmwv / CVE-2025-30049 (high): user passwords stored as unsalted MD5](https://github.com/advisories/GHSA-rjm5-jvqc-mmwv)
- [GHSA-px77-24r7-j4jj / CVE-2025-58403 (medium): reflected XSS via unsanitized user data in URL](https://github.com/advisories/GHSA-px77-24r7-j4jj)

The durable lesson: **an appliance-style platform's "internal" service layer is a full remote attack surface once you are on its network segment — enumerate the segment-internal listeners (interface-engine ports, updater ports, sync services, serialized-object APIs) as first-class targets, and treat any parameter that names code (module, handler, class) as a direct code-execution sink.**

## Why this is worth an operator pattern

- **Dynamic import of an attacker-named module is RCE, not input validation.** `RunCGI.pm` took the module to import straight from a query parameter. The same sink shape exists in every dynamic-dispatch layer: Perl `require`/`do` on a param, Node `require(param)`, Python `importlib.import_module(param)`, Java `Class.forName(param)`, PHP `include $_GET[...]`. Sweep fingerprint: for every CGI/router/dispatch parameter that looks like an identifier or path (`module=`, `handler=`, `class=`, `do=`), test import-resolution semantics — supply a name you can place on disk and observe load, before theorizing about the application logic behind the dispatcher.
- **Interface engines are forgotten network listeners.** Medical OT logic — HL7/MLLP listeners, integration-engine ports, RIS/PACS bridges — commonly run **as root while parsing untrusted peer data** because the "external systems" are assumed trusted hospital partners. Same pattern in industrial gear (Advantech, openPDC). Post-foothold recon inside any clinic/hospital VLAN: port-sweep for interface-engine and updater services first; their parsers are pre-auth and root-privileged. `cgm-updater` (open unauthenticated port) and Java-native-serialized HTTP APIs round out the listener inventory.
- **Serialized-object HTTP APIs fingerprint themselves.** An admin-module API whose request bodies are Java serialized objects (`\xac\xed` magic over HTTP, non-JSON content-types) is a deserialization sink with no credentials per advisory. Grep captured LAN traffic for serialization magics; when present, gadget-chain work is in-scope validation only in authorized labs.
- **Source-IP-as-credential is still shipping.** rsyncd granting file-edit access based solely on client IP turns a VLAN position or spoofable addressing into a write primitive. Decision rule on any appliance segment: every service whose allowlist is `hosts allow`-style is defeated by source-address control — test from a spoofed/secondary address before assuming the network gate holds.
- **Root service running web-user-writable code.** The privilege ladder `uhcapache → HL7 service scripts → root` is the standard appliance mispermission: a service unit whose script/config paths are writable by a lower-tier service account. After any low-priv shell on an appliance, enumerate the units' `ExecStart` paths and configs for write perms owned by your current token — check-then-root, no kernel exploit needed.
- **Secrets-in-file world-readable defaults.** DB + broker creds in a world-readable config (`SysIO.pl`) is the appliance twin of the credentials-in-logs class: any local token (from the LPE leg or the web user) becomes lateral movement material. `strings` every world-readable config file the first account grants you.
- **Unauthenticated document path.** `/DocManagment` listing + download with zero auth is the missing-auth-class leg — but note it was reachable **from the adjacent network only**, which is why whole waves of these products stay unpatched: the vendor CVSS framing ("adjacent") makes them low-priority for patching while giving the post-foothold operator a PHI-read primitive.

## Validation workflow (authorized scope only)

!!! warning "Authorized medical/enterprise network only — zero PHI, zero production writes"
    Any target running patient data demands written authorization before contact. All proofs below stop at existence and boundary evidence; never download real documents, never send real serialized payloads to a live host, never touch HL7 production queues.

1. **Segment listener inventory (post-authorization, passive-first):** enumerate TCP listeners on the appliance from its network segment — MLLP/HL7 ports, updater ports, rsync (873), and any non-HTTP admin APIs. Record port/banner table; correlate against advisory-named services.
2. **Auth-boundary proofs (read-only):** request the `/DocManagment` list route unauthenticated; a 200 with document metadata (not content) is sufficient PHI-exposure proof — redact before reporting.
3. **Dynamic-import sink (lab instance only):** on a disposable CLININET/lab host, confirm the dispatcher's import semantics with a benign module you place in the include path (`module=<canary_module>` writing a marker file on load); no reverse shells, no persistence.
4. **Deserialization API (lab only):** fingerprint the serialization framing from a benign admin request capture; validate only with lab-hosted ysoserial-equivalent markers against a lab server, never production.
5. **File-permission ladder (lab or authorized audit, read-only):** as the web-tier user, `ls -l` the HL7 service unit's script/config paths; existence of write permission is the finding — do not modify service files on a live system.
6. **rsyncd trust check:** enumerate rsync modules anonymously (`rsync HOST::`); module listing is the reportable boundary; file-edit claims stay at config review (test with marker files only in a lab).

## Reporting checklist

- State the network-position precondition precisely per leg (adjacent/same-LAN vs remote) — the vendor band itself matters for triage, and honest adjacency framing survives review.
- For RunCGI.pm, include the dispatch parameter name and the import-load proof (inert module writing a marker), not a command-execution screenshot.
- For `/DocManagment`, prove list/read gating with metadata only; never attach real documents to a report.
- Pair the LPE and world-readable-creds legs as a chain (`web user → service script write → root`, `any local token → DB/broker creds`) — chains raise severity above the per-CV-leg labels, cf. the Plex2Shell per-leg-CVSS-undervalues-chain archetype.
- Note version evidence (build ≤2026.MS3 vs MS3-fixed) via banner/config fingerprint where available.

Related pages: the [HPE ClearPass unauth primitive ladder](2026-10-07-hpe-clearpass-aos-s-unauth-primitive-ladder-nac-trust-boundaries-ghsa.md) (same appliance pre-auth-parse-is-the-boundary framing), the [Advantech ADAM-3600 protocol ladder](2026-10-20-advantech-adam-3600-edgelink-proprietary-protocol-unauth-primitive-ladder-ghsa.md) (OT interface-engine surface), the Sept 16 OT page (openPDC/openHistorian root-privileged untrusted-data listeners), and the [Sept 18 Semantic MediaWiki page](2026-09-18-semantic-mediawiki-unauth-api-tasks-unsigned-cursor-and-debug-sinks-ghsa.md) for the MediaWiki-family BlueSpice follow-up folded this run.
