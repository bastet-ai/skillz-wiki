# Synology DSM wave (27 GHSAs): pre-auth SQLi in the login API writes files

**Published:** 2026-11-12 06:30Z, one coordinated Synology DSM release split across vendor advisories [Synology_SA_26_18](https://www.synology.com/en-global/security/advisory/Synology_SA_26_18) (25 GHSAs) and [Synology_SA_26_19](https://www.synology.com/en-global/security/advisory/Synology_SA_26_19) (2 GHSAs). GHSA package/version fields are **empty** across the wave, the vendor-advisory band-fingerprinting pattern. Fix bands run in **four parallel LTS branches**: 7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, 7.4.1-90080-1. None of these CVEs are in KEV as of catalog 2026.11.10 = head-start window for lab validation.

**Wave in one line:** the crown jewel is a **CVSS 9.8 unauthenticated SQL injection in the Auth API whose impact is arbitrary file read/write**, sitting inside a release where the recurring shape is **per-API authorization drift**: DSM's `/webapi/*.cgi?api=SYNO.*` handlers each carry their own authz declaration, and this wave shows half a dozen of them declaring it wrong or not at all.

**Audience:** pentesters and bug hunters working SMB/home-office perimeters (port-forwarded NAS is a standing finding class), MSP estates with Synology fleets, and any engagement where a DiskStation sits on the internal LAN.

!!! warning "Authorized validation only"
    All testing below belongs in owned labs or explicitly approved customer windows. Keep rsync/WebDAV/SNMP probes against your own units, never brute-force or race a third-party NAS, and do not use vendor Support Form paths against production devices.

## 1. The login API itself is the critical sink

- [GHSA-j4cj-7f89-84j2](https://github.com/advisories/GHSA-j4cj-7f89-84j2) / [CVE-2026-76954](https://nvd.nist.gov/vuln/detail/CVE-2026-76954) (**critical, CVSS 9.8 per vendor**): SQL injection in the **Auth API** lets a **remote unauthenticated attacker read or write arbitrary files** and cause DoS (fixed in all four branches: 7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, 7.4.1-90080-1, [SA_26_19](https://www.synology.com/en-global/security/advisory/Synology_SA_26_19)). The pre-auth login parameters (username-shaped input, session/OTP-adjacent fields) cross into SQL statement construction before any identity exists. An injection in an auth endpoint is priced differently than injection elsewhere: it is reachable at the highest request volume, unauthenticated by definition, and its write primitive lands you on the box, not just in the database.
- [GHSA-mjrf-jqrc-6h77](https://github.com/advisories/GHSA-mjrf-jqrc-6h77) / [CVE-2026-74857](https://nvd.nist.gov/vuln/detail/CVE-2026-74857) (high): **missing critical step in authentication** in the same Auth API surface: authenticated users reach arbitrary file read/write. Two Auth-API legs in one release = the login handler family deserves full-parameter treatment, not just the advertised route.

Operator rules:

1. **Treat login/OTP/session parameters as injection sinks first-class.** On any appliance, run the full grammar battery (quotes, comments, stacked separators, encoding layers) against username, OTP token, device-name, and session fields even when the response looks like a fixed accept/deny. Blind differential via response shape, timing, and side effects (file artifacts, log entries) is the proof surface.
2. **Per-CVE branch sets are the fingerprint.** In this wave each CVE lists its own subset of the four fix branches (e.g., the rsync and Auth-API criticals cover all four, the OTP and Sharing-API legs only 7.3.2/7.4.1). Reading the per-CVE branch table from the vendor advisory tells you which LTS line a target runs even with no version banner, and which older branches were never patched for a given bug at all.

## 2. Sidecar protocol services are parallel auth implementations, and two of them are bypassed

The DSM auth gate lives in `synoscgi`/the webapi layer, but the appliance ships **separate protocol services with their own auth code paths**, and this wave has bypasses in the sidecars rather than the front door:

- [GHSA-33f8-93g6-v9ch](https://github.com/advisories/GHSA-33f8-93g6-v9ch) / [CVE-2026-85101](https://nvd.nist.gov/vuln/detail/CVE-2026-85101) (high): **authentication bypass using an alternate path or channel in rsync** (all four branches): remote attackers read specific files, write arbitrary files. The rsync daemon is a DSM *package-shaped* service with its own daemon auth, and DSM UI policy changes historically do not have to reach it.
- [GHSA-3grq-vh3r-2ww4](https://github.com/advisories/GHSA-3grq-vh3r-2ww4) / [CVE-2026-18596](https://nvd.nist.gov/vuln/detail/CVE-2026-18596) (high): **OTP authentication bypass using an alternate path or channel** (7.3.2/7.4.1): a user with valid credentials skips the second factor by entering through a path that never consults the OTP check. 2FA lives in the login flow you know; every *other* flow that establishes a session is an OTP bypass candidate.
- [GHSA-fx8j-vqw6-4wwc](https://github.com/advisories/GHSA-fx8j-vqw6-4wwc) / [CVE-2026-15198](https://nvd.nist.gov/vuln/detail/CVE-2026-15198) (medium): **missing authentication for critical functionality in the WebDAV API**: remote unauthenticated file read plus limited DoS.
- Supporting memory-safety legs on the same sidecar set: [GHSA-3f7c-6jjj-gfhf](https://github.com/advisories/GHSA-3f7c-6jjj-gfhf) / CVE-2026-18633 (high, uninitialized pointer in **nfsd**, remote DoS) and [GHSA-662v-m44m-2f3p](https://github.com/advisories/GHSA-662v-m44m-2f3p) / CVE-2026-85098 (medium, reachable assertion in **synoscgi**).

Operator rules:

1. **Enumerate the appliance's protocol services as a separate authorization surface.** For DSM that means rsync, WebDAV, NFS, SNMP, FTP/SFTP, Samba, the update daemon, and quickconnect relay legs. For each, the audit question is binary: does the service consult the DSM account policy (password policy, OTP, IP allowlist, account expiry), or does it authenticate against its own copy of the credential store? Any "own copy" answer reproduces this wave's class.
2. **OTP bypass battery:** for each session-establishing entry point (web login, DS file/Drive clients, WebDAV auth, SSH, API tokens, QR/pairing flows) record whether the OTP step is consulted. Present/valid vs present/garbage vs **channel-doesnt-ask** is the three-column decision table; only the third column is a finding nobody tests.

## 3. The webapi layer: per-handler authz declarations drift, again

DSM exposes hundreds of `SYNO.*` APIs via `/webapi/<service>.cgi?api=SYNO.X.Y`. Each handler declares its own auth requirement, and this release is an inventory of drifted declarations:

- Missing authorization (authenticated, or unauthenticated where it shouldn't be): **SocketIo API** write-specific-files ([GHSA-5wwj-g6wh-r9xg](https://github.com/advisories/GHSA-5wwj-g6wh-r9xg) / CVE-2026-81558), **TaskScheduler API** write ([GHSA-8qpp-525r-f9v7](https://github.com/advisories/GHSA-8qpp-525r-f9v7) / CVE-2026-81559), **Promotion API** write ([GHSA-q6f2-r5jp-cwmf](https://github.com/advisories/GHSA-q6f2-r5jp-cwmf) / CVE-2026-19414), **ACL API** read/write ([GHSA-63wp-rj7x-3pv4](https://github.com/advisories/GHSA-63wp-rj7x-3pv4) / CVE-2026-19833), **Security Advisor** unauthenticated file read ([GHSA-5737-cpp3-8657](https://github.com/advisories/GHSA-5737-cpp3-8657) / CVE-2026-124993).
- **Credential API SSRF** with specific-file read ([GHSA-qxxp-wc8c-4g75](https://github.com/advisories/GHSA-qxxp-wc8c-4g75) / CVE-2026-77738): the API that stores third-party creds also dials out on their behalf.
- **SSOAuth authorization bypass through user-controlled key** ([GHSA-8wrc-pj93-f9hp](https://github.com/advisories/GHSA-8wrc-pj93-f9hp) / CVE-2026-13672, high): attacker-chosen key selects which authorization record is consulted, the user-controlled-key class landing in the SSO federation glue of an appliance.
- **API framework leak:** sensitive information inserted into sent data lets authenticated users read **arbitrary files** ([GHSA-m6v6-g37g-8hc4](https://github.com/advisories/GHSA-m6v6-g37g-8hc4) / CVE-2026-87801). A framework-level leg means the sink is shared by every API handler, not one route.
- **SNMP API CRLF injection** with admin → arbitrary file read/write ([GHSA-mw4g-pg7h-574m](https://github.com/advisories/GHSA-mw4g-pg7h-574m) / CVE-2026-86343): header/control-plane framing injection in a management API.

Operator rules:

1. **Enumerate the API namespace, then re-run the authz matrix per handler.** Pull the handler list from the package manifests or the UI's network traffic, then for each `SYNO.*` method test: unauthenticated, low-priv user, and the wrong-scope user. Authz-missing families always cluster (here: SocketIo/TaskScheduler/Promotion/ACL are four siblings of one registration-sweep miss), so one confirmed miss predicts where to look next.
2. **Framework-layer advisories outroute everything.** When the advisory names the *framework* rather than a product feature (87801 here), expect every handler to inherit the sink and prioritize it above per-route bugs of higher CVSS.

## 4. Your identity provider is an attacker input channel, and so is Synology's support portal

- [GHSA-4927-hwg6-5437](https://github.com/advisories/GHSA-4927-hwg6-5437) / [CVE-2026-81584](https://nvd.nist.gov/vuln/detail/CVE-2026-81584) (high): SQL injection in the **User API** reachable by a remote attacker **who controls a compromised LDAP or Active Directory server**. DSM trusts directory-server *responses* as data; here they become SQL. This is the trust inversion of SSRF: the appliance calls out, so the response parser is an unauthenticated-by-proxy input surface for anyone who can get DSM to bind to *their* directory.
- [GHSA-9gv7-pj6c-vhp7](https://github.com/advisories/GHSA-9gv7-pj6c-vhp7) / [CVE-2026-15201](https://nvd.nist.gov/vuln/detail/CVE-2026-15201) (medium): **improper certificate validation in the Support Form** lets an on-path attacker read arbitrary files and write specific files during support-form submission. The vendor-support upload channel is an outbound fetch with trust nobody audits.

Operator rules:

1. **Audit every directory/SSO/SMTP/NTP endpoint the appliance dials out to as an inbound attack surface.** On red-team engagements where you can influence the configured LDAP/AD endpoint (or already hold DNS/BGP position), returning hostile attribute values tests the same boundary as 81584 without touching user data: watch SQL error shapes, timing, and side-effect artifacts.
2. **Support/telemetry/diagnostic upload paths deserve MITM tests in labs**: cert-validation gaps on vendor-relay uploads turn network position on the appliance's uplink into file read/write.

## 5. File-boundary legs: thumbnails, sharing, extraction

- **thumb symlink leg:** improper link resolution before file access in the thumbnail service, authenticated arbitrary file write ([GHSA-55jj-9737-69vf](https://github.com/advisories/GHSA-55jj-9737-69vf) / CVE-2026-19048). Thumbnail/preview generators follow links at render time to paths the upload path never validated: the validate-at-enqueue vs act-at-execute drift, on a NAS.
- **Sharing API traversal:** restricted-directory escape, authenticated arbitrary file read/write ([GHSA-xjfw-3qw5-345q](https://github.com/advisories/GHSA-xjfw-3qw5-345q) / CVE-2026-18792). Share-link machinery computes paths from user input, the classic share-service boundary.
- **contentextract** read-specific-files traversal ([GHSA-q9vx-5qh7-vxjj](https://github.com/advisories/GHSA-q9vx-5qh7-vxjj) / CVE-2026-74850) and **Media Parser** external file-name/path control → arbitrary file write ([GHSA-gv6r-q4wf-9492](https://github.com/advisories/GHSA-gv6r-q4wf-9492) / CVE-2026-16550): the indexer/parser pipeline honors attacker-influenced filenames from uploaded media.
- **synomount external control of system/config setting** → write specific files ([GHSA-63hr-qc85-g274](https://github.com/advisories/GHSA-63hr-qc85-g274) / CVE-2026-88266), plus three render-path legs (Notification API, DSMNotify, Audio Player: CVE-2026-92379 / CVE-2026-81557 / CVE-2026-13656) where input neutralization failures during web page generation reach file read/write, i.e., the rendering pipeline crosses into filesystem sinks.
- **VPN API authenticated admin OS command injection** ([GHSA-5wm9-4h2h-9xf6](https://github.com/advisories/GHSA-5wm9-4h2h-9xf6) / CVE-2026-75785): the VPN config surface shell-constructs; a post-auth escalation leg to chain behind any foothold with admin-adjacent creds.

Operator rules:

1. **On NAS targets, drive the file pipeline end-to-end with hostile filenames and symlink canaries**: upload with traversal-shaped names, plant in-scope symlinks pointing at out-of-scope canaries, then trigger the *secondary* consumers (thumbnailer, indexer, extractor, preview) rather than the uploader. This wave's thumb/contentextract/MediaParser trio proves the secondary consumers are where the traversal survives.
2. **Share-link surfaces get the traversal battery of their own**, separate from file manager routes: share services re-resolve paths from tokens and names with different code than the main file API.

## Validation checklist (lab or approved windows)

1. Fingerprint DSM branch via per-CVE fix-branch tables and observable side effects; record which advisory band applies.
2. Auth API battery: full SQL grammar + auth-step-missing probes on login/OTP/device-registration parameters, blind-differential evidence only.
3. Sidecar parity matrix: rsync, WebDAV, NFS, SNMP against DSM account policy (password, OTP, IP allowlist) - decision table per service.
4. webapi namespace sweep: unauth / low-priv / wrong-scope per `SYNO.*` handler, prioritizing SocketIo/TaskScheduler/Promotion/ACL/SecurityAdvisor/Credential/SSOAuth siblings.
5. File pipeline: symlink canaries + hostile names through upload → thumbnail → index → extract → share-link.
6. Directory-trust leg only with owned LDAP/AD responder under approved scope; observe SQL error/timing shapes without touching real directory data.

**Related pages:** the forged-original-URI and alternate-path family (Sept 15 header-route page), user-controlled-key authorization drift (Sept 19 WP alternate-surface page and Sept 21 precedence page), validate-at-enqueue extraction drift (July 28 extraction page), sidecar-dashboard standing rule (Oct 27 OpenPanel page), and the Supermicro BMC lights-out appliance methodology (Oct 27 BMC page).
