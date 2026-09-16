---
title: Pepperl+Fuchs ICE IODD web UI cluster and Arista EOS gRPC/gNSI management-plane boundaries
---

# Pepperl+Fuchs ICE IODD web UI cluster and Arista EOS gRPC/gNSI management-plane boundaries

A September 16 late wave (GitHub `unreviewed`, published 2026-09-16T09:30Z) delivers two complete appliance-management-plane audits plus one config-export single:

- **Pepperl+Fuchs ICE2-\*/ICE3-\*** industrial Ethernet converter web UI: a 20-CVE cluster spanning unauthenticated authentication bypass, unauthenticated root RCE via IODD file upload, path traversal to SSH private keys, local file inclusion, and roughly ten distinct low-privilege command-injection endpoints (VDE-2026-014/027/028).
- **Arista EOS** gRPC management plane (gNMI/gNSI/OpenConfig): authenticated root code execution via crafted Certz Rotate and gNMI requests, Pathz policy enforcement drift when group and user rules collide, AAA wrong-method-list authorization, Credentialz account-property tampering, silent authz policy-rotation race, and sensitive request/response logging.
- **XikeStor Layer3 switches**: missing authentication on configuration download exposing operating passwords.

These are durable because both clusters are reusable audit templates: **industrial-appliance web UIs with a file "viewer/uploader" feature** and **switch management planes moving from CLI to gRPC**, where every gRPC service becomes a new authz surface with its own rule engine.

Sources (GitHub records; vendor primary for the Pepperl+Fuchs cluster is the certvde bundle):

- Auth bypass `_account_log`: [GHSA-pvrf-wj35-pxjx / CVE-2026-27546](https://github.com/advisories/GHSA-pvrf-wj35-pxjx) (CVSS 9.8, CWE-288 alternate path/channel)
- Unauthenticated IODD upload → root script, survives reboot: [GHSA-9q7j-q2f8-2hh2 / CVE-2026-27565](https://github.com/advisories/GHSA-9q7j-q2f8-2hh2) (CVSS 9.8, CWE-78)
- Path traversal in `/index.php/view_uploaded_iodd_file` → SSH server private keys: [GHSA-64xx-g8pm-3j7r / CVE-2026-27557](https://github.com/advisories/GHSA-64xx-g8pm-3j7r)
- Command injection `/api/iodd/config`: [GHSA-w883-x4xv-cvj7 / CVE-2026-27561](https://github.com/advisories/GHSA-w883-x4xv-cvj7); endpoint variants: [GHSA-3237-x8jg-4g4c / CVE-2026-27547](https://github.com/advisories/GHSA-3237-x8jg-4g4c) (`/index.php/ajax/get_iodd_menu_info`), [GHSA-7qf9-p8pv-fm5w / CVE-2026-27548](https://github.com/advisories/GHSA-7qf9-p8pv-fm5w) (`get_iodd_port_info`), [GHSA-pr57-h748-gjmg / CVE-2026-27549](https://github.com/advisories/GHSA-pr57-h748-gjmg) (`ajax_remove_uploaded_iodd_files`), [GHSA-23xw-rw6g-gx4m / CVE-2026-27558](https://github.com/advisories/GHSA-23xw-rw6g-gx4m), [GHSA-c374-wf66-wjj4 / CVE-2026-27550](https://github.com/advisories/GHSA-c374-wf66-wjj4), [GHSA-rj9q-c22c-qhxv / CVE-2026-27551](https://github.com/advisories/GHSA-rj9q-c22c-qhxv), [GHSA-jg94-p967-pq26 / CVE-2026-27559](https://github.com/advisories/GHSA-jg94-p967-pq26), [GHSA-5vwp-gm8f-c5p6 / CVE-2026-27560](https://github.com/advisories/GHSA-5vwp-gm8f-c5p6), [GHSA-2wvv-pq2h-2gcr / CVE-2026-27562](https://github.com/advisories/GHSA-2wvv-pq2h-2gcr), [GHSA-64h9-m45x-fp44 / CVE-2026-27563](https://github.com/advisories/GHSA-64h9-m45x-fp44), [GHSA-cr25-g7wh-c7vg / CVE-2026-27564](https://github.com/advisories/GHSA-cr25-g7wh-c7vg)
- Improper authorization on upload endpoint: [GHSA-85mr-mj2w-73j9 / CVE-2026-27552](https://github.com/advisories/GHSA-85mr-mj2w-73j9); local file inclusion: [GHSA-fmvr-8vv5-53j5 / CVE-2026-27556](https://github.com/advisories/GHSA-fmvr-8vv5-53j5), [GHSA-56f4-q6w3-cxmv / CVE-2026-27555](https://github.com/advisories/GHSA-56f4-q6w3-cxmv); schema-path manipulation: [GHSA-8vhg-m252-v9wj / CVE-2026-27553](https://github.com/advisories/GHSA-8vhg-m252-v9wj); command injection via schema path: [GHSA-426f-m78p-m3jc / CVE-2026-27554](https://github.com/advisories/GHSA-426f-m78p-m3jc)
- certvde primary bundle: [VDE-2026-014](https://www.certvde.com/en/advisories/VDE-2026-014) (affected: ICE2-\* and ICE3-\* firmware < 1.7.4)
- Arista gNSI Certz Rotate → root command injection (CVSS 9.1): [GHSA-669f-m4vm-pcm2 / CVE-2026-73447](https://github.com/advisories/GHSA-669f-m4vm-pcm2); gNMI crafted request → root code execution: [GHSA-hpwc-p8j3-f332 / CVE-2026-73464](https://github.com/advisories/GHSA-hpwc-p8j3-f332)
- Pathz group-rule vs user-rule enforcement drift: [GHSA-hhmm-qmjm-g2hp / CVE-2026-73439](https://github.com/advisories/GHSA-hhmm-qmjm-g2hp); AAA wrong privilege method list on gRPC OpenConfig: [GHSA-cppj-w9qw-f23c / CVE-2026-73461](https://github.com/advisories/GHSA-cppj-w9qw-f23c) (critical)
- gNSI Credentialz account-property tampering → unintended privilege: [GHSA-9qm5-xc58-9xgf / CVE-2026-73454](https://github.com/advisories/GHSA-9qm5-xc58-9xgf); Authz policy-rotation race keeps revoked access: [GHSA-v538-9xwx-vp3j / CVE-2026-73463](https://github.com/advisories/GHSA-v538-9xwx-vp3j)
- OpenConfig/gNMI/RESTCONF/NETCONF secrets logged locally and to accounting servers: [GHSA-8wh7-8xq3-25wg / CVE-2026-2380](https://github.com/advisories/GHSA-8wh7-8xq3-25wg)
- XikeStor unauthenticated configuration download: [GHSA-jxpm-cmg2-h9hw / CVE-2026-88263](https://github.com/advisories/GHSA-jxpm-cmg2-h9hw)

!!! warning "Authorized validation only"
    Lab appliances only, or explicit written authorization for the specific device. Do not create privileged accounts, read SSH private keys or passwords, upload firmware-affecting files, alter running configuration, or execute commands on production switches. All command-injection proofs below stop at a denied-process recorder or an inert marker.

## Pepperl+Fuchs ICE: the file-upload feature is the unauthenticated RCE surface

The cluster shape matters more than any single CVE. The same web UI has:

1. an **alternate authentication channel** (`_account_log`) that bypasses login entirely even when accounts are properly configured (CWE-288 — a *different path reaches the same handler*);
2. an **IODD upload/view feature** where uploaded files become script content (`view_uploaded_iodd_file` reads back arbitrary paths, upload executes content as root, persistence survives reboot);
3. **~10 independently injected endpoints** that interpolate caller fields into OS commands once you hold any user/operator credential; and
4. **schema-path parameters** that cross into both LFI and command construction.

### Replayable audit workflow (authorized lab device, firmware < 1.7.4 baseline)

1. **Fingerprint before touching anything.** Confirm exact model (ICE2-8IOL-\*, ICE3-8IOL-\*, etc.) and firmware against the certvde affected list. Web UI banner alone is not enough; the fix boundary is firmware 1.7.4.
2. **Alternate-path auth matrix.** Enumerate every route family (public, `_account_log`-style logging/account functions, AJAX endpoints under `/index.php/`) and compare unauthenticated acceptance against the login gate. The positive shape is *a function-name or route that authenticates by presence-of-session-write rather than credential check*. Record route → auth-decision tuples; do not retain admin sessions.
3. **Upload/view round-trip boundary.** Upload only an inert IODD-shaped XML canary carrying a unique marker, then exercise the viewer endpoint with own-file, sibling-path, encoded traversal, and absolute-path variants against a read recorder. The path-traversal proof is *canonical target outside the upload root*, not key extraction — never read the real SSH host key; prove reachability with a synthetic path shape and stop.
4. **Command-injection sink evidence.** For each affected endpoint family (`ajax/get_iodd_*`, `attached_devices_tab/*`, `/api/iodd/config`), send one benign field value plus one inert shell-metacharacter marker, and observe only timing/error/response deltas or (in a patched-handler lab) a denied-exec recorder. Never run `id`-style payloads against the appliance; a denied `execve` trace beats a live root shell.
5. **Persistence question is separate.** "Script survives reboot" is an impact claim for the vendor fix, not something to prove on a live device by rebooting it.

Generalize: any industrial appliance exposing a *file viewer* for a feature-specific format (IODD, EDS, GSDML, CITS) should be tested as (a) an unauthenticated write sink, (b) a path-traversal read sink over the same directory, and (c) an eventual code-loading sink. Feature-named routes (`*_iodd_*`) frequently skip the auth middleware that protects core routes.

## Arista EOS: gRPC management services are fresh authorization surfaces with their own rule engines

Arista's wave shows what happens when a switch's security model (AAA method lists, privilege levels, ACL-style path policies) is re-implemented per gRPC service: each service reimplements enforcement, and each implementation has its own drift class.

| Advisory | gRPC service | Enforcement edge that breaks |
| --- | --- | --- |
| [GHSA-669f-m4vm-pcm2](https://github.com/advisories/GHSA-669f-m4vm-pcm2) | gNSI Certz (and Bootz) | Rotate-certificate request content reaches OS command construction → root |
| [GHSA-hpwc-p8j3-f332](https://github.com/advisories/GHSA-hpwc-p8j3-f332) | gNMI | Crafted request → arbitrary code as root (authenticated gNMI client = root) |
| [GHSA-hhmm-qmjm-g2hp](https://github.com/advisories/GHSA-hhmm-qmjm-g2hp) | gNSI Pathz | Group rule + user rule on same path → policy not enforced; read/write of restricted paths |
| [GHSA-cppj-w9qw-f23c](https://github.com/advisories/GHSA-cppj-w9qw-f23c) | OpenConfig over gRPC + AAA | Wrong privilege level → wrong AAA method list; NETCONF (non-gRPC) unaffected — protocol-family drift |
| [GHSA-9qm5-xc58-9xgf](https://github.com/advisories/GHSA-9qm5-xc58-9xgf) | gNSI Credentialz | Crafted request mutates another account's properties toward elevated access |
| [GHSA-v538-9xwx-vp3j](https://github.com/advisories/GHSA-v538-9xwx-vp3j) | gNSI Authz (multi-transport) | Policy rotation race fails silently → revoked principal keeps access |
| [GHSA-8wh7-8xq3-25wg](https://github.com/advisories/GHSA-8wh7-8xq3-25wg) | gNMI/gNSI/RESTCONF/NETCONF | Secrets (CLI `username ... secret`, TACACS keys) logged locally and to accounting servers |

### Operator workflow for a network pentest

1. **Enumerate gRPC surface separately from the CLI/NETCONF surface.** `grpcurl` reflection (or vendor SDK) against the management VRF; compare which services (gNMI, gNSI Authz/Pathz/Certz/Credentialz/Bootz) are reachable versus what the CLI ACL claims to restrict. The AAA record proves the two families can enforce *different* policy for the same user — never infer gRPC authz from a NETCONF positive control.
2. **Rule-collision testing on Pathz-style policies.** With two lab users and one restricted path, construct group-rule allow + user-rule deny (and the reverse) for the same path, then verify enforcement for *each* principal on *both* rule-present and single-rule configurations. A deny that only works when its counterpart is absent is the bug shape.
3. **Rotation/revoke-state testing.** After any access-revocation change, re-test the *old* credential and a freshly issued one against each configured transport; the race class fails silently, so only positive re-test evidence settles it.
4. **Certz/Rotate and Bootz requests are command-construction candidates.** Treat every "rotate/install certificate" gRPC field like a config-push parameter: in an authorized lab, one benign serial/CN value plus one inert metacharacter variant against a denied-exec recorder, nothing more.
5. **Log-bleed is passive evidence, not a PoC.** Reviewing device-local and accounting-server logs for `username ... secret` material on an authorized engagement is legitimate; do not push fresh secrets through the management plane just to see them echoed.

## XikeStor: config download without authentication

Missing authentication on configuration export yields operating passwords directly. In authorized scope, the check is one request to the config-download endpoint with a diff against the authenticated control — no need to open the returned file on disk if a length/hash comparison plus vendor confirmation suffices. Generalize to any SOHO/industrial switch web UI: request every `*.cfg`, `export`, `download`-shaped route unauthenticated before deeper testing.

## Adjacent records processed without publication

- Linux kernel stable wave (18 GHSA mirror records: perf UAF, ksmbd/ext4/ntfs3/isofs OOB, xfrm6, vxlan vnifilter, nf-sched actions, Bluetooth SCO, KVM arm64, vfio, SUNRPC, rmnet, gtp): kernel memory-safety hygiene without a replayable operator workflow for this wiki — tracked, not published.
- NLnet Labs Unbound DNSSEC/ReTrap algorithmic-complexity and UAF set ([GHSA-qwgf-hj58-8c2w](https://github.com/advisories/GHSA-qwgf-hj58-8c2w) and siblings): resolver DoS/research framing, no operator offense beyond availability; tracked.
- QND/QNDMC named-pipe access control and hardcoded key (local, single-workstation), WTV676/WTV776 IP-camera web interface singles, Arista EOS IS-IS/VRRP/DHCP/MLAG protocol DoS set: single-product availability or local-privesc hygiene without a new reusable axis.
- Qt QDomDocument XXE DoS (parser-only crash), ZenHive mpp payment-plug cache/control items and Airflow/GitLab/WordPress/Octopus items promoted on their own pages this run.

## Reporting notes

- Separate the four edges on the Pepperl+Fuchs cluster: alternate-path auth bypass, upload-to-execution, viewer path traversal, endpoint command injection — each is its own CVE and should be its own finding with its own route/parameter evidence.
- On Arista, state which gRPC service and which policy configuration produced the drift; the AAA record explicitly does not apply to NETCONF, and the Pathz record requires both a group rule and a user rule present.
- Keep firmware/version and configuration state (which gNSI services configured, AAA method lists) in every finding; all Arista records require an authenticated starting position, so pre-auth claims are wrong.
- Bounded impact language: path-traversal proof by canonical-path recorder ≠ extracted keys; denied-exec recorder ≠ code execution; log review finding ≠ secret theft.
