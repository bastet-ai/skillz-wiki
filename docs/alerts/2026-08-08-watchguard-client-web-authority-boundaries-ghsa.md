---
title: WatchGuard client and WebUI authority boundaries
---

# WatchGuard client and WebUI authority boundaries

A WatchGuard advisory update wave exposes three reusable operator seams: a low-privilege Windows principal reaching a privileged command path, non-default installation directories granting write authority over files later consumed as `SYSTEM`, and an unauthenticated `Host` value crossing into trusted WebUI responses or cache identity.

Sources:

- Mobile VPN with SSL Client local privilege escalation: [GHSA-m27x-m5c5-4g53 / CVE-2025-1910](https://github.com/advisories/GHSA-m27x-m5c5-4g53) and [WGSA-2025-00008](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00008);
- Mobile VPN with SSL Client non-default-directory permissions: [GHSA-wwp5-7982-8x96 / CVE-2025-2781](https://github.com/advisories/GHSA-wwp5-7982-8x96) and [WGSA-2025-00004](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00004);
- Terminal Services Agent non-default-directory permissions: [GHSA-r5wr-v3gv-93m3 / CVE-2025-2782](https://github.com/advisories/GHSA-r5wr-v3gv-93m3) and [WGSA-2025-00005](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00005); and
- Fireware OS WebUI `Host` handling: [GHSA-4h8g-6mc6-vxxj / CVE-2025-0178](https://github.com/advisories/GHSA-4h8g-6mc6-vxxj) and [WGSA-2025-00003](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00003).

The GitHub records were unreviewed at scan time. The vendor advisories establish the affected/fixed ranges and high-level impact, but do not disclose the exact command field, privileged consumer, or WebUI response sink. Treat those details as hypotheses to establish in a disposable lab, not as confirmed exploit mechanics.

!!! warning "Disposable clients, appliances, and denied sinks only"
    Use snapshots, synthetic local users, empty installation roots, inert marker files, patched process/service recorders, owned hostnames, and script-disabled browser fixtures. Never replace signed binaries or DLLs, start a payload as `SYSTEM`, disrupt a user's VPN, poison a shared cache, redirect a real administrator, inject active JavaScript, or test an operational firewall management plane.

## 1. Preserve the authority chain

For each candidate path, capture the full transition rather than stopping at a writable directory or reflected string:

```text
principal and product/version
-> attacker-controlled field, path, or header
-> parser and canonical representation
-> authorization or trust decision
-> privileged process, SYSTEM file consumer, response serializer, or cache key
-> denied synthetic sink
```

Require an affected build, the vendor-fixed build, and a negative control. A version banner, permissive ACL, reflected hostname, or process error alone is not proof of the final authority edge.

## 2. Mobile VPN: discover the low-privilege-to-command boundary

CVE-2025-1910 states that a locally authenticated non-administrator can reach `NT AUTHORITY\\SYSTEM`; its GitHub record maps the issue to command injection, but the public summary does not identify the input or subprocess. Do not guess a production payload.

### Prerequisites

- isolated Windows VM snapshots with Mobile VPN with SSL Client 12.11.2 and fixed 12.11.3;
- one local standard user and one setup-only administrator;
- no live VPN profile, credentials, routes, or corporate endpoint;
- Process Monitor or ETW process telemetry; and
- a patched/contained process-creation recorder that denies child execution.

### Workflow

1. Install each build identically and inventory every standard-user-reachable UI action, URI handler, service IPC endpoint, scheduled task, repair/update helper, log/diagnostic export, and configuration field.
2. Capture the standard user's token, integrity level, groups, filesystem rights, and the identity of every service/helper receiving the request.
3. Exercise each surface first with an alphanumeric marker. Record IPC fields and any eventual process image, parent, token, application name, command line, environment, and working directory.
4. Only after a field is proven to reach command construction, replay inert grammar-shaped markers against the denied process recorder. Compare spaces, quoting, backslashes, option-like prefixes, duplicate fields, and empty values. Do not include shell operators or executable payloads.
5. Repeat as administrator, with the privileged service stopped, on 12.11.3, and with the same marker sent through an unrelated field.

A bounded positive is **standard-user-controlled field -> privileged component -> command tokens differ from the intended single argument -> denied process sink runs under the `SYSTEM` token**. If the exact field-to-command transition cannot be established, report only vendor-confirmed exposure and version evidence; do not claim reproduced command injection.

## 3. Non-default installation roots: join ACL reachability to a SYSTEM consumer

CVE-2025-2781 and CVE-2025-2782 apply only when the respective Windows client or agent is installed in a non-default directory. This is a useful review heuristic: installer-selected paths may inherit parent permissions that are broader than those assumed by a privileged service.

### Read-only ACL inventory

Run from a standard-user shell in a disposable VM:

```powershell
$root = 'C:\LabApps\WatchGuard'
whoami /all
icacls $root
icacls "$root\*" /t /c
Get-Acl $root | Format-List Owner,AccessToString
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -like "$root*" } |
  Select-Object Name,StartName,State,PathName
```

If Sysinternals AccessChk is already available from a trusted lab image, use it only for read-only effective-access evidence:

```powershell
accesschk.exe -accepteula -w -s "$root"
```

Record explicit versus inherited ACEs and resolve groups to the test principal. Pay particular attention to `Write`, `Modify`, delete-child, ownership, and ACL-change rights on executables, DLL search directories, service configuration, scripts, plugins, update staging, and files renamed into place.

### Final-consumer proof

1. Compare a default installation and a deliberately chosen non-default root whose parent grants ordinary users write access.
2. As the standard user, create and delete only a new random text marker in a dedicated empty subdirectory. Do not alter any installed file.
3. Trace service start, update, repair, diagnostics, and normal agent operation to identify files the privileged component opens from the installation tree.
4. Build a table joining the standard user's effective write/delete/rename authority to each privileged consumer's canonical path and requested operation.
5. Where final execution proof is required, reproduce the same ACL and load sequence in a purpose-built service harness that records the selected marker but refuses library, script, or process execution. Do not substitute a DLL, binary, configuration file, or junction in the actual product tree.
6. Repeat on Mobile VPN 12.11.2 and Terminal Services Agent 12.11.2, the vendor-fixed releases for these records.

The positive is **ordinary user can replace or redirect a specific path -> the real privileged component selects that same canonical path -> fixed build removes either write authority or privileged consumption**. A writable parent alone is an exposure clue, not privilege-escalation proof. Record the installed path and inheritance state because a default-path installation is a required negative control.

## 4. Fireware WebUI: separate `Host` reflection, navigation, script, and cache effects

CVE-2025-0178 says a network-reachable attacker can manipulate the WebUI `Host` value, with vendor-listed redirect, cache-poisoning, or JavaScript-response impact. Those are separate sinks and need separate evidence.

Use only an isolated affected Firebox or vendor lab, an owned canary hostname, a single-user browser profile, and a private test proxy/cache. Send requests manually at low rate:

```http
GET / HTTP/1.1
Host: canary.example.test
Connection: close
```

Build a matrix covering the expected management authority, owned alternate hostname, host plus alternate port, case, trailing dot, absolute-form request target, and,only if the lab proxy normally supplies them,single `Forwarded` or `X-Forwarded-Host` controls. Do not use CR/LF, ambiguous duplicate headers, third-party domains, or production caches.

For every row capture:

- TLS SNI, TCP destination, raw request target, `Host`, and proxy-added forwarding headers;
- status and `Location`;
- absolute URLs in HTML, scripts, API/bootstrap data, password-reset or login flows;
- CSP/reporting/resource origins;
- private-cache key and stored response metadata; and
- detached, script-disabled DOM insertion location for a harmless hostname marker.

Classify the result precisely:

1. **reflection only**, the marker appears in inert text;
2. **navigation authority**, an absolute `Location` or trusted link selects the owned hostname;
3. **script-context authority**, the marker reaches an executable JavaScript/HTML context, proven only with a harmless DOM marker in a script-disabled fixture; or
4. **cache-key mismatch**, two host variants share a cache object and a second synthetic client receives the first marker.

Do not call reflection XSS, a changed `Location` cache poisoning, or one cache entry cross-user impact. The strongest bounded proof is the exact source-to-sink transition plus an affected-versus-fixed decision table.

## Reporting checklist

- [ ] Exact product, build, installation path, role, and service identity are captured.
- [ ] Publicly undisclosed command fields and consumers are labeled as lab-derived or still unknown.
- [ ] ACL evidence is joined to a specific privileged canonical-path consumer.
- [ ] Process creation and privileged file loads remain denied or are reproduced with inert harnesses.
- [ ] `Host` reflection, navigation, script context, and cache identity are reported separately.
- [ ] Default-path, low-privilege, fixed-build, and clean-host controls are included.
- [ ] No VPN credentials, live routes, firewall configuration, active script, or reusable elevation payload appears in evidence.
