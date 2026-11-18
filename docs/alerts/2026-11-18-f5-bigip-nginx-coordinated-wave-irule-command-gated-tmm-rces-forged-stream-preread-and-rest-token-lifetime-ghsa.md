# F5 BIG-IP and NGINX wave (22 GHSAs): iRule command-gated TMM RCEs and forgeable stream routing state

**Wave in one line:** F5 shipped a coordinated release where five separate 9.8 unauthenticated TMM RCE advisories are each gated on a *specific iRule command* being present on the virtual server, a sixth leg makes iControl REST token expiry holder-influenceable, a Guest-role iControl SOAP user reaches arbitrary system commands, and the NGINX half adds five memory-corruption legs plus a forgeable `ngx_stream_ssl_preread` variable that steers stream routing and a client-certificate verification bypass on non-default stream servers.

**Signal:** GitHub Security Advisories published the F5 cluster at **2026-11-18T18:31:59Z through 18:32:23Z**, alongside the same-minute Dell PowerStore SDNAS, ClamAV, and Mattermost dumps. GHSA package version fields are empty, resolve fix bands from the F5 K-series advisories for the exact build. None of the wave was in CISA KEV at catalog 2026.11.17 (1782, cveID-set sha 01a4ce0f) at scan time. This is the same composite-config perimeter class as the [September 22 BIG-IP APM + OAuth page](2026-09-22-f5-bigip-apm-access-policy-oauth-profile-unauth-rce-validation-boundary-ghsa.md) and the [October 14 NGINX coordinated wave](2026-10-14-nginx-coordinated-wave-ssi-aio-uaf-map-alias-overflows-http3-injection-mtls-session-forgery-and-ingress-header-relay-ghsa.md); read those first, this page carries the new legs.

## Advisory table (operator-relevant legs)

| GHSA | CVE | CVSS | Boundary |
| --- | --- | --- | --- |
| [GHSA-rw85-pcjm-9g8m](https://github.com/advisories/GHSA-rw85-pcjm-9g8m) | CVE-2026-120285 | 9.8 crit | HTTP profile + iRule containing **`PSC::ip_address`**: undisclosed requests terminate TMM and may yield RCE. Data plane only. |
| [GHSA-9pw6-3vp3-hp57](https://github.com/advisories/GHSA-9pw6-3vp3-hp57) | CVE-2026-116953 | 9.8 crit | iRule containing **`GENERICMESSAGE::route`**: same shape, TMM termination and possible RCE. |
| [GHSA-6rm4-5cx8-4fj5](https://github.com/advisories/GHSA-6rm4-5cx8-4fj5) | CVE-2026-120722 | 9.8 crit | iRule containing **`DNS::scrape`**: same shape. The iRule inspects DNS payloads on the data plane. |
| [GHSA-hmgf-h43p-h8f6](https://github.com/advisories/GHSA-hmgf-h43p-h8f6) | CVE-2026-120292 | 9.8 crit | HTTP profile + iRule using **`MR::message` route** command: same shape. |
| [GHSA-mrc9-fwm3-wvcv](https://github.com/advisories/GHSA-mrc9-fwm3-wvcv) | CVE-2026-121805 | 9.8 crit | iRule containing **`PEM::subscriber`**: same shape; policy enforcement manager path. |
| [GHSA-q3pc-8x94-2vq5](https://github.com/advisories/GHSA-q3pc-8x94-2vq5) | CVE-2026-123637 | 9.8 crit | APM per-request policy with **Client Information agent + Endpoint Security agents** on a virtual server: TMM termination and possible RCE, unauthenticated. |
| [GHSA-5495-4wg7-qj5w](https://github.com/advisories/GHSA-5495-4wg7-qj5w) | CVE-2026-120718 | 8.1 crit | **iControl REST tokens may not expire** in all scenarios; a token holder can extend the token's own expiry lifetime unless the token owner deletes it. Control plane only. |
| [GHSA-c2g7-x7pq-jw5c](https://github.com/advisories/GHSA-c2g7-x7pq-jw5c) | CVE-2026-125274 | 8.8 high | **iControl SOAP user with only Guest access** can inject an unauthorized management request: arbitrary system commands, file create/delete, service disable. Control plane. |
| [GHSA-rmpv-v5m5-rr27](https://github.com/advisories/GHSA-rmpv-v5m5-rr27) | CVE-2026-113425 | 8.1 crit | NGINX configured as **mail proxy**: undisclosed traffic causes worker **use-after-free**; RCE where ASLR is off or bypassed. |
| [GHSA-m4q8-cf44-f42r](https://github.com/advisories/GHSA-m4q8-cf44-f42r) | CVE-2026-123007 | 8.1 crit | NGINX **HTTP/2 flow control window exceeds allowed threshold** → heap buffer overflow, worker segfault, RCE conditional on ASLR. |
| [GHSA-7xxj-p8w5-434q](https://github.com/advisories/GHSA-7xxj-p8w5-434q) | CVE-2026-123633 | 8.1 crit | NGINX HTTP/2 client + proxy to backend: crafted request → worker **UAF when the process runs low on `worker_connections`**. Load state is a precondition. |
| [GHSA-fxx2-rrmx-x4v2](https://github.com/advisories/GHSA-fxx2-rrmx-x4v2) | CVE-2026-121810 | 8.1 crit | NGINX **HTTP/3** worker UAF, unauthenticated. |
| [GHSA-qxf8-26hv-4jh5](https://github.com/advisories/GHSA-qxf8-26hv-4jh5) | CVE-2026-123634 | 8.1 crit | NGINX proxy where the **proxied server name includes variables** and an **SSI or mirror subrequest resolves the same server name** → worker UAF. Config-shape leg. |
| [GHSA-c32q-x8cv-vhfr](https://github.com/advisories/GHSA-c32q-x8cv-vhfr) | CVE-2026-123640 | 5.3 med | **`ngx_stream_ssl_preread_module`**: crafted ClientHello **forges the preread variable values** (`$ssl_preread_server_name` etc.) → bypass stream routing selection; can also negotiate a proxied server out of TLS 1.3. |
| [GHSA-q9wg-m5cc-h828](https://github.com/advisories/GHSA-q9wg-m5cc-h828) | CVE-2026-120967 | 4.8 med | `ssl_verify_client on` in a **non-default stream virtual server**: client certificate verification bypassed. |
| [GHSA-mjqw-rmmf-hgxf](https://github.com/advisories/GHSA-mjqw-rmmf-hgxf) | CVE-2026-118899 | 7.5 high | `listen ... ssl` in `http` block with TLS 1.3: crafted connection → **infinite loop while reading the request body**, worker stops accepting. |
| [GHSA-64w6-c5j7-p636](https://github.com/advisories/GHSA-64w6-c5j7-p636), [GHSA-3c9q-9f29-24m6](https://github.com/advisories/GHSA-3c9q-9f29-24m6), [GHSA-9qvx-w4xq-xpm2](https://github.com/advisories/GHSA-9qvx-w4xq-xpm2), [GHSA-54x3-fg73-rwp8](https://github.com/advisories/GHSA-54x3-fg73-rwp8) | CVE-2026-126822, 126336, 125272, 121812 | 7.5 high | APM TMM-termination DoS cluster: SAML SP (plain and encrypted-assertions), form-based Logon Page per-request policy, and the `tmm.access.policytrace` dbkey (default off). Unauthenticated data plane. |
| [GHSA-cgqq-hx2v-pf8c](https://github.com/advisories/GHSA-cgqq-hx2v-pf8c), [GHSA-39qv-989q-vg33](https://github.com/advisories/GHSA-39qv-989q-vg33) | CVE-2026-125283, 120993 | 5.3 med | NGINX `try_files`+`alias`+map regex capture segfault; abbreviated handshake kill under dynamic certs + `proxy_protocol v2`. |

## Durable operator axes

### 1. The iRule command named in the advisory is the reachability question

Five 9.8 legs (120285, 116953, 120722, 120292, 121805) are each armed only when a virtual server's iRule *contains a specific command*: `PSC::ip_address`, `GENERICMESSAGE::route`, `DNS::scrape`, `MR::message route`, `PEM::subscriber`. This refines the standing composite-config rule from the September 22 page down to **statement granularity inside the traffic-handling script**:

- **Build an iRule-command inventory per virtual server before triaging severity.** On authorized targets read (auth required, read-only) `tmsh list ltm virtual` for profile and `iRules` bindings, then the iRule bodies (`tmsh list ltm rule`, `ifile` sources) and grep for the five command names. One matching vserver is the finding; a vulnerable build with zero matching iRules is an inventory note.
- **Some commands are externally fingerprintable.** An iRule with `DNS::scrape` implies the vserver inspects DNS payloads, so UDP/53-shaped traffic to that VIP gets parsed code running on attacker bytes with no authentication. `GENERICMESSAGE::route` implies L4 routing logic keyed on payload content. Route-level behavioral probes (does the VIP respond to malformed DNS, does payload content change routing) tell you which parser families are live without any config read.
- **DoS-and-maybe-RCE wording means the crash is the safe public oracle.** TMM restart is observable (traffic interruption windows, HA failover events, `/var/log/ltm`). Same worker-restart-as-oracle discipline as the October 14 NGINX page: crash observation only with written scope, payload work stays in a lab BIG-IP.
- **The APM Client Information + Endpoint Security leg (123637) is the per-request-policy twin:** the agent chain is another module-pair intersection invisible to version scans. Check which APM policies include both agents; those VSes carry a 9.8 unauthenticated surface.

### 2. Token expiry that the holder can stretch

5495/120718 states a token **holder** can extend the token's own expiry in some scenarios unless the owner deletes it. Two durable rules:

- **Treat token lifetime as holder-influenced state on every control plane you test.** After obtaining any issued token (yours, on scope), attempt self-extension: re-POST the token object, PUT `timeout`/`expiration` fields, re-token from the token (the TeamCity wave the same day has a mint-from-restricted-token leg too). A 200 response with a changed lifetime is a lifecycle finding even when the base grant is legitimate.
- **The residual-risk framing is 'token theft with shelf life extended indefinitely.'** In reports, pair it with where tokens leak on that product (URLs, logs, Referer, CI config) rather than claiming exposure on its own; F5 scopes it to the control plane, so the management-network boundary is the blast radius.

### 3. Guest is not a capability set

c2g7/125274 turns **any iControl SOAP user with Guest access** into arbitrary system commands, file create/delete, and service disable. Standing rule from the September 19 WP page, applied to appliances: enumerate every management entry point (SOAP `iControl` endpoint here, vs REST) and test it **at the lowest role you can obtain**, because alternate API families frequently lag the primary API's authorization model. On lab/authorized BIG-IPs, provision a Guest user and probe SOAP method families; never issue destructive calls on production.

### 4. NGINX legs continue the October 14 rules, and add stream-plane identity forgeries

- **Transport-state memory corruption:** 123007 (HTTP/2 flow-control window overrun) and 121810 (HTTP/3 UAF) mean the whole framing stack is under audit again; run your h2/h3 suites against in-scope builds and watch for worker-restart signatures. 123633 has a **load precondition** (`worker_connections` pressure): reproduce under connection load in the lab, and note that idle production boxes may not show the behavior, absence of crash is not absence of the leg.
- **Config-shape leg again:** 123634 requires a proxy whose `proxy_pass` server name **contains variables** and an SSI/mirror subrequest resolving the same name. That is an inferable shape: mirror directives and SSI are visible in behavior (duplicated requests to a collector, SSI error strings). Apply the October 14 fingerprint-first method.
- **123640: preread values are attacker-forged routing input.** Forged `$ssl_preread_server_name` steers which stream upstream a connection lands in. New target class: any SNI-based stream routing (multi-tenant TLS passthrough, DB/RDP gateways routing by hostname) where routing depends only on preread variables, send ClientHellos with malformed/extless SNI shapes and map routing decisions; the routing-decision table is the evidence. Also verify the negotiated TLS version downstream does not silently downgrade when the preread was forged (the advisory notes proxied-server TLS 1.3 disagreement).
- **120967: client-cert verification bypass on non-default stream servers** extends the October 14 mTLS-forgery family: verification configured on one server block does not reliably apply to others. Enumerate every stream server block (default and named) and run the no-cert battery against each; per-listener controls need per-listener proof.

## Validation boundaries

- No crafted traffic against production BIG-IP or NGINX without explicit written scope; the five 9.8 legs are crash-class advisories with withheld details, and **no PoC is published**. Lab instances only for any crash/RCE pursuit.
- Config inventory via read-only queries on authorized targets; no writes, no iRules changes, no dbkey toggles.
- Stream-preread and cert-bypass batteries only against in-scope stream listeners you own or are authorized to test, with benign routing canaries (expected upstream marker), never pivoting to internal services.
- Token self-extension tests only with tokens issued to you; delete your own tokens; never touch other users' token objects.
- Guest-role SOAP probes only with a lab-provisioned Guest; never file/service operations on production.

## Report framing

Lead each finding with the config intersection verdict (which iRule command, which APM agent pair, which stream server block), then the build string and vendor advisory band, then the observable effect (restart window, routing decision, lifetime delta). Severity follows the intersection and the traffic inventory behind the vserver, per the September 22 framing. For 5495/120718 include the request/response shape that stretched a lab token's expiry and state that it applies to stolen-token persistence. Keep management-network topology and vserver inventories in the client report only.
