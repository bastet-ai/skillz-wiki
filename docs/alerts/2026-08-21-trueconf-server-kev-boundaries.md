---
title: TrueConf server 4307/TCP authority and sandbox-breakout validation (KEV)
---

# TrueConf server 4307/TCP authority and sandbox-breakout validation (KEV)

CISA added two TrueConf Server records to the Known Exploited Vulnerabilities catalog on August 20, 2026. Both sit on the same externally reachable service port and chain into the same outcome class:

- [CVE-2026-72529](https://nvd.nist.gov/vuln/detail/CVE-2026-72529) (KEV due 2026-08-23): **missing authentication for a critical function**, a remote unauthorized attacker with network access via **port 4307/TCP** can execute an arbitrary script **by calling an undocumented function** (CWE-306; KLCERT CVSS vector AV:N/AC:L/PR:N/UI:N).
- [CVE-2026-72530](https://nvd.nist.gov/vuln/detail/CVE-2026-72530) (KEV due 2026-09-03): **code injection**, a crafted script on that same route can **break out of the isolated execution environment and execute arbitrary code on the host system** (CWE-94; KLCERT CVSS vector AV:N/AC:H/PR:N/UI:N/S:C).

The durable operator pattern is a **single service port exposing an unauthenticated script-accepting surface that runs inside an isolation boundary**: establish whether the port is reachable at all, what function is unauthenticated behind it, and whether the isolation layer is the only thing standing between that function and the host. Kaspersky ICS-CERT [KLCERT-26-058](https://ics-cert.kaspersky.com/advisories/2026/08/11/trueconf-server-breakout-from-isolated-environment/) (published 2026-08-07) identifies in-the-wild exploitation by the **Head Mare APT group** delivering **PhantomCore** malware to conference participants, and provides IoCs to correlate against.

Affected product lines per the KLCERT advisory (TrueConf Server for Windows and Linux): all versions before 5.3, 5.3.x before 5.3.9, 5.4.x before 5.4.9, 5.5.x before 5.5.5. Fixed: 5.3.9 / 5.4.9 / 5.5.5.

Primary records:

- [KLCERT-26-058: TrueConf Server. Breakout from isolated environment](https://ics-cert.kaspersky.com/advisories/2026/08/11/trueconf-server-breakout-from-isolated-environment/)
- [KLCERT-26-057: TrueConf Server. Missing authentication for critical function](https://ics-cert.kaspersky.com/advisories/2026-08-11/trueconf-server-missing-authentication-for-critical-function/)
- [TrueConf security fixes, updates, and advisories (vendor)](https://trueconf.com/blog/news/security-fixes-updates-and-advisories)
- [NVD: CVE-2026-72530](https://nvd.nist.gov/vuln/detail/CVE-2026-72530) / [CVE-2026-72529](https://nvd.nist.gov/vuln/detail/CVE-2026-72529)
- [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

!!! warning "Recon and version evidence first; no breakout payloads on live systems"
    Do not send crafted script payloads to an operational TrueConf server. On customer-approved production surfaces, stop at port reachability, service identity, version evidence, and ownership. Exercise the script-accepting function and the isolation layer only in a disposable TrueConf Server lab where the execution sink is patched to log the received script and deny host-level process creation, file access, and outbound network access.

## 1. Establish scope and product identity

TrueConf Server is a conferencing appliance that frequently fronts meeting rooms, contact centers, and ICS-adjacent control spaces. Record:

| Field | Evidence |
| --- | --- |
| authority | IP/hostname, whether 4307/TCP is directly reachable or sits behind a load balancer, reverse proxy, or firewall policy |
| version | UI version banner, `trueconfd` package metadata, or owner-supplied build; compare against 5.3.9 / 5.4.9 / 5.5.5 per product line |
| OS variant | Windows vs Linux Server, the breakout mechanism and host context differ |
| network position | internet-facing, DMZ, VPN-facing, or internal; whether other TrueConf ports (signaling, media, web UI) are open |
| in-use state | active conferences, participant counts, whether the instance participates in federated calls |
| approved depth | passive/version only, 4307 reachability check, or lab sink instrumentation |

Do not infer TrueConf from a generic TCP banner. Preserve at least two product signals: an owner-confirmed asset plus TrueConf-specific behavior on the service port, web UI artifacts, or package metadata. The April 2026 TrueConf **Client** KEV record (CVE-2026-3502, client-side code download without integrity check) is a distinct boundary, do not merge client supply-chain findings into this server-side 4307 record.

## 2. 4307/TCP surface mapping

The public record identifies port 4307/TCP as the network access path for both unauthenticated script execution and the isolation breakout, with the script function reached **by calling an undocumented function** on the service protocol (KLCERT-26-057). Derive the actual pipeline from approved sources:

1. owner-supplied service configuration showing which function is exposed on 4307 and which authentication (if any) is expected;
2. authorized port/service inventory;
3. lab capture of the protocol on 4307 with an inert client;
4. source/patch review for the exact deployed branch.

Record which request shape reaches the unauthenticated script function, whether any authentication gate is expected in front of it, and where the isolation boundary sits between that function and host execution. Redact credentials, session material, and conference content. Do not replay captured production conference traffic.

The map should look like:

```text
remote peer
  -> TrueConf service port 4307/TCP
  -> script-accepting function (no authentication, CWE-306)
  -> isolated execution environment
  -> breakout -> host code execution (CWE-94)
```

## 3. Route-reachability matrix

Use protocol-inert controls against each approved authority:

| Case | Expected evidence |
| --- | --- |
| 4307/TCP closed or filtered | no service, or firewall drop |
| 4307/TCP open | service responds; record banner/protocol behavior |
| unauthenticated request to the script function | accepted or rejected per expected gate; record whether a gate exists at all |
| lab deployment, fixed version | same route, gate or validation present; no isolation breakout |

Capture status/response behavior, banners, and any owner-confirmed function-side artifacts (redacted). One control per approved authority establishes reachability; avoid high-rate scanning of the service port.

## 4. Instrument a denied execution sink in a disposable lab

Only when the assessment authorizes exploit-path validation: clone the affected architecture into an isolated lab with no production conferences, accounts, or credentials, and no outbound network access. Patch or hook the script-accepting function and the isolation boundary to log:

- the received script content (hash it; do not store secrets);
- which isolation layer processed it (sandbox/container/sandboxed interpreter);
- the host context that would run a breakout;
- a random inert marker.

The fixture must deny host process execution, filesystem writes, and egress. Generate the marker locally; do not use a public exploit sample or the PhantomCore delivery chain.

Run affected and fixed builds (5.3.9 / 5.4.9 / 5.5.5) with the same recorder and controls. A bounded positive is:

```text
unauthenticated synthetic request on 4307
  -> accepted by script-accepting function
  -> recorded at isolation layer
  -> host-execution recorder receives marker on affected build
  -> fixed build rejects before that recorder
```

That proves the unauthenticated script boundary and the isolation-breakout path without execution. If the affected build rejects before the recorder, do not claim host code execution based on the KEV entry alone.

## 5. In-the-wild context and IoC correlation

The KLCERT advisory reports Head Mare APT exploitation delivering PhantomCore to conference participants and publishes IoCs. For an authorized engagement:

- correlate owner-supplied telemetry against the published IoCs (process names, file paths, network indicators) without exfiltrating them into the report;
- note the attack shape: unauthenticated script execution on 4307, breakout, then delivery to conference participants, this means **conference participants' endpoints are the downstream blast radius**, not just the server;
- record whether any participant-side compromise indicators exist on owner-approved systems, with all identifiers redacted.

## 6. Separate route exposure from application impact

Report the strongest observed boundary and no more:

| Evidence | Supported claim |
| --- | --- |
| version below 5.3.9/5.4.9/5.5.5 only | potentially affected deployment |
| 4307/TCP reachable | exposed conferencing-service surface |
| unauthenticated script function accepts input | unauthenticated script-execution boundary |
| lab isolation recorder receives marker on affected build | isolation-breakout path proven |
| KEV status plus KLCERT IoC | active in-the-wild exploitation context, not local compromise proof |

Do not claim host compromise, conference access, or participant-endpoint compromise unless separately proven under explicit authorization.

## Evidence bundle

```text
TrueConf authority and deployment class:
Version source and product line (5.3.x / 5.4.x / 5.5.x):
4307/TCP reachability evidence:
Unauthenticated script-function control response (hash):
Lab affected-build sink recorder result:
Lab fixed-build sink recorder result:
Denied sink list:
IoC correlation result (redacted):
Observed claim:
Excluded stronger claims:
```

Keep credentials, conference content, and participant identifiers out of screenshots and reports. Hash received scripts where full content is unnecessary, and include the exact lab build/image digest so the sink result can be replayed.

## Reviewed but not promoted here

- The CVE-2026-3502 TrueConf **client** record (download of code without integrity check) remains on its own [April 2026 page](2026-04-02-trueconf-client-code-download-without-integrity-check-cve-2026-3502.md); it is a different boundary (client update channel, not the 4307 server surface) and should not be merged into this validation workflow.
