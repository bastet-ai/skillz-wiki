---
title: CHARX EV charging controller service, backend, firmware, and privilege boundaries
---

# CHARX EV charging controller service, backend, firmware, and privilege boundaries

A July 30 Phoenix Contact advisory yields a reusable authorized-assessment workflow for EV charging control planes. The affected CHARX SEC-3xxx firmware exposes several distinct boundaries: externally reachable OCPP Agent, JupiCore, MQTT, and optional Modbus services; an OCPP backend treated as a trusted command source; update material accepted without cryptographic authenticity; and low-privilege local identities crossing into root-owned configuration scripts.

Primary source:

- [CERT@VDE VDE-2026-008: Phoenix Contact CHARX SEC-3xxx firmware](https://www.certvde.com/en/advisories/VDE-2026-008)

Representative GitHub records:

- [GHSA-4mmh-4692-xw3f / CVE-2026-7849: system-configuration command injection](https://github.com/advisories/GHSA-4mmh-4692-xw3f)
- [GHSA-hj6x-rh93-r6v7 / CVE-2026-44108: shutdown firewall ordering](https://github.com/advisories/GHSA-hj6x-rh93-r6v7)
- [GHSA-fvfc-m52v-j2p2 / CVE-2026-44104: CRC32-only basemodule firmware validation](https://github.com/advisories/GHSA-fvfc-m52v-j2p2)
- [GHSA-xjm9-rr2c-vpq2 / CVE-2026-44101: unauthenticated OCPP Agent reconfiguration](https://github.com/advisories/GHSA-xjm9-rr2c-vpq2)
- [GHSA-9h9r-3q9w-h7vj / CVE-2026-44090: unauthenticated MQTT broker](https://github.com/advisories/GHSA-9h9r-3q9w-h7vj)
- [GHSA-382g-wcph-26j3 / CVE-2026-44100: unauthenticated JupiCore reconfiguration](https://github.com/advisories/GHSA-382g-wcph-26j3)
- [GHSA-c6hj-8gx4-32qh / CVE-2026-44098: OCPP-backend command injection](https://github.com/advisories/GHSA-c6hj-8gx4-32qh)
- [GHSA-jp46-h3g9-gpp8 / CVE-2026-44103: unverified internal-module firmware](https://github.com/advisories/GHSA-jp46-h3g9-gpp8)
- [GHSA-84gq-hw46-3cvp / CVE-2026-44107: unauthenticated Modbus reboot function](https://github.com/advisories/GHSA-84gq-hw46-3cvp)

The GitHub records were unreviewed when this page was written. CERT@VDE identifies CHARX SEC-3000, SEC-3050, SEC-3100, and SEC-3150 firmware earlier than 1.9.1 as affected. It says firmware 1.9.1 addresses the issues but will be available no later than August 12, 2026; verify actual model-specific availability instead of assuming that the fixed image is already downloadable.

!!! warning "Owned lab or explicitly authorized charger only"
    Charging infrastructure can affect vehicles, billing, physical availability, and industrial networks. Use a disconnected bench controller, vendor test environment, or customer-approved maintenance window. Keep contactors and power outputs disabled. Never reconfigure a production OCPP backend, publish to a live broker, reboot an in-service charger, upload modified firmware, expose internal services during shutdown, collect charging identifiers, or execute commands on a controller.

## Model the control plane before testing

Do not treat the advisory as one unauthenticated-RCE claim. Build a matrix of separately testable edges:

| Boundary | Attacker-controlled representation | Required authority | Safe evidence |
| --- | --- | --- | --- |
| Network exposure | destination address, port, protocol handshake | approved management segment and authenticated principal | SYN/handshake plus service identity |
| OCPP Agent | backend URL or connection settings | authenticated operator and allowlisted backend | owned callback connection with fake station ID |
| JupiCore | charging-point configuration and update request | authenticated maintenance role | marker-only config diff or no-op handler count |
| MQTT | topic, client ID, and message body | authenticated client plus topic ACL | isolated-broker subscription/publish matrix |
| Modbus | function/register request | authenticated or tightly segmented maintenance path | read-only identity query; no reboot write |
| OCPP backend | server-supplied command or field | authenticated, pinned backend plus validated grammar | local recorder and inert argument token |
| Firmware | image, checksum, manifest, target module | cryptographic signature, model, version, and rollback policy | verifier decision table using inert blobs |
| Local scripts | low-role config value or environment | constrained parser and non-root sink | captured argv/config grammar with execution disabled |
| Shutdown | lifecycle phase and packet arrival time | firewall remains effective until services stop | packet trace to a synthetic listener only |

Record each result independently. Reachability does not prove missing authentication; missing authentication does not prove a mutating method; accepted configuration does not prove command execution; and checksum acceptance does not prove that the image reaches an executable firmware slot.

## Phase 1: identify the exact controller and reachable services

1. Obtain written authorization, physical ownership, model number, firmware build, network diagram, and a rollback/recovery plan.
2. Confirm the product through a local label, supported management UI, or vendor inventory export. Do not rely on an OCPP banner alone.
3. Map only the controller addresses supplied in scope. Test OCPP Agent, JupiCore, MQTT, and Modbus ports individually from the expected management segment and one explicitly approved untrusted segment.
4. Preserve TCP outcome, TLS certificate metadata, protocol handshake, and product evidence. Do not issue mutating protocol functions during discovery.
5. For Modbus, first establish whether the feature is enabled and whether `CharxModbusServer` is listening. Stop at a read-only identification request or TCP handshake; do not exercise the reboot function.
6. Repeat against firmware 1.9.1 when available. A closed port and an authenticated rejection are different negative controls.

A useful exposure result is **confirmed CHARX model/build -> scoped network path -> protocol handshake identifies the expected service -> anonymous session is accepted or rejected**. Do not infer a vulnerability from a generic open MQTT or Modbus port.

## Phase 2: test service authentication and object scope with canaries

Use an isolated controller with fake charging-point identifiers, no customer records, and no connected power output.

### OCPP Agent and JupiCore

1. Capture a legitimate configuration request from the vendor UI without retaining credentials in the report.
2. Replay missing-session, malformed-session, low-role, operator, and expected maintenance-role controls.
3. Replace any backend destination with an HTTPS listener you own. The listener should return a fixed harmless response and log only a synthetic station marker.
4. Request one reversible marker-only setting or instrument the configuration sink with a counter. Do not change charging limits, credentials, network routes, payment state, or real backend enrollment.
5. Compare own charging point, nonexistent point, and a second synthetic point to separate authentication from object authorization.
6. Restore the original fake configuration and verify the before/after hashes.

A bounded positive result is **no authenticated identity -> configuration method accepts request -> owned callback receives only the fake marker or a reversible canary field changes**. Disclosure of real charging-point UIDs is neither necessary nor appropriate.

### MQTT

1. Connect the controller only to a disposable broker network with fake topics and no bridge to production telemetry.
2. Test anonymous, random-credential, low-role, and expected-client connections.
3. Use unique canary topics to build a subscribe/publish matrix. Keep all messages inert plain text.
4. Instrument configuration consumers so messages are recorded but not applied.
5. Vary client ID, topic separators, retained flag, duplicate delivery, CR/LF characters, oversized-but-safe field lengths, and malformed JSON independently.
6. Confirm whether a message crosses into the Modbus/configuration parser; do not send register writes or shell metacharacters.

The evidence chain should distinguish **broker connection -> topic authorization -> message acceptance -> parser consumption -> configuration sink**. CVE-2026-44090, CVE-2026-44091, and CVE-2026-44092 describe different edges; do not collapse them into “MQTT RCE.”

## Phase 3: validate backend-to-command boundaries without command execution

CVE-2026-44098 requires control over the OCPP backend and a firewall-bypass condition. Preserve both preconditions.

1. Point the lab controller to an owned OCPP simulator through the normal configuration flow.
2. Disable shell execution in the controller harness or replace the relevant process launcher with an argv recorder and no-op return value.
3. Send ordinary control fields, an inert delimiter-shaped token, duplicate keys, encoded separators, and length-boundary values. Do not send a shell command, callback, file-write target, or destructive OCPP action.
4. Record the decoded field, normalized configuration, final argv or command-template representation, effective low-privilege identity, and no-op sink count.
5. Test whether the same input is rejected when received from an unpinned backend, through a direct non-OCPP request, and on the fixed build.
6. Review root-owned follow-on scripts separately. A command template reached as `charx-oa` is not proof of root compromise.

A safe positive is **owned backend sends inert delimiter marker -> controller accepts it in the vulnerable field -> recorder shows a command-token boundary change under the documented limited identity**. Never execute the generated command merely to strengthen impact.

## Phase 4: separate firmware transport, authenticity, and activation

The advisory describes a two-stage risk: JupiCore can pass unverified firmware to an internal charging module (CVE-2026-44103), while the basemodule update path checks CRC32 without a cryptographic signature (CVE-2026-44104). CRC32 proves accidental-corruption detection, not publisher authenticity.

1. Obtain vendor-approved disposable firmware fixtures or replace the updater and internal-module consumer with recorders.
2. Create inert blobs for: valid signature and checksum, modified bytes with stale checksum, modified bytes with recomputed CRC32 but no valid signature, wrong model, rollback version, duplicate manifest fields, and truncated image.
3. Exercise download, staging, verifier, target-module selection, activation, and rollback as separate phases.
4. Stop after verifier/staging evidence. Do not flash modified bytes even on a bench device unless Phoenix Contact explicitly supplies a safe test image and procedure.
5. Record which identity may trigger each phase and whether OCPP, JupiCore, REST, or another route can initiate it without authentication.
6. Confirm that 1.9.1 rejects unsigned/re-summed fixtures before transfer to the internal module and binds the signature to model, version, and complete image.

Report **unsigned fixture accepted by verifier or forwarded to a recorder** rather than “malicious firmware installed” unless an approved inert image actually completed the vendor's test activation path.

## Phase 5: review local-to-root script boundaries statically or with no-op sinks

The same advisory includes multiple root-bound script paths: user-application init scripts, network configuration, system configuration, and `udhcpc` handling. These may be reachable only after a separate foothold as `user-app`, `charx-web`, or another limited identity.

1. Use a vendor image copy or disposable controller filesystem. Inventory script owner, mode, interpreter, environment, and writable inputs.
2. Trace each low-role field into generated configuration, shell expansion, service restart, and root-owned execution.
3. Replace privileged process launches with a recorder. Supply only inert delimiter-shaped markers and verify whether they alter argv or configuration grammar.
4. Test whitespace, newline, option-prefix, quote, variable-expansion, and path-canonicalization representations independently.
5. Verify fixed behavior with structured argument passing, allowlisted values, root-owned temporary files, and safe environment resets.
6. Keep credential-log exposure (CVE-2026-44105) as a separate foothold edge. Seed a fake credential marker and prove only whether that marker reaches a low-role-readable log; never recover an actual controller password.

The result should name the exact source identity and sink identity. Do not report a remote-root chain unless the remote foothold, local transition, and root-owned sink were each reproduced with canaries.

## Phase 6: measure shutdown firewall ordering safely

CVE-2026-44108 concerns a temporary lifecycle window, not steady-state exposure.

1. Use a disconnected bench network with one controller, a packet recorder, and one synthetic internal TCP listener that returns a fixed marker.
2. Confirm the listener is unreachable during steady operation and that no real management daemon is used as the target.
3. Instrument lifecycle timestamps for firewall stop, synthetic listener stop, interface down, and power-off.
4. During an approved shutdown, send low-rate connection attempts only to the synthetic listener.
5. Preserve packet timestamps and service logs. Stop after one marker response; do not enumerate newly reachable ports.
6. Repeat on the fixed build and require firewall enforcement to remain until internal listeners and interfaces are unavailable.

A bounded positive result is **steady-state blocked -> firewall termination event -> synthetic listener accepts one canary connection before listener/interface shutdown**. This does not by itself prove access to JupiCore, MQTT, SSH, or root execution.

## Reporting checklist

Include:

- exact model number, firmware build, feature state, network segment, port, protocol, and test identity;
- service-by-service authentication and authorization matrices;
- OCPP backend ownership, TLS/pinning result, normalized field, and no-op command-recorder diff;
- firmware stage reached, checksum/signature/model/version decisions, and proof that activation did not occur;
- low-role source identity, root-owned script or service, captured argv/config grammar, and disabled sink;
- lifecycle timestamps for firewall, interface, and synthetic listener;
- firmware 1.9.1 availability as observed on the test date, not merely the vendor's future availability deadline;
- separate impact statements for reachability, anonymous access, reversible configuration, parser boundary, firmware acceptance, local privilege transition, and shutdown exposure.

Do not publish controller credentials, backend URLs, real station identifiers, MQTT topics, firmware images, command strings, charging schedules, customer records, or production network details.

## October 3 follow-up: the charging-network backend tier (Monta WebSocket cluster + Armatura One credential lifecycle)

The July page covers the charger controller. The October 3 ICSA-mirrored wave adds the two tiers above it — the fleet SaaS backend and the OT charging platform — and both yield reusable axes.

### Monta (monta.app) — unauthenticated station-identity WebSocket backend ([ICSA-26-274-02](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-274-02.json))

- [GHSA-jr23-ffqr-cj5j](https://github.com/advisories/GHSA-jr23-ffqr-cj5j) / CVE-2026-95102 (9.4): WebSocket endpoints accept station-identity claims with **no authentication** — anyone can impersonate a charging station to the backend and read/push station state.
- [GHSA-jwgf-7prh-7v76](https://github.com/advisories/GHSA-jwgf-7prh-7v76) / CVE-2026-97212 (7.3): sessions are keyed **only by the charging-station identifier**, multiple endpoints may bind the same id, and identifiers are predictable — connect-with-known-id is the auth.
- [GHSA-9x8m-4wcm-v33m](https://github.com/advisories/GHSA-9x8m-4wcm-v33m) / CVE-2026-93474: station authentication identifiers are **publicly accessible via web mapping platforms** — the identifier space is enumerable from public data.
- [GHSA-pfh8-7x9x-2rrf](https://github.com/advisories/GHSA-pfh8-7x9x-2rrf) / CVE-2026-97363: no rate limiting on WS auth requests (brute-force/DoS leg).
- Durable chain pattern — **identifier-as-credential with a public identifier source**: recon (public map platform) → grammar (predictable ids) → transport (unauthenticated WS destination) composes into full station impersonation with zero secrets. This is the message-transport analogue of this page's unauthenticated-OCPP-Agent phase: on any IoT/OT fleet backend, enumerate WebSocket/MQTT/STOMP destinations with the *lowest* principal and ask where the identity material is supposed to come from — if it's a device identifier, grep for where that identifier is exposed (public dashboards, map integrations, mobile-app API responses). Multi-binding on the same session key is a separate probe: two clients under one id can interleave state.
- Validation boundary: no live station impersonation or backend state writes; prove with an owned/lab-registered station id and read-only canary subscriptions against customer-approved scope only.

### Armatura One <4.7.2 — install-material credential lifecycle ([ICSA-26-274-01](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-274-01.json), also lists CVE-2023-46604 ActiveMQ in the same product)

- [GHSA-rpcg-4hqj-wfv3](https://github.com/advisories/GHSA-rpcg-4hqj-wfv3) / CVE-2026-94591 (8.4): config "encryption" uses a **fixed AES-128-CBC key+IV embedded in the software**, identical across every installation — possessing the (public) installer package plus any installation's config file decrypts its DB/broker credentials.
- [GHSA-rq48-r7v8-mfh6](https://github.com/advisories/GHSA-rq48-r7v8-mfh6) / CVE-2026-94592 (8.4): DB superuser gets a **fixed vendor-defined password** at init.
- [GHSA-3j8c-r7f9-v4vm](https://github.com/advisories/GHSA-3j8c-r7f9-v4vm) / CVE-2026-94593 (7.8): backup/restore logs the **full connection command including the superuser password** in a host log.
- [GHSA-cmfx-346m-p68q](https://github.com/advisories/GHSA-cmfx-346m-p68q) / CVE-2026-94594: broker client credentials logged in plaintext during normal operation — and the advisory notes logs flow into **backups and support bundles**.
- Operator axes: (1) **"encrypted at rest" with product-embedded key material is obfuscation** — audit checklist for any appliance/platform: locate the crypto call, ask where the key comes from; if it's compiled in or a constant, the installer download is the key-theft primitive and config/support-bundle files become decryptable offline; (2) **fixed-installation passwords + credential-bearing logs/bundles** = post-foothold credential harvest list (logs, backup files, support bundles, install configs) that generalizes far beyond charging platforms — pair with the Airflow masker-shape and MAAS-style log-credential findings; (3) the presence of CVE-2023-46604 (ActiveMQ broker RCE) in the same CSAF tells you the platform likely bundles an ActiveMQ broker — fingerprint bundled middleware versions from product docs as a standing OT recon step.