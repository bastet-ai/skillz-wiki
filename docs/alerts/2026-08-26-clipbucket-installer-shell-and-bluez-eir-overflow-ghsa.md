# ClipBucket V5 web-installer `php_cli_filepath` shell execution and BlueZ crafted-EIR stack overflow

Source: GitHub Security Advisories, 2026-08-26 hourly scan: [GHSA-h7wf-mrfw-7fxq](https://github.com/advisories/GHSA-h7wf-mrfw-7fxq) / [CVE-2026-80138](https://nvd.nist.gov/vuln/detail/CVE-2026-80138) (critical) and [GHSA-f784-6479-v89p](https://github.com/advisories/GHSA-f784-6479-v89p) / [CVE-2026-80186](https://nvd.nist.gov/vuln/detail/CVE-2026-80186) (high). Two distinct, reusable operator primitives: an **unauthenticated web-installer parameter that reaches shell execution**, and a **wireless in-range protocol-stack overflow via a crafted Bluetooth Extended Inquiry Response (EIR)**.

## What changed

### ClipBucket V5 web installer (CVE-2026-80138, critical)

ClipBucket V5's web installer fails to properly validate or escape the `php_cli_filepath` parameter before passing it to shell execution. An unauthenticated attacker can submit a crafted `POST` to the installer with a malicious `php_cli_filepath` value to execute arbitrary commands as the web server user.

The reusable pattern is the classic **installer-time config parameter -> shell execution** boundary: installers routinely accept paths to runtime binaries (`php`, `python`, `node`) so they can verify the environment, and that path flows into a shell command. It is the same family as the 3X-UI log-path import chain and the `php_cli`/`php_binary` installer parameters seen across PHP app installers.

### BlueZ crafted EIR stack overflow (CVE-2026-80186, high)

A stack-based buffer overflow in BlueZ, the Linux Bluetooth protocol stack. A remote user within Bluetooth radio range can send a specially crafted Extended Inquiry Response (EIR) packet that overflows a stack buffer when the target device performs Bluetooth discovery. This can crash the `bluetoothd` service (DoS) and may allow arbitrary code execution.

The reusable pattern is a **wireless in-range protocol-parser overflow**: an unauthenticated, radio-range attacker sends a crafted advertisement/inquiry-response that the local stack parses into a fixed-size stack buffer. EIR parsing is a classic target because the payload is fully attacker-controlled and unauthenticated.

## Operator triage

### ClipBucket
1. **Fingerprint the installer.** Identify externally reachable ClipBucket V5 installers: the installer route, the `php_cli_filepath` form field, and version markers. An exposed installer on a live host is the pre-condition; most real deployments complete installation, so this is highest-value on partially configured / reinstallable instances.
2. **Confirm the shell sink.** The impact ceiling is the web server user. If the app runs as `www-data`/`apache`/`nginx` worker, the command execution is that user.
3. **Scope the primitive as unauthenticated RCE.** No login, no upload, no CSRF, a single crafted `POST` field. This is a top-tier finding on an in-scope target.

### BlueZ
1. **Fingerprint Bluetooth stack and exposure.** Confirm the target runs BlueZ (`bluetoothd`) and that the host performs Bluetooth discovery (inquiry), a phone/desktop with Bluetooth enabled in a Bluetooth range. The overflow fires during *discovery*, so the target must be actively inquiring or accept inquiry responses.
2. **Confirm in-range.** This is a physical / wireless proximity primitive. Value is highest in shared-physical-space red-team work (office, venue, device-in-warehouse) rather than remote bug-bounty.
3. **Prioritize by impact.** DoS (crash `bluetoothd`) is the reliable result; code execution is possible but unproven in the advisory. Report DoS as the confirmed primitive and RCE as the ceiling, and prove whichever you can in a lab.

## Replayable validation boundaries

Validate on authorized, disposable hardware / VMs only. Do not target production hosts, shared wireless infrastructure, or devices you do not control. Do not crash services on a live host, do not exfiltrate data, and do not run payloads against unowned devices.

### ClipBucket lab
- A disposable ClipBucket V5 instance in an incomplete-install state, on a VM/container you own.
- Craft the `POST` to the installer with a `php_cli_filepath` value that is a canary shell command (a marker script that writes a canary file), not a real payload.
- Confirm the command executes as the web server user and the canary file is created. Record the exact field, the value, the process user, and the canary effect. On a patched/control build, confirm the value is rejected or escaped.
- Do not run destructive commands; the proof is the canary write plus process-user confirmation.

### BlueZ lab
- A disposable BlueZ host (VM/container with a virtual Bluetooth adapter, or dedicated test hardware) and a second controlled BLE/BT device within range.
- Use a controlled Bluetooth radio to emit a crafted EIR with an oversized/edge-case field that overflows the stack buffer during the host's discovery.
- Confirm DoS: the host's `bluetoothd` crashes / restarts, with the crash signature (assert/segfault, core) captured. Record the crafted EIR bytes, the crash signature, and the pre/post state.
- If pursuing code execution, prove it only on the isolated lab host with a controlled stack canary/controlled return; do not attempt exploitation on shared or production hardware.
- Keep all radio traffic within your controlled lab airspace; never transmit test beacons in a shared venue or against unowned devices.

## Reporting heuristics
- **ClipBucket:** frame as **unauthenticated web-installer `php_cli_filepath` -> shell execution as web server user**. Record the route, the exact crafted value, the process user, and the canary effect. State the version (V5) and note the unauthenticated pre-condition.
- **BlueZ:** frame as **in-range crafted EIR -> BlueZ `bluetoothd` stack overflow during discovery -> DoS (and possible RCE)**. Record the crafted EIR structure, the crash signature, the radio-range pre-condition, and the DoS/RCE split.
- Keep the two as distinct findings (different products, different attack surfaces) but group them on this page as a "reusable installer-parameter-shell + wireless-protocol-overflow" pairing.

## Safety
- **Authorized, in-scope targets only.** Both require lab mirrors; never test a production installer or a live Bluetooth host you do not own.
- **Canary payloads only.** Use marker writes / controlled crashes; do not deploy real payloads, do not exfiltrate, and do not touch production state.
- **Controlled radio airspace only.** BlueZ testing must be in a controlled, owned wireless environment; never transmit test beacons in a shared venue or against unowned devices.
- **No destructive DoS on live systems.** Confirm the crash on a disposable host, not a production one.
