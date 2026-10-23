---
title: "DJI CrystalSky firmware wave: hard-coded USB serial backdoor, unauthenticated adbd, Binder system() sinks, logcat-to-shell eval"
---

# DJI CrystalSky firmware wave: hard-coded USB serial backdoor, unauthenticated adbd, Binder system() sinks, logcat-to-shell eval

Source: hourly offensive-security scan, 2026-10-23. A six-GHSA wave (published 15:31Z) covers DJI CrystalSky ZS600C firmware `v0.3.9.7` through `v0.6.6.9` (Android-based monitor). These are firmware teardown findings written with unusual specificity — magic strings, transaction codes, daemon names — which makes them an excellent template for authorized Android-firmware assessments: every leg is one inspection away on any similar embedded Android product.

!!! warning "Owned hardware only"
    Firmware teardown and these checks apply to devices you own or have explicit written permission to test (e.g. a newsroom/drone-operator's unit is third-party hardware — do not touch). Lab units only; firmware extraction from a device you own for security research is the assumed posture.

## The legs

1. **Hard-coded backdoor string on the USB gadget serial** ([GHSA-pvg3-27hx-g76q](https://github.com/advisories/GHSA-pvg3-27hx-g76q) / CVE-2026-114353, high): the root-privileged `assistant` daemon listens on `/dev/ttyGS0` (USB gadget serial) and, on receiving the hard-coded magic string `dji26656677`, passes **each subsequent line to `system()` as root**. Physically-present attacker with a USB cable = root shell.
2. **Unauthenticated ADB shipped enabled** ([GHSA-826v-5gj2-v5c8](https://github.com/advisories/GHSA-826v-5gj2-v5c8) / CVE-2026-114357, critical, vendor CVSS 9.3): `ro.adb.secure=0` (no host-key authorization) **and** USB ADB enabled by default → unauthenticated uid-2000 shell over USB. ADB-over-TCP is off by default but a single shipped helper (`/system/bin/adbd_tcp.sh` or `setprop persist.adb.tcp.port 5555`) flips it to an **unauthenticated network shell** — a one-command USB-to-network escalation of the same primitive.
3. **Native Binder service `android.dji.server` → root `system()`** ([GHSA-f65q-v44p-qw67](https://github.com/advisories/GHSA-f65q-v44p-qw67) / CVE-2026-114354, high): transaction code **1018** hands a caller-supplied string straight to `system()` in the root `assistant` daemon, no caller-identity or permission check — any unprivileged installed app is root.
4. **`DJIUpdateService` Binder, no authorization at all** ([GHSA-pgwp-m7vv-2xhr](https://github.com/advisories/GHSA-pgwp-m7vv-2xhr) / CVE-2026-114356, high): `onTransact()` performs zero checks; transaction 153 = factory reset with user-data wipe, 105 = shutdown, 101/123 = clock/timezone change, **151 = firmware-apply hand-off**. Destructive + update-hijack entry from any app with no permissions.
5. **logcat-fed shell eval** ([GHSA-258v-3gxg-h7w6](https://github.com/advisories/GHSA-258v-3gxg-h7w6) / CVE-2026-114355, high): the root `hardware_monitor` helper reads lines from the Android log and **shell-evals** them — a local unprivileged process writes a crafted logcat line and runs as root. Global, world-writable IPC (the log) used as a command channel.

## Operator rules this wave generalizes

- **Firmware strings are the first recon, and they pay literally.** `grep -r` the extracted filesystem for magic tokens (`dji26656677`), `system(`/`exec` call sites in vendor daemons, and init.rc/service definitions running as root. On any embedded Android target: extract the super partition from an owned device, enumerate root-owned custom daemons, and check each one's input channels (serial ports, sockets, logs, Binder) for direct exec sinks. This wave is five legs from exactly that sweep.
- **Check `ro.adb.secure` and shipped ADB helpers in every vendor image.** Debugging infrastructure shipped enabled is KEV-class exposure on field gear; a shipped `.sh`/prop that enables ADB-TCP turns any LAN position into an unauthenticated shell. `getprop | grep -i "secure\|adb"` + searching `/system/bin` for adbd helpers is a two-minute audit on any pulled firmware.
- **Enumerate Binder services and transaction codes, then diff their authorization.** `service list` / native Binder registration review, then per-transaction checks (or their absence, like `onTransact()` with zero checks). Named, numbered privileged transactions with no permission gate are a stable Android-firmware finding class: an app with no permissions reaching factory-reset/firmware-apply is both an integrity and an availability boundary break. The firmware-apply hand-off (transaction 151) is the update-path leg — pair with update-payload signature verification checks before calling update hijack.
- **The Android log is a global IPC channel — never a trusted input.** Any root helper that parses logcat text (or any world-writable global surface: properties, `/dev/socket/logdr`, config centers) into eval/exec is a local-root ladder. Grep vendor helpers for logcat parsing; battery: line-injection shapes into every field the helper reads.
- **Physical-access ≠ low severity on field gear.** Drone monitors sit in vans and hangars; a USB-C port plus a hard-coded string makes physical contact = root. Frame these in reports for the audience that owns the device: the gadget-serial backdoor needs no software foothold at all, and the Binder legs give any sideloaded app (or any app that phishes an install) a root hop.
- **Same-product audit-tree**: one teardown finding on an embedded Android product usually implies the family — all three root daemons here (`assistant`, `hardware_monitor`, `DJIUpdateService`) were separate findings by the same method. After finding one exec sink, sweep every root daemon's inputs, not just the discovered one.

## Assessment flow for similar devices (owned/lab units)

1. Pull firmware (official updates or owned-device extraction); mount super.
2. Inventory root services: init scripts, `sepolicy` gaps, vendor daemons in `/system/bin`, `/vendor/bin`.
3. Static grep: `system(`, `popen`, `exec`, magic strings, hard-coded passwords, `adb`, `ttyGS`, log parsers.
4. Build props audit: `ro.adb.secure`, `ro.debuggable`, `persist.*` debug switches.
5. On-device (lab): `service list`, dumpsys/Binder enumeration, transaction-code fuzz on vendor services with inert markers, `/dev/ttyGS0` line probes at the USB console.
6. Proof boundaries: inert marker files/echo commands only; never flash modified firmware onto operational aircraft/monitors, never trigger factory-reset/firmware-apply transactions on units holding flight data.

## Tracked with this wave

KEV moved this scan — see [cisa-kev.md](cisa-kev.md): Arista **VeloCloud Orchestrator SQL injection CVE-2026-114625 KEV'd 2026-10-23** (due 10-26) on the same product page already carrying the July command-injection KEV and the October authenticated→superuser-operator escalation; third distinct VCO boundary KEV'd this quarter keeps the same-product re-sweep rule hot for any SD-WAN control-plane engagement. PHP2Shell (CVE-2026-109618/109619) **still not in KEV** as of catalog 2026.10.23 — head-start watch continues. DJI legs are not KEV'd (local/physical class).
