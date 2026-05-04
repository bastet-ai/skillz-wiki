# VM2, Incus, OpenClaw, and fleet telemetry boundary batch (GHSA)

**Signal:** GitHub Security Advisories surfaced new and newly updated advisories on **2026-05-04** covering five different trust-boundary failures: JavaScript sandbox escape, pre-validation SSRF, OVN control-plane TLS authentication collapse, Slack allowlist context bleed, and vehicle telemetry identity spoofing.

## Advisories in this batch

- **VM2 sandbox breakout through `__lookupGetter__`** — `vm2` versions `<= 3.10.4` allow sandboxed JavaScript to reach host `Function` and execute commands. Fixed in **3.11.0**. References: <https://github.com/advisories/GHSA-grj5-jjm8-h35p>, <https://github.com/patriksimek/vm2/security/advisories/GHSA-grj5-jjm8-h35p>
- **Incus blind SSRF via image import preflight HEAD** — authenticated users in restricted projects can make the daemon send host-originated `HEAD` requests to arbitrary URLs before image-source policy fully rejects the import. Fixed in **7.0.0**. References: <https://github.com/advisories/GHSA-8gw4-p4wq-4hcv>, <https://github.com/lxc/incus/security/advisories/GHSA-8gw4-p4wq-4hcv>
- **Incus OVN TLS peer-supplied root acceptance** — OVN database client paths disabled standard TLS verification and then built trust roots from certificates supplied by the peer, defeating the configured CA for OVN northbound/southbound database connections. The advisory rates this low because exploitation normally needs a strong control-plane network position, but the durable lesson is important: custom TLS verification must anchor to operator-supplied roots, not peer-provided material. Fixed in **7.0.0**. References: <https://github.com/advisories/GHSA-c839-4qxr-j4x3>, <https://github.com/lxc/incus/security/advisories/GHSA-c839-4qxr-j4x3>, CVE-2026-40243.
- **OpenClaw Slack thread context allowlist bypass** — OpenClaw `<= 2026.4.1` could include Slack thread messages from non-allowlisted senders when an allowlisted user replied in the same thread. Fixed in **2026.4.2**. References: <https://github.com/advisories/GHSA-qm77-8qjp-4vcm>, <https://nvd.nist.gov/vuln/detail/CVE-2026-41358>
- **Tesla Fleet Telemetry VIN spoofing with compromised vehicle credentials** — `github.com/teslamotors/fleet-telemetry` `<= 0.8.0` allowed a client with valid compromised vehicle credentials to submit falsified telemetry for arbitrary VINs. Fixed in **0.9.0**. Reference: <https://github.com/advisories/GHSA-prxj-3gcv-cqrh>

## Why this is durable

These are different systems, but the reusable lesson is the same: a partial boundary is not a boundary.

- A sandbox is not safe if any host-context primitive can be recovered from bridged built-ins or prototype access.
- An SSRF policy is not safe if metadata/preflight network traffic happens before all policy checks pass.
- Custom TLS verification is not safe if it replaces platform validation without preserving configured CA roots and endpoint identity checks.
- A sender allowlist is not safe if historical thread context is fetched through a wider API path than live messages.
- A telemetry identity model is not safe if one valid credential can assert identifiers it was never bound to.

## Immediate triage

1. **Find exposure quickly:** search dependency manifests and SBOMs for `vm2`, `github.com/lxc/incus/v6/cmd/incusd`, `openclaw`, and `github.com/teslamotors/fleet-telemetry`.
2. **Patch or isolate:** upgrade to VM2 `3.11.0`, Incus `7.0.0`, OpenClaw `2026.4.2`, and Fleet Telemetry `0.9.0` where applicable. If you cannot patch immediately, restrict untrusted code execution, image imports, OVN control-plane reachability, Slack thread-context ingestion, and telemetry write paths.
3. **Treat sandbox escape as host compromise:** for systems that ran attacker-controlled JavaScript in VM2, preserve evidence, rotate secrets reachable from the process, and rebuild from trusted images.
4. **Review pre-validation egress:** block daemon/service egress to link-local, loopback, RFC1918, and metadata endpoints unless explicitly required; log rejected and attempted preflight destinations.
5. **Review custom TLS paths:** inventory `InsecureSkipVerify`, `VerifyPeerCertificate`, custom CA-pool construction, and mTLS client code; require tests proving the configured CA is the trust root and rogue self-signed peer chains fail.
6. **Re-check context filters:** verify that every Slack/thread-history retrieval path enforces the same sender allowlist as live message handling before content enters model context.
7. **Bind credentials to subjects:** for telemetry or device fleets, ensure certificates/keys are cryptographically and server-side bound to the specific device/VIN/account they may report for.

## Hunt ideas

- Look for VM2 workloads that executed user-provided code and then spawned child processes, touched unexpected files, or made unusual outbound connections.
- Query Incus logs and proxy/egress logs for image import attempts to webhook, metadata, loopback, internal DNS names, or unusual ports that failed after a `HEAD` request.
- For OVN-backed Incus clusters, review management-network changes, OVN database endpoint/DNS changes, unexpected certificates, failed OVN transactions, and logs around northbound/southbound database reconnects.
- Audit Slack agent transcripts for thread context containing senders outside the configured allowlist, especially threads where an allowlisted user responded after untrusted participants.
- Compare telemetry ingestion logs for one certificate/key presenting multiple VINs, unexpected VIN/key pairings, impossible location sequences, or telemetry bursts after a vehicle-rooting event.

## Durable controls

- Run untrusted code only in a layered isolation model: process/container/VM boundaries, seccomp/AppArmor, read-only filesystems, no ambient cloud credentials, and deny-by-default egress.
- Validate policy before side effects. URL parsing, allowlists, identity checks, and authorization must complete before network requests, context fetches, writes, or expensive processing.
- Prefer platform TLS verification with explicit `RootCAs`/server names; if custom verification is unavoidable, add negative tests for rogue self-signed chains, peer-supplied intermediates, wrong hostnames, expired certificates, and missing client-auth constraints.
- Apply the same authorization filter to every data path: live events, API history fetches, cache hydration, retries, background jobs, and summarization context.
- Design telemetry and device APIs so credentials prove both possession and subject authority; never let a bearer certificate choose arbitrary subject identifiers at request time.

## Operator lesson

When reviewing a system, trace the first side effect after untrusted input enters the process. If any network request, context load, code execution, TLS trust decision, or identity assertion happens before the relevant policy guard, the guard is probably in the wrong place.
