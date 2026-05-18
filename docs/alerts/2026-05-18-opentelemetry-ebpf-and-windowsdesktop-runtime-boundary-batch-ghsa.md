# OpenTelemetry eBPF and WindowsDesktop runtime-boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-fjq3-ffvr-vm46](https://github.com/advisories/GHSA-fjq3-ffvr-vm46),
[GHSA-r6c9-g6q5-qrf9](https://github.com/advisories/GHSA-r6c9-g6q5-qrf9),
[GHSA-89c6-vpcj-7vj4](https://github.com/advisories/GHSA-89c6-vpcj-7vj4), and
[GHSA-8x9c-mqxv-q2pp](https://github.com/advisories/GHSA-8x9c-mqxv-q2pp).

This batch is durable because it connects two recurring host-boundary lessons: observability agents that run privileged kernel-facing probes must treat every traced process as hostile input, and desktop/runtime packages must be patched with the same urgency as application dependencies when local file or UI paths can cross privilege boundaries.

## What changed

- **OpenTelemetry eBPF Instrumentation / OBI (`go.opentelemetry.io/obi`)** fixed three issues in 0.9.0:
  - Java TLS ioctl tracing read a user-controlled ioctl pointer with kernel-memory read helpers, allowing an instrumented local process to steer telemetry collection toward kernel memory and disclose bytes through exported traces.
  - The HTTP/HTTP2 fallback path could substitute a 256-byte buffer while preserving an original payload size up to 8 KiB, creating an over-read into adjacent memory that could be emitted as telemetry.
  - Internal BPF metrics replayed one histogram observation per probe hit without capping the run-count delta, so high probe activity could turn a scrape interval into CPU exhaustion.
- **Microsoft WindowsDesktop .NET runtime packages** fixed CVE-2026-35433, a local elevation-of-privilege issue in .NET 8, 9, and 10 for Windows Desktop runtime packages. Patched package trains are 8.0.27, 9.0.16, and 10.0.8 for win-x86, win-x64, and win-arm64.

## Operator triage

1. Upgrade OBI / OpenTelemetry eBPF Instrumentation to 0.9.0+ anywhere it runs with BPF privileges, especially shared Kubernetes nodes, developer workstations, multi-tenant CI hosts, and production clusters that instrument untrusted workloads.
2. Treat observability output as potentially sensitive until patched: telemetry pipelines, trace stores, logs, and metrics backends may contain leaked process or kernel-adjacent bytes from vulnerable probes.
3. Patch WindowsDesktop runtime packages on Windows hosts running WPF/WinForms/Desktop .NET applications, local automation tools, packaged desktop clients, or installer/updater flows that can be influenced by untrusted users.
4. Prioritize hosts where local users, build jobs, browser-launched helpers, or remote-support sessions can supply crafted inputs to .NET desktop components.
5. If immediate OBI patching is blocked, disable Java TLS tracing and internal BPF metrics export where possible, reduce scrape frequency, isolate tracing agents from tenant-readable telemetry sinks, and restart agents after abnormal CPU or memory behavior.

## Replayable validation boundaries

- **eBPF user-pointer boundary:** instrument a hostile local test process that supplies invalid, kernel-like, unmapped, and oversized ioctl pointers. Patched probes must read only user memory through user-safe helpers and must not emit unrelated kernel/process bytes.
- **Fallback-buffer size boundary:** force CPU-mismatch or fallback-buffer paths and verify the exported payload length is clamped to the actual fallback buffer size, not the original captured request size.
- **Metrics cardinality / replay boundary:** drive high probe counts between Prometheus scrapes and confirm exporter CPU cost is bounded by series count or bucket updates, not by raw probe-hit count.
- **Telemetry secrecy boundary:** search trace, log, and metrics stores for unexpected binary blobs, adjacent process memory, secrets, HTTP payload fragments, and kernel-looking addresses after reproducing probe failures.
- **WindowsDesktop runtime boundary:** inventory deployed `Microsoft.WindowsDesktop.App.Runtime.win-*` package versions and verify every app resolves to 8.0.27, 9.0.16, 10.0.8, or newer; test local crafted-input paths under least-privilege user accounts.

## Durable controls

- Privileged observability agents need the same secure-coding posture as endpoint sensors: strict user/kernel pointer separation, exact buffer-length propagation, bounded aggregation, and least-sensitive export defaults.
- Do not let telemetry systems become a covert memory-disclosure channel. Apply redaction and retention controls to traces and metrics, and isolate tenant visibility when agents observe shared hosts.
- Prefer aggregate math over per-event replay for metrics exporters. Counters and histograms should update in bounded work per scrape interval.
- Track runtime packages separately from application dependencies; NuGet lockfiles, base images, desktop installers, and self-contained publish artifacts can each pin vulnerable runtime components.
- Run local desktop helpers and observability collectors with the minimum privileges needed, and keep their update path fast enough for out-of-band runtime and sensor fixes.
