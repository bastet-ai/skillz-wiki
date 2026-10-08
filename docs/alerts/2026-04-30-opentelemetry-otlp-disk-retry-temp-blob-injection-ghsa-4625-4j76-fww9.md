# OpenTelemetry OTLP disk retry temp-blob injection (GHSA-4625-4j76-fww9 / CVE-2026-42191)

**Signal:** GitHub Security Advisories published **2026-04-30**. OpenTelemetry .NET OTLP exporter disk retry could fall back to shared temp directories and trust predictable retry blob paths.

## What it is
When `OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY=disk` was enabled without `OTEL_DOTNET_EXPERIMENTAL_OTLP_DISK_RETRY_DIRECTORY_PATH`, `OpenTelemetry.Exporter.OpenTelemetryProtocol` used `Path.GetTempPath()` and fixed subdirectories such as `traces`, `metrics`, and `logs` for retry `*.blob` files.

On multi-user systems or shared temp roots, a local attacker could:

- inject crafted retry blobs that the exporter later forwards to the configured OTLP collector under the application identity;
- read queued telemetry blobs during export failures, exposing spans, metrics, logs, and possibly sensitive attributes;
- deposit many or oversized blobs to exhaust disk/CPU/IO in retry loops.

Affected package: NuGet `OpenTelemetry.Exporter.OpenTelemetryProtocol` versions `1.8.0` through `1.15.2` when disk retry is enabled and no dedicated retry directory is configured. Fixed version: `1.15.3`.

Reference: <https://github.com/advisories/GHSA-4625-4j76-fww9>

## Triage
1. Search .NET services for `OpenTelemetry.Exporter.OpenTelemetryProtocol` and disk retry environment variables.
2. Identify hosts where app temp directories are shared with other users, tenants, jobs, sidecars, or containers.
3. Check for `/tmp/traces`, `/tmp/metrics`, `/tmp/logs`, `%TEMP%\traces`, `%TEMP%\metrics`, or `%TEMP%\logs` containing unexpected `*.blob` files.
4. Treat telemetry from affected windows as potentially tainted or disclosed if local attackers or co-tenants were present.

## Mitigation
- Upgrade `OpenTelemetry.Exporter.OpenTelemetryProtocol` to `1.15.3` or later.
- Configure a dedicated retry directory with strict owner-only permissions whenever disk retry is enabled.
- Avoid disk retry in shared or multi-tenant environments unless the retry path is private and quota-bound.
- Keep telemetry exporter egress pinned to trusted collectors and protected by TLS.

## Detection ideas
- Monitor retry directories for unexpected owners, permissions, symlinks, or anomalous blob counts/sizes.
- Alert when telemetry retry backlogs grow suddenly or exporter CPU/IO spikes during retry scans.
- Inspect collector data for malformed or impossible spans/logs that could indicate blob injection.

## Durable lesson
Retry queues are trust boundaries. If a process will later replay files with its identity, the queue path must be private, permission-checked, quota-bound, and never silently default to a shared temp root.

## October 8 follow-up: same shape in native-library loaders ([GHSA-mcr4-qmvw-px4g / CVE-2026-106451](https://github.com/advisories/GHSA-mcr4-qmvw-px4g), high, yawkat `lz4-java` < 1.11.4)

`net.jpountz.util.Native.load()` extracts the bundled native library into `java.io.tmpdir` when no system `liblz4-java` is present and `System.load()`s it. Only the `.lck` sentinel gets a random, exclusively-created name; the library path is derived by stripping `.lck`, is predictable before creation, and is opened without exclusive creation. A co-tenant that wins the race controls the code loaded into every JVM that later uses the library — arbitrary-code-execution-grade local persistence in one shared temp root.

Operator rules for shared-host footholds (the recon half of this class):

1. **Enumerate loader-written temp artifacts.** On any multi-user host, list predictable shared-temp library/bundle/queue names (`lib*-java*.so`, exporter retry blobs, extracted helper binaries). A file another user's process will later `load()`/replay with its identity is a standing local-privilege target.
2. **Race-shape check, bounded.** The reportable primitive is "path is predictable and non-exclusive" — prove with a marker file placed at the predicted path in a lab, never by loading code on a shared system. Evidence: the lock-file/library-file naming scheme, file owner, and load-order timeline.
3. **Grep-side fingerprint for audits:** `createTempFile` followed by a derived (string-mangled) path used in `System.load`/`dlopen`/`exec` — the random name guards only the lock, not the payload. Same genealogy as the Oct 6 Nx world-connectable daemon UDS finding: the safely-created artifact and the actually-consumed artifact are different files.
