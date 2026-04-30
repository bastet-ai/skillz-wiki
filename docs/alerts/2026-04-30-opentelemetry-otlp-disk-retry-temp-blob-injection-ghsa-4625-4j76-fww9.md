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
