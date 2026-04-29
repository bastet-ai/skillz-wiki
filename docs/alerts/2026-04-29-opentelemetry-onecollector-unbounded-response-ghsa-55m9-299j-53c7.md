# OpenTelemetry OneCollector exporter unbounded response body (GHSA-55m9-299j-53c7)

**Signal:** GitHub Security Advisory published **2026-04-29**. `OpenTelemetry.Exporter.OneCollector` could read unbounded HTTP response bodies into memory.

## What it is
The OneCollector exporter in OpenTelemetry .NET Contrib accepted HTTP responses without a strict body-size cap. If an attacker can control or intercept the collector endpoint, they can return a very large response and force memory exhaustion or service instability.

Affected package:

- NuGet: `OpenTelemetry.Exporter.OneCollector`
- Vulnerable range: `<= 1.15.0`
- Fixed version: `1.15.1`
- Advisory CVE: `CVE-2026-41484`

References:

- <https://github.com/advisories/GHSA-55m9-299j-53c7>
- <https://github.com/open-telemetry/opentelemetry-dotnet-contrib/security/advisories/GHSA-55m9-299j-53c7>

## Triage
1. Search .NET services for `OpenTelemetry.Exporter.OneCollector`.
2. Check whether exporter endpoints can be configured by tenants, environment variables, deployment manifests, or compromised service discovery.
3. Prioritize high-availability services where telemetry startup or export failures can crash the process.
4. Review proxy/service-mesh paths that could tamper with collector responses.

## Mitigation
- Upgrade `OpenTelemetry.Exporter.OneCollector` to `1.15.1+`.
- Pin collector endpoints to trusted hosts and enforce TLS validation.
- Put telemetry exporters behind egress allowlists; they should not talk to arbitrary hosts.
- Apply process memory limits and restart policies so telemetry failures do not become full-service outages.

## Detection ideas
- Alert on sudden memory growth tied to telemetry export attempts.
- Inspect exporter traffic for unusually large response bodies from collector endpoints.
- Hunt configuration changes that alter collector URLs, proxies, or certificate-validation behavior.

## Durable lesson
Telemetry exporters are production network clients. They need response-size caps, endpoint allowlists, and failure isolation so observability cannot become an availability dependency.
