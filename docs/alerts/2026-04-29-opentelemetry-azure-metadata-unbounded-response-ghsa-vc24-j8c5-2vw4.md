# OpenTelemetry Azure resource detector unbounded metadata response (GHSA-vc24-j8c5-2vw4)

**Signal:** GitHub Security Advisory published **2026-04-29**. `OpenTelemetry.Resources.Azure` could read an unbounded Azure Instance Metadata Service response body into memory.

## What it is
The Azure VM resource detector in OpenTelemetry .NET Contrib requests metadata from the Azure IMDS endpoint at `http://169.254.169.254`. Vulnerable versions buffered the response body without a size limit. If an attacker can control the configured endpoint or intercept metadata traffic, they can return an arbitrarily large body and force excessive heap allocation, garbage-collection stalls, or process termination.

Affected package:

- NuGet: `OpenTelemetry.Resources.Azure`
- Vulnerable range: `<= 1.15.0-beta.1`
- Advisory CVE: `CVE-2026-41483`

References:

- GitHub advisory: <https://github.com/advisories/GHSA-vc24-j8c5-2vw4>
- Fix discussion: <https://github.com/open-telemetry/opentelemetry-dotnet-contrib/pull/4121>

## Triage
1. Search .NET services for `OpenTelemetry.Resources.Azure` and Azure VM resource detector usage.
2. Prioritize internet-facing, multi-tenant, job-runner, and telemetry-heavy services where an OOM crash has customer impact.
3. Check whether deployments rely on metadata-service routing, sidecars, service meshes, local proxies, or custom endpoint overrides.
4. Review network controls around `169.254.169.254`; metadata traffic should not be transparently redirected through untrusted paths.

## Mitigation
- Upgrade `OpenTelemetry.Resources.Azure` to a fixed release (`1.15.1-beta.1` or later, based on the advisory package metadata).
- If immediate upgrade is not possible, disable the Azure VM resource detector for exposed workloads.
- Enforce egress controls so metadata requests only reach the real Azure IMDS endpoint from expected hosts.
- Treat metadata endpoints as privileged infrastructure dependencies; avoid routing them through generic proxies or untrusted service-mesh hops.
- Prefer streaming reads with explicit response-size caps for all metadata, discovery, and telemetry enrichment clients.

## Detection ideas
- Alert on sudden memory growth or OOM kills shortly after service startup or telemetry initialization.
- Inspect outbound requests to `169.254.169.254` and any nonstandard metadata endpoint overrides.
- Look for unusually large HTTP responses on metadata-service paths in proxy, service-mesh, or host firewall logs.

## Durable lesson
Metadata clients are still network clients. They need the same response-size limits, streaming behavior, and trust-boundary controls as internet-facing HTTP fetchers.
