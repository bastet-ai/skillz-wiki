# OpenTelemetry ServiceMonitor token-file boundary

Source: hourly offensive-security scan, 2026-06-10. Primary entry: GitHub advisory [GHSA-cxh2-4639-vmc5](https://github.com/advisories/GHSA-cxh2-4639-vmc5) / CVE-2026-47701 for OpenTelemetry Operator for Kubernetes TargetAllocator preserving `ServiceMonitor` file-backed bearer-token settings.

This is durable for operators because it turns a Kubernetes monitoring integration into a repeatable file-read and token-forwarding boundary check: a tenant with `ServiceMonitor` write can cause the collector pod to read a local file and send it as bearer auth to an attacker-controlled scrape endpoint.

## What changed

OpenTelemetry Operator TargetAllocator watches Prometheus Operator `ServiceMonitor` resources and converts selected endpoints into Prometheus scrape configuration. In affected versions, endpoint `bearerTokenFile` is preserved as `HTTPClientConfig.Authorization.CredentialsFile`. The collector then reads that path from its own pod filesystem at scrape time and sends the contents in an `Authorization: Bearer ...` header to the configured scrape target.

The advisory calls out the collector service-account token path as a concrete example, but the primitive is broader: any file readable inside the collector pod and accepted by the scrape auth configuration can become outbound header material.

## Operator triage

1. **Find TargetAllocator deployments:** inventory OpenTelemetry Operator installs where `targetAllocator.prometheusCR.enabled` is enabled.
2. **Map selected namespaces:** record `serviceMonitorSelector` and `serviceMonitorNamespaceSelector` values, then identify namespaces where non-admin tenants, app teams, CI jobs, or GitOps repos can create or update `ServiceMonitor` or `PodMonitor` objects.
3. **Check collector token/file exposure:** confirm whether the collector pod mounts a service-account token and what other projected secrets, certs, or config files are readable by the collector process.
4. **Confirm outbound reachability:** determine whether the collector can scrape tenant-controlled endpoints, external URLs, or in-cluster capture services.
5. **Scope Kubernetes impact by RBAC:** the severity depends on the collector service account. High-value findings show cluster-wide list/read privileges, workload metadata access, or other API permissions bound to the stolen token.

## Replayable validation boundary

Use a lab namespace or an explicitly approved cluster. Do not exfiltrate real tokens or secrets from production.

1. Stand up a controlled HTTPS/HTTP capture endpoint inside the approved test scope and log only request metadata plus a synthetic marker header/body when possible.
2. Create or update a `ServiceMonitor` selected by TargetAllocator with a benign scrape target that points to the capture endpoint.
3. For proof without exposing real secrets, prefer a disposable collector deployment with a mounted synthetic file such as `/tmp/skillz-otel-canary-token` and set `bearerTokenFile` to that path.
4. Wait for a scrape interval and confirm the capture endpoint receives `Authorization: Bearer <canary>`, proving the collector read a pod-local file because of tenant-controlled monitoring configuration.
5. If customer validation specifically requires the default service-account-token path, coordinate a short-lived lab token, redact it immediately, and capture only evidence that a bearer header was sent—not the token value.

Minimal shape of the risky object:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: otel-token-file-canary
  namespace: tenant-lab
spec:
  selector:
    matchLabels:
      app: approved-canary
  endpoints:
    - port: web
      path: /metrics
      interval: 30s
      bearerTokenFile: /tmp/skillz-otel-canary-token
```

## Reporting heuristics

- Lead with the exact boundary: **tenant-controlled monitoring config causes the collector pod to read a local file and forward it as bearer auth**.
- Include the selected namespace/selector path, the actor who can write `ServiceMonitor`, the file path proven with a canary, the scrape target under tester control, and the collector service-account RBAC summary.
- Avoid claiming arbitrary file download unless you prove response capture of file contents through the bearer header path. The reliable primitive is file-to-Authorization-header forwarding.
- Keep evidence redacted: never paste service-account JWTs, mounted certs, customer file contents, or capture logs containing live credentials into the wiki or report.
