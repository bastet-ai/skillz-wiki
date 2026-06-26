# Fluentd log-ingestion placeholder, outbound HTTP, and monitor API boundary checks

Source: hourly offensive-security scan, 2026-06-26. GitHub Advisory Database: [GHSA-44hj-4m45-frj3](https://github.com/advisories/GHSA-44hj-4m45-frj3) / CVE-2026-44024, [GHSA-72f5-rr8c-r6gr](https://github.com/advisories/GHSA-72f5-rr8c-r6gr) / CVE-2026-44161, [GHSA-pr7j-96cj-549h](https://github.com/advisories/GHSA-pr7j-96cj-549h) / CVE-2026-44025, plus adjacent resource-exhaustion advisories [GHSA-j9cw-hwqf-85w7](https://github.com/advisories/GHSA-j9cw-hwqf-85w7) / CVE-2026-44160 and [GHSA-xv9w-7v6q-hpjh](https://github.com/advisories/GHSA-xv9w-7v6q-hpjh) / CVE-2026-44162.

These items are durable for operators because Fluentd often sits on a trust boundary: applications, tenants, edge collectors, CI jobs, Kubernetes workloads, and cloud services can supply log records or tags that later cross into file paths, outbound HTTP destinations, plugin instance state, and decompression paths. Treat log pipelines as active control planes, not passive telemetry plumbing.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-44hj-4m45-frj3](https://github.com/advisories/GHSA-44hj-4m45-frj3) / CVE-2026-44024 | Fluentd `out_file` and file-style configs using `${tag}` | attacker-influenced tag strings can traverse out of intended file directories when expanded into paths | Hunt for untrusted log inputs where tags are preserved into `path` parameters; prove with disposable marker files only. |
| [GHSA-72f5-rr8c-r6gr](https://github.com/advisories/GHSA-72f5-rr8c-r6gr) / CVE-2026-44161 | Fluentd `out_http` `endpoint` placeholders | tag-derived placeholders can control outbound request hostnames | Test whether log tags can steer collectors toward owned callback URLs, then stop before internal-service probing. |
| [GHSA-pr7j-96cj-549h](https://github.com/advisories/GHSA-pr7j-96cj-549h) / CVE-2026-44025 | Fluentd `in_monitor_agent` REST API | monitor endpoints can expose plugin instance variables, including credentials held by loaded plugins | Include `:24220` monitor-agent reachability in observability recon, but capture only synthetic plugin-secret markers. |
| [GHSA-j9cw-hwqf-85w7](https://github.com/advisories/GHSA-j9cw-hwqf-85w7) / CVE-2026-44160 | Fluentd `in_http` / `in_forward` gzip ingestion | compressed input size limits may not constrain decompressed payload size | Use only lab-sized negative controls to document decompression policy gaps; avoid production resource exhaustion. |
| [GHSA-xv9w-7v6q-hpjh](https://github.com/advisories/GHSA-xv9w-7v6q-hpjh) / CVE-2026-44162 | `fluent-plugin-s3` `in_s3` | S3 objects monitored by collectors can decompress into excessive memory use | Treat monitored buckets as log-ingestion control planes when assessing who can write objects or choose compression formats. |

## Operator triage

1. **Map the log trust boundary first.** Identify every source that can choose Fluentd tag names: `in_forward`, `in_http`, Kubernetes metadata, app-side logging libraries, tenant job names, CI pipeline names, and rewrite-tag filters.
2. **Find placeholder expansion in sinks.** Prioritize configs where `${tag}`, `${record[...]}`, or derived placeholders appear in `path`, `endpoint`, object keys, or plugin-specific URL fields.
3. **Separate tag control from record control.** A user who can write log body text may not control the tag; a workload, namespace, route, or logger name may control it indirectly.
4. **Treat monitor-agent as a secret surface.** If `in_monitor_agent` is reachable beyond localhost, check whether loaded plugins include synthetic credentials in instance variables before touching real deployments.
5. **Use decompression advisories as boundary context, not a production test plan.** They help identify exposed collectors and bucket-write control, but proofs should avoid outage conditions.

## Replayable validation boundaries

### Tag-to-file-path harness

- Preconditions: explicit authorization, disposable Fluentd instance or isolated collector pod, synthetic log source, and a scratch output directory with no production files.
- Create a config that mirrors the target pattern: an untrusted input, tag-preserving or tag-rewrite flow, and an `out_file`-style `path` that contains `${tag}`.
- Send paired events with a normal tag and a traversal-shaped tag such as `scope.canary` versus a safely encoded traversal canary. Do not target `/etc`, shell startup files, service config, credentials, or real plugin directories.
- Validate only whether the collector attempts to create or write a marker outside the intended scratch output root.
- Evidence should include Fluentd version, input type, tag source, relevant config snippet, observed output path, filesystem marker path, and patched-version or tag-validation negative control.

### Tag-to-HTTP-destination harness

- Preconditions: lab collector, owned callback domain, no internal target probing, and a config path where `out_http endpoint` or equivalent destination includes a placeholder.
- Feed a synthetic tag or record value that should expand into an owned hostname, then observe whether the collector makes a request to the callback.
- Capture request metadata that proves collector-origin egress without collecting headers that may contain real tokens.
- Evidence should include Fluentd version, `out_http` config, placeholder value, expected endpoint, observed callback timestamp, and a fixed config that rejects non-allowlisted hosts.

### Monitor-agent exposure harness

- Preconditions: authorization to query the collector, a known lab monitor-agent endpoint, and synthetic plugin configuration containing a fake secret marker.
- Probe only monitor routes such as `/api/plugins.json` and related plugin-status endpoints on the monitor-agent port, commonly `24220` when enabled.
- Confirm whether the fake marker appears in plugin instance data. Do not collect real passwords, API keys, cloud credentials, buffer contents, customer log samples, or environment dumps.
- Evidence should include bind address, route, Fluentd version, plugin name, redacted response excerpt showing the fake marker, and negative control after upgrade or binding restriction.

### Decompression-boundary harness

- Preconditions: isolated collector, low resource limits, synthetic gzip/S3 object, and operator approval to run a bounded resource test.
- Use tiny, controlled payloads to prove whether decompressed-size enforcement exists; do not send bombs, max-size payloads, or repeated traffic.
- For S3 ingestion, use a disposable bucket/prefix and a canary object owned by the test account.
- Evidence should show configured compressed limits, decompressed-size control, object or request metadata, collector behavior, and fixed-version negative control.

## Reporting notes

- Lead with the boundary: **untrusted log tag to filesystem path**, **log placeholder to outbound HTTP host**, **monitor API to plugin instance variables**, or **bucket/upload control to collector decompression**.
- Include whether the attacker controls tag, record body, object name, S3 write permissions, or only application log content.
- Keep proof artifacts synthetic: scratch files, owned callback domains, fake plugin secrets, disposable buckets, and bounded canary payloads.
- Do not publish production RCE chains, internal metadata-service probes, real secrets, live log samples, or destructive decompression tests.
