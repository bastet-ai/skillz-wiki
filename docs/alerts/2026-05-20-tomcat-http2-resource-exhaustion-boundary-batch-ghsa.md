# Tomcat HTTP/2 resource-exhaustion boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-20.

This batch is durable because both advisories describe HTTP/2 protocol handling that lets a remote client convert small connection or stream choices into process-wide Tomcat memory or thread exhaustion. The affected releases are old, but the defensive lesson remains current for any Java edge service that terminates h2c/HTTP/2 directly.

## What changed

- **Tomcat h2c upgrade processor leak leading to OOM** — [GHSA-vf77-8h7g-gghp](https://github.com/advisories/GHSA-vf77-8h7g-gghp) / CVE-2020-13934: Tomcat `10.0.0-M1` through `10.0.0-M5`, `9.0.0.M5` before `9.0.36`, and `8.5.1` before `8.5.56` failed to release the HTTP/1.1 processor after an h2c upgrade to HTTP/2. Enough direct h2c upgrade requests could trigger `OutOfMemoryException` and deny service.
- **Tomcat HTTP/2 SETTINGS and blocking-I/O stream exhaustion** — [GHSA-qcxh-w3j9-58qr](https://github.com/advisories/GHSA-qcxh-w3j9-58qr) / CVE-2019-0199: Tomcat `9.0.0.M1` through `9.0.14` and `8.5.0` through `8.5.37` accepted excessive HTTP/2 SETTINGS frames and allowed streams to stay open without request/response progress. When those streams used Servlet API blocking I/O, attacker-held streams could exhaust server threads.

## Operator triage

1. Confirm every internet-facing or proxy-facing Tomcat runtime is newer than `9.0.36` or `8.5.56`; for embedded `tomcat-embed-core`, require at least `9.0.16` or `8.5.38` for the older SETTINGS/thread exhaustion issue and newer patched lines for the h2c leak.
2. Inventory whether h2c direct upgrade is enabled anywhere. If HTTP/2 is required, prefer terminating it at a hardened reverse proxy and forwarding bounded HTTP/1.1 or a separately monitored backend protocol.
3. Review access logs and reverse-proxy metrics for repeated h2c upgrades, high HTTP/2 SETTINGS frame rates, many idle streams per client, or servlet threads stuck in blocking I/O.
4. For legacy apps that cannot move immediately, restrict HTTP/2/h2c exposure to trusted frontends, cap concurrent streams, enforce idle/read/write timeouts, and add memory/thread-pool saturation alerts.

## Replayable validation boundaries

- **h2c upgrade lifecycle test:** send repeated HTTP/1.1-to-h2c upgrade requests against a staging Tomcat; expected result is stable processor counts and heap use after connection close.
- **SETTINGS flood test:** generate HTTP/2 streams with excessive SETTINGS frames through the approved edge path; expected result is rate limiting, connection closure, or proxy rejection before Tomcat worker/thread exhaustion.
- **Idle blocking stream test:** hold request/response streams open against a blocking servlet endpoint; expected result is bounded per-client streams and timeout-driven cleanup.
- **Proxy containment test:** attempt direct h2c access to the Tomcat backend from untrusted networks; expected result is no route or explicit rejection.

## Durable controls

- Treat HTTP/2 and h2c as resource-boundary surfaces, not just transport features. Every enabled connector needs stream, frame, timeout, thread, and heap budgets.
- Keep Tomcat and embedded Tomcat dependencies patched even for internal services; old h2c/HTTP/2 flaws are easy to rediscover with generic protocol fuzzers.
- Terminate complex client protocols at one hardened, observable edge layer whenever possible, and keep backend connectors private.
- Monitor connector-level counters: active HTTP/2 streams, refused streams, idle stream age, servlet thread utilization, direct-buffer/heap pressure, and h2c upgrade rates.
- Include HTTP/2 slow-read, SETTINGS-frame, and h2c-upgrade regressions in load and abuse tests for Java services.
