# Observability, database, and resource-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because observability and database clients are often treated as trusted plumbing, yet their authentication, config, and compressed-data paths can expose secrets or exhaust shared infrastructure.

## Advisories covered

- **pgjdbc SCRAM authentication** — [GHSA-98qh-xjc8-98pq](https://github.com/advisories/GHSA-98qh-xjc8-98pq): unbounded PBKDF2 iterations can cause CPU-exhaustion denial of service.
- **Prometheus remote read** — [GHSA-8rm2-7qqf-34qm](https://github.com/advisories/GHSA-8rm2-7qqf-34qm): crafted snappy payloads can trigger denial of service.
- **Prometheus Azure AD remote write** — [GHSA-wg65-39gg-5wfj](https://github.com/advisories/GHSA-wg65-39gg-5wfj): OAuth client secret can be exposed through the config API.

## Operator triage

1. Patch database drivers and observability components before exposing remote-read/write or accepting untrusted server authentication parameters.
2. Cap SCRAM/PBKDF iteration counts and authentication CPU time; reject extreme values before entering expensive crypto loops.
3. Put compressed-payload limits before decompression: max compressed size, max expanded size, max block count, and request timeout.
4. Audit Prometheus config/API exposure and verify remote-write OAuth secrets are redacted from every config, debug, and status endpoint.
5. Hunt for high-CPU auth spikes, failed SCRAM handshakes with unusual iteration counts, malformed snappy remote-read requests, and unexpected config API reads.

## Durable controls

- Client libraries must treat server-supplied authentication parameters as untrusted inputs with cost ceilings.
- Observability APIs frequently carry credentials; config endpoints should be authenticated, least-privileged, and redacted by construction.
- Compression parsers need resource accounting before allocation or expansion.
- Monitoring systems should monitor themselves for parser/authentication resource-exhaustion indicators.
