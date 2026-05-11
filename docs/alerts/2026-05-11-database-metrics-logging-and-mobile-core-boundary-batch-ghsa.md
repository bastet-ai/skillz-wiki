# Database metrics, logging, and mobile-core boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11.

This batch is durable because it ties together a recurring production-control lesson: observability, protocol parsers, database-backed filesystems, and mobile-core handover paths often run with more authority than their input deserves.

## Advisories covered

- **CloudNativePG metrics exporter PostgreSQL superuser / OS RCE** — [GHSA-423p-g724-fr39](https://github.com/advisories/GHSA-423p-g724-fr39): `github.com/cloudnative-pg/cloudnative-pg <1.28.3` and `>=1.29.0,<1.29.1` opened the scrape session as `postgres` through the pod-local Unix socket and demoted with `SET ROLE pg_monitor`; SQL evaluated during metrics collection could `RESET ROLE` back to superuser and chain to `COPY ... TO PROGRAM`.
- **elFinder MySQL volume SQL injection** — [GHSA-c3gj-q88f-7hqj](https://github.com/advisories/GHSA-c3gj-q88f-7hqj): Composer `studio-42/elfinder <=2.1.67`, when configured with `elFinderVolumeMySQL`, allowed authenticated users — including read-only users — to inject SQL through crafted `target` file hashes. Fixed in `2.1.68`.
- **Valtimo RestClient sensitive-data logging** — [GHSA-3jh5-rr2q-xfv7](https://github.com/advisories/GHSA-3jh5-rr2q-xfv7): Maven `com.ritense.valtimo:web >=12.4.0,<12.33.0` and `>=13.0.0,<13.26.0` logged request bodies, response bodies, and headers from outgoing Spring `RestClient` calls on error paths, regardless of DEBUG logging.
- **GoBGP BMP parser out-of-bounds read** — [GHSA-w88c-9vg8-cmq8](https://github.com/advisories/GHSA-w88c-9vg8-cmq8): `github.com/osrg/gobgp <4.4.0` had remotely triggerable BMP parser bounds issues in `BMPPeerUpNotification.ParseBody` / `BMPStatisticsReport.ParseBody`.
- **Ella Core forged radio / handover boundary issues** — [GHSA-qfxw-v8qx-vj3v](https://github.com/advisories/GHSA-qfxw-v8qx-vj3v), [GHSA-pwfh-mqp3-pqwj](https://github.com/advisories/GHSA-pwfh-mqp3-pqwj), [GHSA-mc29-hmx6-856q](https://github.com/advisories/GHSA-mc29-hmx6-856q): `github.com/ellanetworks/core <1.10.0` failed to scope some UE context/security-capability and concurrent security-procedure checks to the correct radio/SCTP association and TS 33.501 rules, enabling downlink redirection or security-state corruption in specific radio attack paths.

## Operator triage

1. For CloudNativePG, patch operators to **1.28.3** or **1.29.1** or later, review metrics collector SQL, and inspect pods for unexpected `COPY ... PROGRAM`, shell, or outbound activity from PostgreSQL containers.
2. Do not expose database metrics or admin scrape paths broadly. Treat metrics SQL as code running inside a privileged database session.
3. For elFinder, identify deployments using `elFinderVolumeMySQL`; patch to **2.1.68+**, rotate database credentials if exploitation is plausible, and inspect SQL logs for unusual `target` hash parsing errors or stacked/boolean SQL payloads.
4. For Valtimo, patch affected lines and purge or restrict logs that may contain bearer tokens, API keys, request bodies, response bodies, or partner data from outgoing RestClient calls.
5. For GoBGP/Ella Core, patch protocol-facing daemons and review peer/radio logs for malformed BMP messages, unexpected handover failures, UE security-capability changes, or GTP tunnels created toward unexpected radios.

## Durable controls

- Metrics exporters should connect with the least database role needed for each query; `SET ROLE` is not a privilege boundary if the session user remains superuser.
- Filesystem abstractions backed by SQL still need strict identifier/hash parsing and parameterized queries at every lookup boundary.
- Error logging must redact request/response bodies and headers by default; logging level is not a secret-boundary control.
- Protocol parsers need length-first validation before interpreting nested message bodies.
- Mobile-core state machines must bind UE context and security state to the verified transport association, not just IDs carried inside protocol messages.
