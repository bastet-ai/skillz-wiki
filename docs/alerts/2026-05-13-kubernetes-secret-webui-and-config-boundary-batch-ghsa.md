# Kubernetes secret, WebUI, and config-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because secret operators and admin WebUIs keep treating “configuration editors” as low risk. In practice, CA providers, secret names, proxy settings, TLS verification flags, package folders, and exception output all become security boundaries.

## Advisories covered

- **ExternalSecrets secret overwrite privilege escalation** — [GHSA-fq7h-9x26-6j22](https://github.com/advisories/GHSA-fq7h-9x26-6j22): attacker-controlled ExternalSecret behavior could overwrite secrets across privilege boundaries. Fixed in `2.4.1`.
- **External Secrets Operator CAProvider namespace isolation bypass** — [GHSA-wv26-88m5-6h59](https://github.com/advisories/GHSA-wv26-88m5-6h59): `SecretStore` CAProvider ConfigMap resolution crossed namespace boundaries. Fixed in `2.4.0`.
- **PyLoad traceback disclosure** — [GHSA-c3gc-9pf2-84gg](https://github.com/advisories/GHSA-c3gc-9pf2-84gg): global WebUI exception handling leaked traceback details without authentication. Fixed in `pyload-ng 0.5.0b3.dev100`.
- **PyLoad package-folder path traversal** — [GHSA-838g-gr43-qqg9](https://github.com/advisories/GHSA-838g-gr43-qqg9), [GHSA-97r3-5w84-r4q8](https://github.com/advisories/GHSA-97r3-5w84-r4q8): package folder names reached filesystem paths. Fixed in `0.5.0b3.dev100`.
- **pyload-ng proxy reconfiguration incomplete fix** — [GHSA-pg67-9wjv-mr85](https://github.com/advisories/GHSA-pg67-9wjv-mr85): non-admin `SETTINGS` users could redirect outbound traffic through attacker-controlled proxies. Fixed in `0.5.0b3.dev100`.
- **pyload-ng TLS verification disable incomplete fix** — [GHSA-ccxc-x975-4hh9](https://github.com/advisories/GHSA-ccxc-x975-4hh9): non-admin `SETTINGS` users could disable outbound TLS peer verification. Fixed in `0.5.0b3.dev100`.

## Operator triage

1. Patch External Secrets controllers before adding new `SecretStore`, `ClusterSecretStore`, or tenant namespaces.
2. Audit existing ExternalSecret objects for writes to privileged secret names, service-account tokens, registry credentials, webhook secrets, and cross-namespace CAProvider references.
3. Patch or isolate PyLoad WebUI deployments; remove public exposure and require strong authentication at a reverse proxy if patching is delayed.
4. Review PyLoad settings changes for proxy host changes, TLS verification toggles, and package folder names containing encoded separators or traversal sequences.

## Durable controls

- Secret controllers must enforce namespace, service-account, and destination-secret policy after reference resolution, not only when parsing manifests.
- Separate “can edit preferences” from “can edit outbound network/TLS trust”; proxy and certificate verification settings are security administration.
- WebUIs should return generic errors to unauthenticated users and log tracebacks only to protected operator logs.
- File paths derived from package names or folders need canonicalization, base-directory enforcement, and tests for encoded traversal variants.
