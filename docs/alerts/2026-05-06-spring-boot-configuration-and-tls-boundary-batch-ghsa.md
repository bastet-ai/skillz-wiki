# Spring Boot configuration and TLS boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced seven Spring Boot advisories updated on **2026-05-06** spanning Actuator authorization, DevTools secret comparison, predictable/temp-file boundaries, weak random values, and missing TLS hostname verification in auto-configured clients.

## Advisories covered

- **Actuator default security filter chain gap** — [GHSA-8v8j-3hxp-93wr](https://github.com/advisories/GHSA-8v8j-3hxp-93wr): applications with Actuator but without Health could end up without an authorization rule in the default chain.
- **DevTools remote secret timing attack** — [GHSA-56v8-86gj-66jp](https://github.com/advisories/GHSA-56v8-86gj-66jp): remote secret comparison leaked timing information.
- **Predictable temp directory ownership gap** — [GHSA-wwpq-f5c3-7hvx](https://github.com/advisories/GHSA-wwpq-f5c3-7hvx): predictable temp directory selection without ownership verification could expose local privilege or data-boundary risks.
- **PID file symlink following** — [GHSA-5368-6h4h-gr29](https://github.com/advisories/GHSA-5368-6h4h-gr29): PID file writes at predictable paths could follow symlinks.
- **Weak random property source for secrets** — [GHSA-m4x9-hx6x-2c43](https://github.com/advisories/GHSA-m4x9-hx6x-2c43): random values meant for configuration were not suitable as secrets.
- **RabbitMQ hostname verification disabled** — [GHSA-9vc8-qppq-wvxc](https://github.com/advisories/GHSA-9vc8-qppq-wvxc).
- **Cassandra hostname verification disabled** — [GHSA-mqvw-jfmh-93qq](https://github.com/advisories/GHSA-mqvw-jfmh-93qq).
- **Elasticsearch hostname verification disabled** — [GHSA-c96x-rpm4-349p](https://github.com/advisories/GHSA-c96x-rpm4-349p).

## Why this is durable

Framework auto-configuration is a hidden security boundary. It can create network clients, temp files, PID files, secrets, and default authorization chains before application teams add explicit policy. The safe default must be explicit verification, explicit ownership, and explicit authorization.

## Immediate triage

1. Inventory Spring Boot versions and prioritize internet-facing, Actuator-enabled, DevTools-enabled, and broker/search/database-connected services.
2. Review Actuator exposure and security chains; require explicit authorization rules for every management endpoint, not just defaults.
3. Disable remote DevTools outside controlled development networks; rotate any long-lived DevTools secrets that may have been exposed.
4. Replace configuration-generated random values used as passwords, tokens, or signing secrets with CSPRNG-generated secrets from a secret manager.
5. Verify RabbitMQ, Cassandra, and Elasticsearch TLS clients perform certificate chain and hostname validation; pin expected SANs where possible.
6. Move PID/temp paths into private, ownership-checked runtime directories and reject symlinks before writing.

## Durable controls

- Ban implicit framework defaults for management endpoints: every exposed endpoint gets a reviewed allow/deny rule.
- Treat generated configuration values as identifiers unless they come from a CSPRNG and secret lifecycle.
- Use constant-time comparison for authentication material and rate-limit failed remote-secret attempts.
- For file writes, create parent directories with restrictive permissions and validate final inodes are not symlinks.
- Add integration tests that fail if TLS hostname verification is disabled for broker, database, and search clients.
